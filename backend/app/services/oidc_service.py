import base64
import hashlib
import json
import logging
import secrets
import threading
import time
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
from redis import Redis
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AuthenticationError, AuthorizationError, ValidationAppError
from app.core.permissions import RoleName
from app.core.security import create_access_token, create_refresh_token
from app.db.models import Membership, Tenant, User
from app.db.session import set_rls_context
from app.services.audit_service import record_audit_event
from app.services.auth_service import ensure_default_roles

logger = logging.getLogger("sentinelgraph.oidc")

ALLOWED_OIDC_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384"]
_OIDC_STATE_TTL_SECONDS = 600
_CACHE_TTL_SECONDS = 300

_state_lock = threading.Lock()
_memory_states: dict[str, dict[str, Any]] = {}

_cache_lock = threading.Lock()
_discovery_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_jwks_cache: dict[str, tuple[float, dict[str, Any]]] = {}


def reset_oidc_caches() -> None:
    """Clear in-memory OIDC state and metadata/JWKS caches (useful in tests)."""
    with _state_lock:
        _memory_states.clear()
    with _cache_lock:
        _discovery_cache.clear()
        _jwks_cache.clear()


def _get_redis() -> Redis | None:
    settings = get_settings()
    if not settings.redis_url:
        return None
    try:
        client = Redis.from_url(settings.redis_url, socket_connect_timeout=1, socket_timeout=1)
        client.ping()
        return client
    except Exception:
        return None


def _store_oidc_state(state: str, payload: dict[str, Any]) -> None:
    encoded = json.dumps(payload)
    client = _get_redis()
    if client is not None:
        try:
            client.set(f"sg:oidc:state:{state}", encoded, ex=_OIDC_STATE_TTL_SECONDS)
            return
        except Exception:
            pass
    now = time.time()
    with _state_lock:
        expired = [k for k, v in _memory_states.items() if float(v.get("expires_at", 0)) <= now]
        for k in expired:
            del _memory_states[k]
        _memory_states[state] = payload


def _pop_oidc_state(state: str) -> dict[str, Any] | None:
    client = _get_redis()
    if client is not None:
        try:
            key = f"sg:oidc:state:{state}"
            raw = client.get(key)
            if raw is not None:
                client.delete(key)
                parsed = json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
                if float(parsed.get("expires_at", 0)) > time.time():
                    return parsed
                return None
        except Exception:
            pass
    with _state_lock:
        rec = _memory_states.pop(state, None)
    if rec and float(rec.get("expires_at", 0)) > time.time():
        return rec
    return None


def _pkce_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _fetch_discovery_metadata(
    issuer_url: str,
    http_transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    clean_issuer = issuer_url.rstrip("/")
    now = time.time()
    if http_transport is None:
        with _cache_lock:
            cached = _discovery_cache.get(clean_issuer)
            if cached and cached[0] > now:
                return cached[1]

    discovery_url = f"{clean_issuer}/.well-known/openid-configuration"
    try:
        with httpx.Client(timeout=10.0, transport=http_transport) as client:
            resp = client.get(discovery_url)
            resp.raise_for_status()
            meta = resp.json()
    except Exception as exc:
        raise AuthenticationError(
            f"Unable to fetch OIDC discovery metadata from {clean_issuer}.",
            code="OIDC_DISCOVERY_ERROR",
        ) from exc

    if not isinstance(meta, dict) or "authorization_endpoint" not in meta or "token_endpoint" not in meta:
        raise AuthenticationError("Invalid OIDC discovery metadata document.", code="OIDC_DISCOVERY_ERROR")

    if http_transport is None:
        with _cache_lock:
            _discovery_cache[clean_issuer] = (now + _CACHE_TTL_SECONDS, meta)
    return meta


def _fetch_jwks(
    jwks_uri: str,
    *,
    force_refresh: bool = False,
    http_transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    now = time.time()
    if not force_refresh and http_transport is None:
        with _cache_lock:
            cached = _jwks_cache.get(jwks_uri)
            if cached and cached[0] > now:
                return cached[1]

    try:
        with httpx.Client(timeout=10.0, transport=http_transport) as client:
            resp = client.get(jwks_uri)
            resp.raise_for_status()
            jwks = resp.json()
    except Exception as exc:
        raise AuthenticationError("Unable to retrieve OIDC JWKS keys.", code="OIDC_JWKS_ERROR") from exc

    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        raise AuthenticationError("Malformed OIDC JWKS response.", code="OIDC_JWKS_ERROR")

    if http_transport is None:
        with _cache_lock:
            _jwks_cache[jwks_uri] = (now + _CACHE_TTL_SECONDS, jwks)
    return jwks


def _verify_id_token(
    id_token: str,
    *,
    issuer_url: str,
    client_id: str,
    jwks_uri: str,
    expected_nonce: str,
    http_transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    try:
        unverified_header = jwt.get_unverified_header(id_token)
    except jwt.InvalidTokenError as exc:
        raise AuthenticationError("Malformed OIDC id_token header.", code="OIDC_TOKEN_INVALID") from exc

    alg = str(unverified_header.get("alg", ""))
    if alg not in ALLOWED_OIDC_ALGORITHMS:
        raise AuthenticationError(
            f"Unsupported OIDC id_token signing algorithm '{alg}'.",
            code="OIDC_ALG_REJECTED",
        )

    kid = unverified_header.get("kid")
    jwks = _fetch_jwks(jwks_uri, http_transport=http_transport)
    matching_key = None
    for jwk in jwks.get("keys", []):
        if kid is None or jwk.get("kid") == kid:
            matching_key = jwk
            break

    if matching_key is None:
        jwks = _fetch_jwks(jwks_uri, force_refresh=True, http_transport=http_transport)
        for jwk in jwks.get("keys", []):
            if kid is None or jwk.get("kid") == kid:
                matching_key = jwk
                break

    if matching_key is None:
        raise AuthenticationError("Signing key not found in OIDC JWKS.", code="OIDC_KEY_NOT_FOUND")

    try:
        signing_key = jwt.PyJWK.from_dict(matching_key).key
        claims = jwt.decode(
            id_token,
            signing_key,
            algorithms=ALLOWED_OIDC_ALGORITHMS,
            audience=client_id,
            issuer=issuer_url.rstrip("/"),
            options={"require": ["sub", "iss", "aud", "exp"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthenticationError("OIDC ID token expired.", code="OIDC_TOKEN_EXPIRED") from exc
    except jwt.InvalidTokenError as exc:
        raise AuthenticationError("OIDC ID token signature or claims invalid.", code="OIDC_TOKEN_INVALID") from exc

    if claims.get("nonce") != expected_nonce:
        raise AuthenticationError("OIDC nonce mismatch.", code="OIDC_NONCE_INVALID")
    return dict(claims)


def build_oidc_authorization_url(
    *,
    tenant_slug: str | None = None,
    http_transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    settings = get_settings()
    if not settings.oidc_issuer_url or not settings.oidc_client_id:
        raise ValidationAppError(
            code="OIDC_NOT_CONFIGURED",
            message="OIDC authentication is not configured on this server (set OIDC_ISSUER_URL and OIDC_CLIENT_ID).",
        )

    meta = _fetch_discovery_metadata(settings.oidc_issuer_url, http_transport=http_transport)
    code_verifier = secrets.token_urlsafe(48)
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(24)

    _store_oidc_state(
        state,
        {
            "code_verifier": code_verifier,
            "nonce": nonce,
            "tenant_slug": tenant_slug.strip().lower() if tenant_slug else None,
            "redirect_uri": settings.oidc_redirect_uri,
            "expires_at": time.time() + _OIDC_STATE_TTL_SECONDS,
        },
    )

    query = urlencode(
        {
            "response_type": "code",
            "client_id": settings.oidc_client_id,
            "redirect_uri": settings.oidc_redirect_uri,
            "scope": settings.oidc_scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": _pkce_challenge(code_verifier),
            "code_challenge_method": "S256",
        }
    )
    auth_endpoint = str(meta["authorization_endpoint"])
    sep = "&" if "?" in auth_endpoint else "?"
    return {
        "oidc_enabled": True,
        "authorization_url": f"{auth_endpoint}{sep}{query}",
        "state": state,
    }


def complete_oidc_callback(
    db: Session,
    *,
    code: str,
    state: str,
    tenant_slug: str | None = None,
    request_id: str,
    http_transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    settings = get_settings()
    if not settings.oidc_issuer_url or not settings.oidc_client_id:
        raise ValidationAppError(
            code="OIDC_NOT_CONFIGURED",
            message="OIDC authentication is not configured on this server.",
        )

    stored = _pop_oidc_state(state)
    if stored is None:
        raise AuthenticationError("OIDC state expired or invalid.", code="OIDC_STATE_INVALID")

    meta = _fetch_discovery_metadata(settings.oidc_issuer_url, http_transport=http_transport)
    token_endpoint = str(meta["token_endpoint"])
    jwks_uri = str(meta.get("jwks_uri") or "")
    if not jwks_uri:
        raise AuthenticationError("OIDC discovery document missing jwks_uri.", code="OIDC_DISCOVERY_ERROR")

    form_data: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": str(stored["redirect_uri"]),
        "client_id": settings.oidc_client_id,
        "code_verifier": str(stored["code_verifier"]),
    }
    if settings.oidc_client_secret:
        form_data["client_secret"] = settings.oidc_client_secret

    try:
        with httpx.Client(timeout=10.0, transport=http_transport) as client:
            token_resp = client.post(
                token_endpoint,
                data=form_data,
                headers={"Accept": "application/json"},
            )
            token_resp.raise_for_status()
            token_body = token_resp.json()
    except Exception as exc:
        raise AuthenticationError("OIDC authorization code exchange failed.", code="OIDC_EXCHANGE_FAILED") from exc

    id_token = token_body.get("id_token")
    if not id_token:
        raise AuthenticationError("OIDC token response missing id_token.", code="OIDC_TOKEN_INVALID")

    claims = _verify_id_token(
        str(id_token),
        issuer_url=str(meta.get("issuer") or settings.oidc_issuer_url),
        client_id=settings.oidc_client_id,
        jwks_uri=jwks_uri,
        expected_nonce=str(stored["nonce"]),
        http_transport=http_transport,
    )

    subject = str(claims["sub"])
    email_claim = str(claims.get("email") or "").strip().lower()
    email_verified = claims.get("email_verified", True)
    if email_claim and email_verified is False:
        raise AuthenticationError("OIDC email address is unverified.", code="OIDC_EMAIL_UNVERIFIED")

    requested_slug = (tenant_slug or stored.get("tenant_slug") or "").strip().lower() or None

    user = db.execute(
        select(User).where(User.auth_provider == "oidc", User.external_subject == subject)
    ).scalar_one_or_none()

    if user is None and email_claim:
        user = db.execute(select(User).where(User.email == email_claim)).scalar_one_or_none()
        if user is not None and not user.external_subject:
            user.external_subject = subject
            user.auth_provider = "oidc"
            db.flush()

    if user is None:
        jit_slug = (settings.oidc_jit_tenant_slug or "").strip().lower()
        if not jit_slug or (requested_slug and requested_slug != jit_slug):
            raise AuthorizationError(
                "No provisioned SentinelGraph user matches this OIDC identity.",
                code="OIDC_USER_NOT_PROVISIONED",
            )
        if not email_claim:
            raise AuthenticationError("OIDC ID token missing required email claim for JIT user.", code="OIDC_EMAIL_REQUIRED")

        jit_tenant = db.execute(select(Tenant).where(Tenant.slug == jit_slug)).scalar_one_or_none()
        if jit_tenant is None:
            raise AuthorizationError(
                f"Configured JIT tenant '{jit_slug}' does not exist.",
                code="OIDC_JIT_TENANT_MISSING",
            )

        roles = ensure_default_roles(db)
        jit_role_name = settings.oidc_jit_role if settings.oidc_jit_role in roles else RoleName.ANALYST.value
        display_name = str(claims.get("name") or claims.get("preferred_username") or email_claim.split("@")[0])[:200]
        user = User(
            email=email_claim,
            display_name=display_name,
            auth_provider="oidc",
            external_subject=subject,
            password_hash=None,
            is_active=True,
            mfa_enabled=True,
        )
        db.add(user)
        db.flush()

        set_rls_context(db, tenant_id=jit_tenant.id, user_id=user.id)
        db.add(
            Membership(
                tenant_id=jit_tenant.id,
                user_id=user.id,
                role_id=roles[jit_role_name].id,
                status="active",
            )
        )
        db.flush()

    if not user.is_active:
        raise AuthenticationError("User account is disabled.", code="USER_INACTIVE")

    set_rls_context(db, user_id=user.id)
    memberships = list(
        db.execute(
            select(Membership).where(Membership.user_id == user.id, Membership.status == "active")
        ).scalars()
    )
    if not memberships:
        raise AuthorizationError("User has no active tenant membership.", code="NO_MEMBERSHIP")

    selected: Membership | None = None
    if requested_slug:
        for m in memberships:
            if m.tenant.slug == requested_slug:
                selected = m
                break
        if selected is None:
            raise AuthorizationError(
                f"User is not an active member of tenant '{requested_slug}'.",
                code="TENANT_ACCESS_DENIED",
            )
    else:
        selected = memberships[0]

    set_rls_context(db, tenant_id=selected.tenant_id, user_id=user.id)
    access_token = create_access_token(
        user_id=user.id,
        email=user.email,
        tenant_id=selected.tenant_id,
        role=selected.role.name,
        auth_method="oidc",
    )
    refresh_token = create_refresh_token(
        user_id=user.id,
        email=user.email,
        tenant_id=selected.tenant_id,
        role=selected.role.name,
        auth_method="oidc",
    )

    record_audit_event(
        db,
        tenant_id=selected.tenant_id,
        actor_user_id=user.id,
        actor_email=user.email,
        action="auth.oidc_login",
        object_type="user",
        object_id=str(user.id),
        outcome="success",
        request_id=request_id,
        details={"auth_method": "oidc", "role": selected.role.name, "oidc_subject": subject},
    )
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": settings.access_token_expire_minutes * 60,
        "token_type": "bearer",
        "oidc_subject": subject,
        "user": {
            "id": str(user.id),
            "email": user.email,
            "display_name": user.display_name,
            "mfa_enabled": user.mfa_enabled,
        },
        "active_tenant": {
            "id": str(selected.tenant.id),
            "slug": selected.tenant.slug,
            "name": selected.tenant.name,
            "is_demo": selected.tenant.is_demo,
            "role": selected.role.name,
        },
        "memberships": [
            {
                "tenant_id": str(m.tenant.id),
                "tenant_slug": m.tenant.slug,
                "tenant_name": m.tenant.name,
                "is_demo": m.tenant.is_demo,
                "role": m.role.name,
            }
            for m in memberships
        ],
    }
