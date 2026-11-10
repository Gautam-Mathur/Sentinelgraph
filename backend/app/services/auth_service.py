import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import (
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    ValidationAppError,
)
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
    hash_password,
    validate_password_strength,
    verify_password,
)
from app.core.token_store import is_token_revoked, revoke_token
from app.db.models import Membership, Role, User
from app.db.session import set_rls_context
from app.services.audit_service import record_audit_event


def authenticate_local_user(
    db: Session,
    *,
    email: str,
    password: str,
    tenant_slug: str | None,
    request_id: str,
) -> dict[str, Any]:
    settings = get_settings()
    if not settings.local_dev_auth_enabled:
        raise AuthenticationError(
            "Local seeded authentication is disabled outside development/test environments; use OIDC.",
            code="LOCAL_AUTH_DISABLED",
        )

    user = db.execute(select(User).where(User.email == email.lower().strip())).scalar_one_or_none()
    if user is None or not user.is_active or not user.password_hash:
        raise AuthenticationError("Invalid email or password", code="INVALID_CREDENTIALS")

    if not verify_password(password, user.password_hash):
        # Attempt to log failed login under user's primary tenant if any
        set_rls_context(db, user_id=user.id)
        mem = db.execute(
            select(Membership).where(Membership.user_id == user.id, Membership.status == "active")
        ).scalars().first()
        if mem is not None:
            set_rls_context(db, tenant_id=mem.tenant_id, user_id=user.id)
            record_audit_event(
                db,
                tenant_id=mem.tenant_id,
                actor_user_id=user.id,
                actor_email=user.email,
                action="auth.login_failed",
                object_type="user",
                object_id=str(user.id),
                outcome="denied",
                request_id=request_id,
                details={"reason": "bad_password"},
            )
            db.commit()
        raise AuthenticationError("Invalid email or password", code="INVALID_CREDENTIALS")

    set_rls_context(db, user_id=user.id)
    memberships = list(
        db.execute(
            select(Membership).where(Membership.user_id == user.id, Membership.status == "active")
        ).scalars()
    )
    if not memberships:
        raise AuthorizationError("User has no active tenant membership", code="NO_MEMBERSHIP")

    selected: Membership | None = None
    if tenant_slug:
        for m in memberships:
            if m.tenant.slug == tenant_slug:
                selected = m
                break
        if selected is None:
            raise AuthorizationError(
                f"User is not an active member of tenant '{tenant_slug}'.",
                code="TENANT_ACCESS_DENIED",
            )
    else:
        selected = memberships[0]

    set_rls_context(db, tenant_id=selected.tenant_id, user_id=user.id)
    token = create_access_token(
        user_id=user.id,
        email=user.email,
        tenant_id=selected.tenant_id,
        role=selected.role.name,
        auth_method="local_dev",
    )
    refresh_token = create_refresh_token(
        user_id=user.id,
        email=user.email,
        tenant_id=selected.tenant_id,
        role=selected.role.name,
        auth_method="local_dev",
    )

    record_audit_event(
        db,
        tenant_id=selected.tenant_id,
        actor_user_id=user.id,
        actor_email=user.email,
        action="auth.login",
        object_type="user",
        object_id=str(user.id),
        outcome="success",
        request_id=request_id,
        details={"auth_method": "local_dev", "role": selected.role.name},
    )
    db.commit()

    return {
        "access_token": token,
        "refresh_token": refresh_token,
        "expires_in": settings.access_token_expire_minutes * 60,
        "token_type": "bearer",
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


def switch_active_tenant(
    db: Session,
    *,
    user_id: uuid.UUID,
    target_tenant_id: uuid.UUID,
    request_id: str,
) -> dict[str, Any]:
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise AuthenticationError("User account inactive or missing.")

    set_rls_context(db, user_id=user.id)
    membership = db.execute(
        select(Membership).where(
            Membership.user_id == user.id,
            Membership.tenant_id == target_tenant_id,
            Membership.status == "active",
        )
    ).scalar_one_or_none()
    if membership is None:
        raise NotFoundError(code="TENANT_NOT_FOUND", message="Tenant not found or access denied")

    settings = get_settings()
    set_rls_context(db, tenant_id=membership.tenant_id, user_id=user.id)
    token = create_access_token(
        user_id=user.id,
        email=user.email,
        tenant_id=membership.tenant_id,
        role=membership.role.name,
        auth_method="tenant_switch",
    )
    refresh_token = create_refresh_token(
        user_id=user.id,
        email=user.email,
        tenant_id=membership.tenant_id,
        role=membership.role.name,
        auth_method="tenant_switch",
    )
    record_audit_event(
        db,
        tenant_id=membership.tenant_id,
        actor_user_id=user.id,
        actor_email=user.email,
        action="auth.tenant_switch",
        object_type="tenant",
        object_id=str(membership.tenant_id),
        outcome="success",
        request_id=request_id,
        details={"role": membership.role.name},
    )
    db.commit()

    return {
        "access_token": token,
        "refresh_token": refresh_token,
        "expires_in": settings.access_token_expire_minutes * 60,
        "token_type": "bearer",
        "active_tenant": {
            "id": str(membership.tenant.id),
            "slug": membership.tenant.slug,
            "name": membership.tenant.name,
            "is_demo": membership.tenant.is_demo,
            "role": membership.role.name,
        },
    }


def refresh_session(
    db: Session,
    *,
    refresh_token: str,
    request_id: str,
) -> dict[str, Any]:
    settings = get_settings()
    claims = decode_refresh_token(refresh_token)
    old_jti = str(claims["jti"])
    if is_token_revoked(db, old_jti):
        raise AuthenticationError("Refresh token has been revoked.", code="TOKEN_REVOKED")

    try:
        user_id = uuid.UUID(str(claims["sub"]))
        tenant_id = uuid.UUID(str(claims["tenant_id"]))
    except ValueError as exc:
        raise AuthenticationError("Malformed refresh token claims.", code="REFRESH_TOKEN_INVALID") from exc

    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise AuthenticationError("User account inactive or missing.", code="USER_INACTIVE")

    set_rls_context(db, tenant_id=tenant_id, user_id=user.id)
    memberships = list(
        db.execute(
            select(Membership).where(Membership.user_id == user.id, Membership.status == "active")
        ).scalars()
    )
    selected = next((m for m in memberships if m.tenant_id == tenant_id), None)
    if selected is None:
        raise AuthorizationError("Tenant membership revoked or inactive.", code="TENANT_ACCESS_DENIED")

    exp_dt = datetime.fromtimestamp(int(claims["exp"]), tz=UTC)
    revoke_token(db, jti=old_jti, user_id=user.id, token_type="refresh", expires_at=exp_dt)

    auth_method = str(claims.get("auth_method", "refresh"))
    new_access = create_access_token(
        user_id=user.id,
        email=user.email,
        tenant_id=selected.tenant_id,
        role=selected.role.name,
        auth_method=auth_method,
    )
    new_refresh = create_refresh_token(
        user_id=user.id,
        email=user.email,
        tenant_id=selected.tenant_id,
        role=selected.role.name,
        auth_method=auth_method,
    )

    record_audit_event(
        db,
        tenant_id=selected.tenant_id,
        actor_user_id=user.id,
        actor_email=user.email,
        action="auth.token_refresh",
        object_type="user",
        object_id=str(user.id),
        outcome="success",
        request_id=request_id,
        details={"rotated_jti": old_jti},
    )
    db.commit()

    return {
        "access_token": new_access,
        "refresh_token": new_refresh,
        "expires_in": settings.access_token_expire_minutes * 60,
        "token_type": "bearer",
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


def logout_session(
    db: Session,
    *,
    user: User,
    claims: dict[str, Any],
    refresh_token: str | None,
    request_id: str,
) -> dict[str, str]:
    jti = str(claims.get("jti") or "")
    exp_ts = claims.get("exp")
    exp_dt = (
        datetime.fromtimestamp(int(exp_ts), tz=UTC)
        if exp_ts is not None
        else datetime.now(UTC)
    )
    if jti:
        revoke_token(db, jti=jti, user_id=user.id, token_type="access", expires_at=exp_dt)

    if refresh_token:
        try:
            r_claims = decode_refresh_token(refresh_token)
            if str(r_claims.get("sub")) == str(user.id):
                r_exp = datetime.fromtimestamp(int(r_claims["exp"]), tz=UTC)
                revoke_token(
                    db,
                    jti=str(r_claims["jti"]),
                    user_id=user.id,
                    token_type="refresh",
                    expires_at=r_exp,
                )
        except Exception:
            pass

    raw_tid = claims.get("tenant_id")
    if raw_tid:
        try:
            tid = uuid.UUID(str(raw_tid))
            set_rls_context(db, tenant_id=tid, user_id=user.id)
            record_audit_event(
                db,
                tenant_id=tid,
                actor_user_id=user.id,
                actor_email=user.email,
                action="auth.logout",
                object_type="user",
                object_id=str(user.id),
                outcome="success",
                request_id=request_id,
                details={"revoked_jti": jti},
            )
        except Exception:
            pass
    db.commit()
    return {"status": "logged_out", "revoked_jti": jti}


def change_local_password(
    db: Session,
    *,
    ctx: Any,
    current_password: str,
    new_password: str,
) -> dict[str, str]:
    user = db.get(User, ctx.user_id)
    if user is None or not user.is_active:
        raise AuthenticationError("User account inactive or missing.", code="USER_INACTIVE")
    if not user.password_hash:
        raise ValidationAppError(
            code="PASSWORD_CHANGE_UNSUPPORTED",
            message="Password changes are only supported for local password accounts.",
        )
    if not verify_password(current_password, user.password_hash):
        raise AuthenticationError("Current password is incorrect.", code="INVALID_CREDENTIALS")
    if current_password == new_password:
        raise ValidationAppError(
            code="WEAK_PASSWORD",
            message="New password must differ from current password.",
        )

    validate_password_strength(new_password)
    user.password_hash = hash_password(new_password)
    set_rls_context(db, tenant_id=ctx.tenant_id, user_id=user.id)
    record_audit_event(
        db,
        tenant_id=ctx.tenant_id,
        actor_user_id=user.id,
        actor_email=user.email,
        action="auth.password_change",
        object_type="user",
        object_id=str(user.id),
        outcome="success",
        request_id=ctx.request_id,
        details={"auth_provider": user.auth_provider},
    )
    db.commit()
    return {"status": "password_updated"}


def list_user_memberships(db: Session, user_id: uuid.UUID) -> list[dict[str, Any]]:
    set_rls_context(db, user_id=user_id)
    rows = list(
        db.execute(
            select(Membership).where(Membership.user_id == user_id, Membership.status == "active")
        ).scalars()
    )
    return [
        {
            "tenant_id": str(m.tenant.id),
            "tenant_slug": m.tenant.slug,
            "tenant_name": m.tenant.name,
            "is_demo": m.tenant.is_demo,
            "role": m.role.name,
        }
        for m in rows
    ]


def ensure_default_roles(db: Session) -> dict[str, Role]:
    from app.core.permissions import ROLE_PERMISSIONS, RoleName

    role_map: dict[str, Role] = {}
    for rname in RoleName:
        existing = db.execute(select(Role).where(Role.name == rname.value)).scalar_one_or_none()
        perms = sorted(p.value for p in ROLE_PERMISSIONS[rname])
        if existing is None:
            existing = Role(
                name=rname.value,
                description=f"SentinelGraph built-in {rname.value} role",
                permissions=perms,
            )
            db.add(existing)
            db.flush()
        else:
            existing.permissions = perms
        role_map[rname.value] = existing
    return role_map


def get_oidc_public_config() -> dict[str, Any]:
    settings = get_settings()
    return {
        "oidc_enabled": bool(settings.oidc_issuer_url and settings.oidc_client_id),
        "issuer_url": settings.oidc_issuer_url or None,
        "client_id": settings.oidc_client_id or None,
        "redirect_uri": settings.oidc_redirect_uri,
        "local_dev_auth_enabled": settings.local_dev_auth_enabled,
        "supported_roles": ["tenant_admin", "assessor", "analyst", "remediation_owner", "auditor", "read_only"],
    }
