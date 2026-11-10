import uuid
from typing import Annotated

from fastapi import Depends, Header, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import AuthenticationError, AuthorizationError
from app.core.logging import correlation_id_var, tenant_id_var
from app.core.security import decode_access_token
from app.core.token_store import is_token_revoked
from app.db.models import Membership, User
from app.db.session import get_db_session, set_rls_context
from app.services.context import ActorContext

_bearer_scheme = HTTPBearer(auto_error=False)


def get_request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", correlation_id_var.get("-")))


def get_current_user_basic(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)],
    db: Annotated[Session, Depends(get_db_session)],
) -> tuple[User, dict[str, object]]:
    if credentials is None or not credentials.credentials:
        raise AuthenticationError("Missing Bearer token", "AUTH_REQUIRED")
    payload = decode_access_token(credentials.credentials)
    jti = payload.get("jti")
    if jti and is_token_revoked(db, str(jti)):
        raise AuthenticationError("Access token has been revoked", "TOKEN_REVOKED")
    try:
        user_id = uuid.UUID(str(payload["sub"]))
    except (ValueError, KeyError) as exc:
        raise AuthenticationError("Malformed subject claim", "TOKEN_INVALID") from exc

    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise AuthenticationError("User account is inactive or missing", "USER_INACTIVE")
    return user, payload


def get_actor_context(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)],
    db: Annotated[Session, Depends(get_db_session)],
    x_tenant_id: Annotated[str | None, Header(alias="X-Tenant-ID")] = None,
) -> ActorContext:
    user, payload = get_current_user_basic(credentials, db)

    raw_tenant = x_tenant_id or str(payload.get("tenant_id", ""))
    try:
        tenant_id = uuid.UUID(raw_tenant)
    except ValueError as exc:
        raise AuthenticationError("Invalid tenant context", "INVALID_TENANT_CONTEXT") from exc

    set_rls_context(db, tenant_id=tenant_id, user_id=user.id)
    membership = db.execute(
        select(Membership).where(
            Membership.tenant_id == tenant_id,
            Membership.user_id == user.id,
            Membership.status == "active",
        )
    ).scalar_one_or_none()
    if membership is None:
        raise AuthorizationError(
            "No active membership for requested tenant.",
            code="TENANT_ACCESS_DENIED",
        )

    tenant_id_var.set(str(tenant_id))
    request.state.tenant_id = str(tenant_id)
    return ActorContext(
        user_id=user.id,
        email=user.email,
        display_name=user.display_name,
        tenant_id=membership.tenant.id,
        tenant_slug=membership.tenant.slug,
        tenant_name=membership.tenant.name,
        tenant_is_demo=membership.tenant.is_demo,
        role=membership.role.name,
        request_id=get_request_id(request),
        auth_method=str(payload.get("auth_method", "bearer")),
    )
