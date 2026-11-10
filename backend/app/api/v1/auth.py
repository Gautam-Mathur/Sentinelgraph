import re
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.deps import get_actor_context, get_current_user_basic, get_request_id
from app.core.config import get_settings
from app.core.telemetry import metrics
from app.db.models import User
from app.db.session import get_db_session
from app.services.auth_service import (
    authenticate_local_user,
    change_local_password,
    get_oidc_public_config,
    list_user_memberships,
    logout_session,
    refresh_session,
    switch_active_tenant,
)
from app.services.context import ActorContext
from app.services.oidc_service import build_oidc_authorization_url, complete_oidc_callback

health_router = APIRouter(tags=["health"])
auth_router = APIRouter(prefix="/auth", tags=["auth"])


_EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=256)
    tenant_slug: str | None = Field(default=None, max_length=64)

    @field_validator("email")
    @classmethod
    def validate_email_syntax(cls, v: str) -> str:
        cleaned = v.strip().lower()
        if not _EMAIL_RE.match(cleaned):
            raise ValueError("Invalid email address format")
        return cleaned


class OidcCallbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=1, max_length=2048)
    state: str = Field(min_length=1, max_length=512)
    tenant_slug: str | None = Field(default=None, max_length=64)


class RefreshTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    refresh_token: str = Field(min_length=10, max_length=4096)


class LogoutRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    refresh_token: str | None = Field(default=None, max_length=4096)


class ChangePasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


class SwitchTenantRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: uuid.UUID


@health_router.get("/healthz")
def healthz() -> dict[str, str]:
    settings = get_settings()
    return {"status": "ok", "service": settings.app_name, "version": settings.app_version}


@health_router.get("/readyz")
def readyz(db: Session = Depends(get_db_session)) -> dict[str, str]:
    db.execute(text("SELECT 1"))
    return {"status": "ready", "database": "ok"}


@health_router.get("/metrics")
def get_metrics(ctx: ActorContext = Depends(get_actor_context)) -> dict[str, Any]:
    return {"tenant_id": str(ctx.tenant_id), "metrics": metrics.snapshot()}


@health_router.get("/metrics/prometheus")
def get_metrics_prometheus(ctx: ActorContext = Depends(get_actor_context)) -> Response:  # noqa: ARG001
    return Response(
        content=metrics.to_prometheus_text(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@auth_router.get("/oidc/config")
def oidc_config() -> dict[str, Any]:
    return get_oidc_public_config()


@auth_router.get("/oidc/login")
def oidc_login(
    tenant_slug: str | None = Query(default=None, max_length=64),
) -> dict[str, Any]:
    return build_oidc_authorization_url(tenant_slug=tenant_slug)


@auth_router.post("/oidc/callback")
def oidc_callback(
    body: OidcCallbackRequest,
    request: Request,
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return complete_oidc_callback(
        db,
        code=body.code,
        state=body.state,
        tenant_slug=body.tenant_slug,
        request_id=get_request_id(request),
    )


@auth_router.post("/login")
def login_local(
    body: LoginRequest,
    request: Request,
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return authenticate_local_user(
        db,
        email=body.email,
        password=body.password,
        tenant_slug=body.tenant_slug,
        request_id=get_request_id(request),
    )


@auth_router.post("/refresh")
def refresh_token_endpoint(
    body: RefreshTokenRequest,
    request: Request,
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return refresh_session(
        db,
        refresh_token=body.refresh_token,
        request_id=get_request_id(request),
    )


@auth_router.post("/logout")
def logout_endpoint(
    request: Request,
    body: LogoutRequest | None = None,
    user_and_claims: tuple[User, dict[str, object]] = Depends(get_current_user_basic),
    db: Session = Depends(get_db_session),
) -> dict[str, str]:
    user, claims = user_and_claims
    return logout_session(
        db,
        user=user,
        claims=dict(claims),
        refresh_token=body.refresh_token if body else None,
        request_id=get_request_id(request),
    )


@auth_router.post("/change-password")
def change_password_endpoint(
    body: ChangePasswordRequest,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, str]:
    return change_local_password(
        db,
        ctx=ctx,
        current_password=body.current_password,
        new_password=body.new_password,
    )


@auth_router.get("/me")
def get_me(
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return {
        "user": {
            "id": str(ctx.user_id),
            "email": ctx.email,
            "display_name": ctx.display_name,
        },
        "active_tenant": {
            "id": str(ctx.tenant_id),
            "slug": ctx.tenant_slug,
            "name": ctx.tenant_name,
            "is_demo": ctx.tenant_is_demo,
            "role": ctx.role,
        },
        "memberships": list_user_memberships(db, ctx.user_id),
    }


@auth_router.post("/switch-tenant")
def switch_tenant(
    body: SwitchTenantRequest,
    request: Request,
    user_and_claims: tuple[User, dict[str, object]] = Depends(get_current_user_basic),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    user, _ = user_and_claims
    return switch_active_tenant(
        db,
        user_id=user.id,
        target_tenant_id=body.tenant_id,
        request_id=get_request_id(request),
    )
