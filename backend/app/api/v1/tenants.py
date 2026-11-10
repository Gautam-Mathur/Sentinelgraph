import uuid
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.api.deps import get_actor_context, get_current_user_basic, get_request_id
from app.db.models import User
from app.db.session import get_db_session
from app.services.context import ActorContext
from app.services.dashboard_service import get_dashboard_kpis, global_tenant_search
from app.services.tenant_service import (
    create_tenant,
    invite_or_add_member,
    list_tenant_memberships,
    update_member_role,
)

tenants_router = APIRouter(prefix="/tenants", tags=["tenants"])
dashboard_router = APIRouter(tags=["dashboard"])


class CreateTenantRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=2, max_length=200)
    slug: str = Field(min_length=3, max_length=64)
    is_demo: bool = False


class CreateMemberRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=320)
    display_name: str = Field(min_length=2, max_length=200)
    role: str = Field(min_length=2, max_length=64)
    auth_provider: Literal["oidc", "local"] = "oidc"
    password: str | None = Field(default=None, max_length=256)
    external_subject: str | None = Field(default=None, max_length=255)


class UpdateMemberRoleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: str | None = Field(default=None, min_length=2, max_length=64)
    status: Literal["active", "suspended"] | None = None


@tenants_router.post("", status_code=201)
def create_tenant_endpoint(
    body: CreateTenantRequest,
    request: Request,
    user_and_claims: tuple[User, dict[str, object]] = Depends(get_current_user_basic),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    user, _ = user_and_claims
    return create_tenant(
        db,
        creator_user_id=user.id,
        creator_email=user.email,
        name=body.name,
        slug=body.slug,
        is_demo=body.is_demo,
        request_id=get_request_id(request),
    )


@tenants_router.get("/members")
def list_members_endpoint(
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return {"items": list_tenant_memberships(db, ctx)}


@tenants_router.post("/members", status_code=201)
def create_member_endpoint(
    body: CreateMemberRequest,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return invite_or_add_member(
        db,
        ctx,
        email=body.email,
        display_name=body.display_name,
        role=body.role,
        auth_provider=body.auth_provider,
        password=body.password,
        external_subject=body.external_subject,
    )


@tenants_router.patch("/members/{membership_id}")
def update_member_role_endpoint(
    membership_id: uuid.UUID,
    body: UpdateMemberRoleRequest,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return update_member_role(
        db,
        ctx,
        membership_id=membership_id,
        new_role=body.role,
        new_status=body.status,
    )


@dashboard_router.get("/dashboard")
def get_dashboard(
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return get_dashboard_kpis(db, ctx)


@dashboard_router.get("/search")
def global_search(
    q: str = Query(default="", max_length=128),
    limit: int = Query(default=25, ge=1, le=100),
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return global_tenant_search(db, ctx, query=q, limit=limit)
