import re
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import ConflictError, NotFoundError, ValidationAppError
from app.core.permissions import Permission, RoleName, require_permission
from app.core.security import hash_password, validate_password_strength
from app.db.models import Membership, Role, Tenant, User
from app.db.session import set_rls_context
from app.services.audit_service import record_audit_event
from app.services.auth_service import ensure_default_roles

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,62}[a-z0-9]$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")


def create_tenant(
    db: Session,
    *,
    creator_user_id: uuid.UUID,
    creator_email: str,
    name: str,
    slug: str,
    is_demo: bool,
    request_id: str,
) -> dict[str, Any]:
    cleaned_slug = slug.strip().lower()
    if not SLUG_RE.match(cleaned_slug):
        raise ValidationAppError(
            code="INVALID_TENANT_SLUG",
            message="Tenant slug must be 3-64 lowercase alphanumeric or hyphen characters.",
        )

    existing = db.execute(select(Tenant).where(Tenant.slug == cleaned_slug)).scalar_one_or_none()
    if existing is not None:
        raise ConflictError(code="TENANT_EXISTS", message=f"Tenant slug '{cleaned_slug}' already exists.")

    roles = ensure_default_roles(db)
    tenant = Tenant(name=name.strip(), slug=cleaned_slug, is_demo=is_demo)
    db.add(tenant)
    db.flush()

    set_rls_context(db, tenant_id=tenant.id, user_id=creator_user_id)
    membership = Membership(
        tenant_id=tenant.id,
        user_id=creator_user_id,
        role_id=roles[RoleName.TENANT_ADMIN.value].id,
        status="active",
    )
    db.add(membership)
    db.flush()

    record_audit_event(
        db,
        tenant_id=tenant.id,
        actor_user_id=creator_user_id,
        actor_email=creator_email,
        action="tenant.create",
        object_type="tenant",
        object_id=str(tenant.id),
        outcome="success",
        request_id=request_id,
        details={"slug": tenant.slug, "is_demo": tenant.is_demo},
    )
    db.commit()

    return {
        "id": str(tenant.id),
        "slug": tenant.slug,
        "name": tenant.name,
        "is_demo": tenant.is_demo,
        "role": RoleName.TENANT_ADMIN.value,
    }


def list_tenant_memberships(db: Session, ctx: Any) -> list[dict[str, Any]]:
    require_permission(ctx.role, Permission.MEMBERSHIP_MANAGE)
    rows = list(
        db.execute(select(Membership).where(Membership.tenant_id == ctx.tenant_id)).scalars()
    )
    return [
        {
            "membership_id": str(m.id),
            "user_id": str(m.user_id),
            "email": m.user.email,
            "display_name": m.user.display_name,
            "auth_provider": m.user.auth_provider,
            "role": m.role.name,
            "status": m.status,
            "mfa_enabled": m.user.mfa_enabled,
        }
        for m in rows
    ]


def invite_or_add_member(
    db: Session,
    ctx: Any,
    *,
    email: str,
    display_name: str,
    role: str,
    auth_provider: str = "oidc",
    password: str | None = None,
    external_subject: str | None = None,
) -> dict[str, Any]:
    require_permission(ctx.role, Permission.MEMBERSHIP_MANAGE)
    clean_email = email.strip().lower()
    if not EMAIL_RE.match(clean_email):
        raise ValidationAppError(code="INVALID_EMAIL", message="Invalid member email address.")
    try:
        RoleName(role)
    except ValueError as exc:
        raise ValidationAppError(code="INVALID_ROLE", message=f"Unsupported role '{role}'.") from exc

    if auth_provider not in ("oidc", "local"):
        raise ValidationAppError(
            code="INVALID_AUTH_PROVIDER",
            message="auth_provider must be 'oidc' or 'local'.",
        )

    settings = get_settings()
    if auth_provider == "local" and not settings.local_dev_auth_enabled:
        raise ValidationAppError(
            code="LOCAL_AUTH_DISABLED",
            message="Cannot provision local password users outside development/test environments; use 'oidc'.",
        )

    roles = ensure_default_roles(db)
    user = db.execute(select(User).where(User.email == clean_email)).scalar_one_or_none()
    if user is None:
        pwd_hash: str | None = None
        if auth_provider == "local":
            if not password:
                raise ValidationAppError(
                    code="PASSWORD_REQUIRED",
                    message="Initial password is required for local user provisioning.",
                )
            validate_password_strength(password)
            pwd_hash = hash_password(password)
        user = User(
            email=clean_email,
            display_name=display_name.strip()[:200],
            auth_provider=auth_provider,
            external_subject=external_subject.strip() if external_subject else None,
            password_hash=pwd_hash,
            is_active=True,
            mfa_enabled=(auth_provider == "oidc"),
        )
        db.add(user)
        db.flush()

    existing_mem = db.execute(
        select(Membership).where(
            Membership.tenant_id == ctx.tenant_id,
            Membership.user_id == user.id,
        )
    ).scalar_one_or_none()
    if existing_mem is not None:
        raise ConflictError(
            code="MEMBERSHIP_EXISTS",
            message=f"User '{clean_email}' is already a member of this tenant.",
        )

    membership = Membership(
        tenant_id=ctx.tenant_id,
        user_id=user.id,
        role_id=roles[role].id,
        status="active",
    )
    db.add(membership)
    db.flush()

    record_audit_event(
        db,
        tenant_id=ctx.tenant_id,
        actor_user_id=ctx.user_id,
        actor_email=ctx.email,
        action="membership.create",
        object_type="membership",
        object_id=str(membership.id),
        outcome="success",
        request_id=ctx.request_id,
        details={
            "target_user_email": user.email,
            "role": role,
            "auth_provider": auth_provider,
        },
    )
    db.commit()

    return {
        "membership_id": str(membership.id),
        "user_id": str(user.id),
        "email": user.email,
        "display_name": user.display_name,
        "auth_provider": user.auth_provider,
        "role": role,
        "status": membership.status,
        "mfa_enabled": user.mfa_enabled,
    }


def _count_active_tenant_admins(db: Session, tenant_id: uuid.UUID) -> int:
    rows = list(
        db.execute(
            select(Membership).where(
                Membership.tenant_id == tenant_id,
                Membership.status == "active",
            )
        ).scalars()
    )
    return sum(1 for m in rows if m.role.name == RoleName.TENANT_ADMIN.value)


def update_member_role(
    db: Session,
    ctx: Any,
    *,
    membership_id: uuid.UUID,
    new_role: str | None = None,
    new_status: str | None = None,
) -> dict[str, Any]:
    require_permission(ctx.role, Permission.MEMBERSHIP_MANAGE)
    if new_role is None and new_status is None:
        raise ValidationAppError(
            code="NO_UPDATE_FIELDS",
            message="Provide at least one of 'role' or 'status' to update.",
        )

    if new_role is not None:
        try:
            RoleName(new_role)
        except ValueError as exc:
            raise ValidationAppError(
                code="INVALID_ROLE",
                message=f"Unsupported role '{new_role}'.",
            ) from exc

    if new_status is not None and new_status not in ("active", "suspended"):
        raise ValidationAppError(
            code="INVALID_MEMBERSHIP_STATUS",
            message="Membership status must be 'active' or 'suspended'.",
        )

    membership = db.execute(
        select(Membership).where(
            Membership.id == membership_id,
            Membership.tenant_id == ctx.tenant_id,
        )
    ).scalar_one_or_none()
    if membership is None:
        raise NotFoundError(code="MEMBERSHIP_NOT_FOUND", message="Membership not found")

    old_role = membership.role.name
    old_status = membership.status
    target_role = new_role if new_role is not None else old_role
    target_status = new_status if new_status is not None else old_status

    was_active_admin = old_role == RoleName.TENANT_ADMIN.value and old_status == "active"
    will_remain_active_admin = (
        target_role == RoleName.TENANT_ADMIN.value and target_status == "active"
    )
    if (
        was_active_admin
        and not will_remain_active_admin
        and _count_active_tenant_admins(db, ctx.tenant_id) <= 1
    ):
        raise ConflictError(
                code="LAST_ADMIN_PROTECTED",
                message="Cannot demote or suspend the last active tenant_admin in a tenant.",
            )

    if new_role is not None and new_role != old_role:
        role_obj = db.execute(select(Role).where(Role.name == new_role)).scalar_one_or_none()
        if role_obj is None:
            role_obj = ensure_default_roles(db)[new_role]
        membership.role_id = role_obj.id

    if new_status is not None:
        membership.status = new_status

    db.flush()

    record_audit_event(
        db,
        tenant_id=ctx.tenant_id,
        actor_user_id=ctx.user_id,
        actor_email=ctx.email,
        action="membership.update",
        object_type="membership",
        object_id=str(membership.id),
        outcome="success",
        request_id=ctx.request_id,
        details={
            "target_user_email": membership.user.email,
            "old_role": old_role,
            "new_role": target_role,
            "old_status": old_status,
            "new_status": target_status,
        },
    )
    db.commit()

    return {
        "membership_id": str(membership.id),
        "user_id": str(membership.user_id),
        "email": membership.user.email,
        "display_name": membership.user.display_name,
        "role": target_role,
        "status": membership.status,
    }
