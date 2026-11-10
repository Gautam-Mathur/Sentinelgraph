import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, NotFoundError, ValidationAppError
from app.core.permissions import Permission, require_permission
from app.db.models import Group, Identity
from app.domain.models import IdentityType
from app.services.audit_service import record_audit_event
from app.services.context import ActorContext


def list_identities(
    db: Session,
    ctx: ActorContext,
    *,
    identity_type: str | None = None,
    privilege_level: str | None = None,
    search: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    require_permission(ctx.role, Permission.IDENTITY_READ)
    stmt = select(Identity).where(Identity.tenant_id == ctx.tenant_id, Identity.deleted_at.is_(None))
    if identity_type:
        stmt = stmt.where(Identity.identity_type == identity_type)
    if privilege_level:
        stmt = stmt.where(Identity.privilege_level == privilege_level)
    if search:
        pat = f"%{search.strip()}%"
        stmt = stmt.where(
            or_(
                Identity.display_name.ilike(pat),
                Identity.principal_name.ilike(pat),
                Identity.external_id.ilike(pat),
            )
        )

    total = int(db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one())
    rows = list(db.execute(stmt.order_by(desc(Identity.created_at)).offset(offset).limit(limit)).scalars())
    return [
        {
            "id": str(i.id),
            "identity_type": i.identity_type,
            "external_id": i.external_id,
            "provider": i.provider,
            "display_name": i.display_name,
            "principal_name": i.principal_name,
            "enabled": i.enabled,
            "privilege_level": i.privilege_level,
            "privilege_indicators": i.privilege_indicators,
            "auth_metadata": i.auth_metadata,
            "confidence": i.confidence,
            "first_seen": i.first_seen.isoformat(),
            "last_seen": i.last_seen.isoformat(),
            "source_refs": i.source_refs,
        }
        for i in rows
    ], total


def list_groups(db: Session, ctx: ActorContext, *, limit: int = 50, offset: int = 0) -> tuple[list[dict[str, Any]], int]:
    require_permission(ctx.role, Permission.IDENTITY_READ)
    stmt = select(Group).where(Group.tenant_id == ctx.tenant_id)
    total = int(db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one())
    rows = list(db.execute(stmt.order_by(Group.display_name.asc()).offset(offset).limit(limit)).scalars())
    return [
        {
            "id": str(g.id),
            "external_id": g.external_id,
            "provider": g.provider,
            "display_name": g.display_name,
            "group_type": g.group_type,
            "privilege_indicators": g.privilege_indicators,
            "enabled": g.enabled,
            "confidence": g.confidence,
            "source_refs": g.source_refs,
        }
        for g in rows
    ], total


def create_identity(
    db: Session,
    ctx: ActorContext,
    *,
    identity_type: str,
    external_id: str,
    provider: str,
    display_name: str,
    principal_name: str,
    enabled: bool,
    privilege_level: str,
    privilege_indicators: list[str],
    confidence: float,
) -> dict[str, Any]:
    require_permission(ctx.role, Permission.IDENTITY_WRITE)
    IdentityType(identity_type)

    existing = db.execute(
        select(Identity).where(
            Identity.tenant_id == ctx.tenant_id,
            Identity.provider == provider,
            Identity.external_id == external_id,
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise ConflictError(code="IDENTITY_EXISTS", message="Identity external_id already exists")

    now = datetime.now(UTC)
    ident = Identity(
        tenant_id=ctx.tenant_id,
        identity_type=identity_type,
        external_id=external_id.strip(),
        provider=provider.strip(),
        display_name=display_name.strip(),
        principal_name=principal_name.strip(),
        enabled=enabled,
        privilege_level=privilege_level,
        privilege_indicators=privilege_indicators,
        auth_metadata={"created_via": "api"},
        first_seen=now,
        last_seen=now,
        confidence=confidence,
        raw_attributes={},
        source_refs=[
            {
                "source_product": "manual_analyst_entry",
                "source_record_id": external_id,
                "collection_time": now.isoformat(),
                "parser_version": "api_v1",
                "confidence": confidence,
            }
        ],
    )
    db.add(ident)
    db.flush()

    record_audit_event(
        db,
        tenant_id=ctx.tenant_id,
        actor_user_id=ctx.user_id,
        actor_email=ctx.email,
        action="identity.create",
        object_type="identity",
        object_id=str(ident.id),
        outcome="success",
        request_id=ctx.request_id,
        details={"external_id": ident.external_id, "privilege_level": ident.privilege_level},
    )
    db.commit()
    return {
        "id": str(ident.id),
        "identity_type": ident.identity_type,
        "external_id": ident.external_id,
        "provider": ident.provider,
        "display_name": ident.display_name,
        "principal_name": ident.principal_name,
        "enabled": ident.enabled,
        "privilege_level": ident.privilege_level,
        "confidence": ident.confidence,
    }


def get_identity_detail(db: Session, ctx: ActorContext, identity_id: uuid.UUID) -> dict[str, Any]:
    require_permission(ctx.role, Permission.IDENTITY_READ)
    ident = db.execute(
        select(Identity).where(
            Identity.id == identity_id,
            Identity.tenant_id == ctx.tenant_id,
            Identity.deleted_at.is_(None),
        )
    ).scalar_one_or_none()
    if ident is None:
        raise NotFoundError(code="IDENTITY_NOT_FOUND", message="Identity not found")
    return {
        "id": str(ident.id),
        "identity_type": ident.identity_type,
        "external_id": ident.external_id,
        "provider": ident.provider,
        "display_name": ident.display_name,
        "principal_name": ident.principal_name,
        "enabled": ident.enabled,
        "privilege_level": ident.privilege_level,
        "privilege_indicators": ident.privilege_indicators,
        "auth_metadata": ident.auth_metadata,
        "confidence": ident.confidence,
        "source_refs": ident.source_refs,
    }


def update_identity(
    db: Session,
    ctx: ActorContext,
    *,
    identity_id: uuid.UUID,
    display_name: str | None = None,
    enabled: bool | None = None,
    privilege_level: str | None = None,
    privilege_indicators: list[str] | None = None,
    retire: bool = False,
) -> dict[str, Any]:
    require_permission(ctx.role, Permission.IDENTITY_WRITE)
    ident = db.execute(
        select(Identity).where(
            Identity.id == identity_id,
            Identity.tenant_id == ctx.tenant_id,
            Identity.deleted_at.is_(None),
        )
    ).scalar_one_or_none()
    if ident is None:
        raise NotFoundError(code="IDENTITY_NOT_FOUND", message="Identity not found")

    if privilege_level is not None:
        if privilege_level not in ("standard", "elevated", "privileged", "domain_admin"):
            raise ValidationAppError(
                code="INVALID_PRIVILEGE_LEVEL",
                message="privilege_level must be standard, elevated, privileged, or domain_admin.",
            )
        ident.privilege_level = privilege_level

    if display_name is not None:
        ident.display_name = display_name.strip()[:255]
    if enabled is not None:
        ident.enabled = enabled
    if privilege_indicators is not None:
        ident.privilege_indicators = privilege_indicators
    if retire:
        ident.enabled = False
        ident.deleted_at = datetime.now(UTC)

    db.flush()
    record_audit_event(
        db,
        tenant_id=ctx.tenant_id,
        actor_user_id=ctx.user_id,
        actor_email=ctx.email,
        action="identity.retire" if retire else "identity.update",
        object_type="identity",
        object_id=str(ident.id),
        outcome="success",
        request_id=ctx.request_id,
        details={
            "enabled": ident.enabled,
            "privilege_level": ident.privilege_level,
            "retired": retire,
        },
    )
    db.commit()
    return {
        "id": str(ident.id),
        "identity_type": ident.identity_type,
        "external_id": ident.external_id,
        "provider": ident.provider,
        "display_name": ident.display_name,
        "principal_name": ident.principal_name,
        "enabled": ident.enabled,
        "privilege_level": ident.privilege_level,
        "privilege_indicators": ident.privilege_indicators,
        "auth_metadata": ident.auth_metadata,
        "confidence": ident.confidence,
        "retired": bool(ident.deleted_at is not None),
        "source_refs": ident.source_refs,
    }
