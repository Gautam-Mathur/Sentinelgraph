import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.core.errors import NotFoundError, ValidationAppError
from app.core.permissions import Permission, require_permission
from app.db.models import Asset, Group, Identity, Observation, Relationship, Service
from app.domain.relationship_rules import validate_relationship
from app.services.audit_service import record_audit_event
from app.services.context import ActorContext


def _verify_node_exists(
    db: Session,
    *,
    tenant_id: uuid.UUID,
    node_kind: str,
    node_id: uuid.UUID,
) -> str:
    if node_kind == "asset":
        row = db.execute(
            select(Asset).where(Asset.id == node_id, Asset.tenant_id == tenant_id, Asset.deleted_at.is_(None))
        ).scalar_one_or_none()
        if row is not None:
            return row.display_name
    elif node_kind == "identity":
        row_i = db.execute(
            select(Identity).where(
                Identity.id == node_id, Identity.tenant_id == tenant_id, Identity.deleted_at.is_(None)
            )
        ).scalar_one_or_none()
        if row_i is not None:
            return row_i.display_name
    elif node_kind == "group":
        row_g = db.execute(
            select(Group).where(Group.id == node_id, Group.tenant_id == tenant_id)
        ).scalar_one_or_none()
        if row_g is not None:
            return row_g.display_name
    elif node_kind == "service":
        row_s = db.execute(
            select(Service).where(Service.id == node_id, Service.tenant_id == tenant_id)
        ).scalar_one_or_none()
        if row_s is not None:
            return f"{row_s.service_name}:{row_s.port}/{row_s.protocol}"
    raise NotFoundError(
        code="NODE_NOT_FOUND",
        message=f"Endpoint {node_kind}:{node_id} was not found in this tenant.",
    )


def list_relationships(
    db: Session,
    ctx: ActorContext,
    *,
    relation_type: str | None = None,
    fact_kind: str | None = None,
    include_suppressed: bool = True,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    require_permission(ctx.role, Permission.RELATIONSHIP_READ)
    stmt = select(Relationship).where(Relationship.tenant_id == ctx.tenant_id)
    if relation_type:
        stmt = stmt.where(Relationship.relation_type == relation_type)
    if fact_kind:
        stmt = stmt.where(Relationship.fact_kind == fact_kind)
    if not include_suppressed:
        stmt = stmt.where(Relationship.is_suppressed.is_(False))

    total = int(db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one())
    rows = list(
        db.execute(stmt.order_by(desc(Relationship.created_at)).offset(offset).limit(limit)).scalars()
    )

    label_cache: dict[tuple[str, uuid.UUID], str] = {}
    for a in db.execute(select(Asset).where(Asset.tenant_id == ctx.tenant_id)).scalars():
        label_cache[("asset", a.id)] = a.display_name
    for i in db.execute(select(Identity).where(Identity.tenant_id == ctx.tenant_id)).scalars():
        label_cache[("identity", i.id)] = i.display_name
    for g in db.execute(select(Group).where(Group.tenant_id == ctx.tenant_id)).scalars():
        label_cache[("group", g.id)] = g.display_name
    for s in db.execute(select(Service).where(Service.tenant_id == ctx.tenant_id)).scalars():
        label_cache[("service", s.id)] = f"{s.service_name}:{s.port}/{s.protocol}"

    return [
        {
            "id": str(r.id),
            "assessment_id": str(r.assessment_id) if r.assessment_id else None,
            "source_kind": r.source_kind,
            "source_id": str(r.source_id),
            "source_label": label_cache.get((r.source_kind, r.source_id), str(r.source_id)),
            "target_kind": r.target_kind,
            "target_id": str(r.target_id),
            "target_label": label_cache.get((r.target_kind, r.target_id), str(r.target_id)),
            "relation_type": r.relation_type,
            "fact_kind": r.fact_kind,
            "confidence": r.confidence,
            "valid_from": r.valid_from.isoformat(),
            "valid_to": r.valid_to.isoformat() if r.valid_to else None,
            "provenance": r.provenance,
            "edge_metadata": r.edge_metadata,
            "is_suppressed": r.is_suppressed,
            "suppressed_reason": r.suppressed_reason,
            "suppressed_at": r.suppressed_at.isoformat() if r.suppressed_at else None,
        }
        for r in rows
    ], total


def create_relationship(
    db: Session,
    ctx: ActorContext,
    *,
    assessment_id: uuid.UUID | None,
    source_kind: str,
    source_id: uuid.UUID,
    target_kind: str,
    target_id: uuid.UUID,
    relation_type: str,
    fact_kind: str,
    confidence: float,
    valid_from: datetime | None,
    valid_to: datetime | None,
    edge_metadata: dict[str, Any],
) -> dict[str, Any]:
    require_permission(ctx.role, Permission.RELATIONSHIP_WRITE)
    validate_relationship(
        source_kind=source_kind,
        target_kind=target_kind,
        relation_type=relation_type,
        fact_kind=fact_kind,
        confidence=confidence,
        source_id=str(source_id),
        target_id=str(target_id),
    )

    if valid_from and valid_to and valid_to < valid_from:
        raise ValidationAppError(
            code="INVALID_TEMPORAL_WINDOW",
            message="valid_to must not precede valid_from",
        )

    src_label = _verify_node_exists(db, tenant_id=ctx.tenant_id, node_kind=source_kind, node_id=source_id)
    tgt_label = _verify_node_exists(db, tenant_id=ctx.tenant_id, node_kind=target_kind, node_id=target_id)

    now = datetime.now(UTC)
    rel = Relationship(
        tenant_id=ctx.tenant_id,
        assessment_id=assessment_id,
        source_kind=source_kind,
        source_id=source_id,
        target_kind=target_kind,
        target_id=target_id,
        relation_type=relation_type,
        fact_kind=fact_kind,
        confidence=confidence,
        valid_from=valid_from or now,
        valid_to=valid_to,
        provenance={
            "source_product": "manual_analyst_assertion" if fact_kind == "analyst_assertion" else "api_v1",
            "source_record_id": f"{source_id}->{target_id}:{relation_type}",
            "collection_time": now.isoformat(),
            "parser_version": "api_v1",
            "confidence": confidence,
            "actor_email": ctx.email,
        },
        edge_metadata=edge_metadata,
    )
    db.add(rel)
    db.flush()

    record_audit_event(
        db,
        tenant_id=ctx.tenant_id,
        actor_user_id=ctx.user_id,
        actor_email=ctx.email,
        action="relationship.create",
        object_type="relationship",
        object_id=str(rel.id),
        outcome="success",
        request_id=ctx.request_id,
        details={
            "relation_type": relation_type,
            "fact_kind": fact_kind,
            "source": src_label,
            "target": tgt_label,
        },
    )
    db.commit()

    return {
        "id": str(rel.id),
        "source_kind": rel.source_kind,
        "source_id": str(rel.source_id),
        "source_label": src_label,
        "target_kind": rel.target_kind,
        "target_id": str(rel.target_id),
        "target_label": tgt_label,
        "relation_type": rel.relation_type,
        "fact_kind": rel.fact_kind,
        "confidence": rel.confidence,
        "is_suppressed": rel.is_suppressed,
        "provenance": rel.provenance,
    }


def suppress_relationship(
    db: Session,
    ctx: ActorContext,
    *,
    relationship_id: uuid.UUID,
    suppressed: bool,
    reason: str,
) -> dict[str, Any]:
    require_permission(ctx.role, Permission.EVIDENCE_CHALLENGE)
    rel = db.execute(
        select(Relationship).where(
            Relationship.id == relationship_id,
            Relationship.tenant_id == ctx.tenant_id,
        )
    ).scalar_one_or_none()
    if rel is None:
        raise NotFoundError(code="RELATIONSHIP_NOT_FOUND", message="Relationship not found")

    rel.is_suppressed = suppressed
    rel.suppressed_reason = reason.strip() if suppressed else None
    rel.suppressed_by = ctx.user_id if suppressed else None
    rel.suppressed_at = datetime.now(UTC) if suppressed else None
    db.flush()

    record_audit_event(
        db,
        tenant_id=ctx.tenant_id,
        actor_user_id=ctx.user_id,
        actor_email=ctx.email,
        action="evidence.suppress" if suppressed else "evidence.restore",
        object_type="relationship",
        object_id=str(rel.id),
        outcome="success",
        request_id=ctx.request_id,
        details={"suppressed": suppressed, "reason": reason, "raw_provenance_preserved": True},
    )
    db.commit()

    return {
        "id": str(rel.id),
        "is_suppressed": rel.is_suppressed,
        "suppressed_reason": rel.suppressed_reason,
        "provenance": rel.provenance,
    }


def suppress_observation(
    db: Session,
    ctx: ActorContext,
    *,
    observation_id: uuid.UUID,
    suppressed: bool,
    reason: str,
) -> dict[str, Any]:
    require_permission(ctx.role, Permission.EVIDENCE_CHALLENGE)
    obs = db.execute(
        select(Observation).where(
            Observation.id == observation_id,
            Observation.tenant_id == ctx.tenant_id,
        )
    ).scalar_one_or_none()
    if obs is None:
        raise NotFoundError(code="OBSERVATION_NOT_FOUND", message="Observation not found")

    obs.is_suppressed = suppressed
    obs.suppression_reason = reason.strip() if suppressed else None
    obs.suppressed_by = ctx.user_id if suppressed else None
    obs.suppressed_at = datetime.now(UTC) if suppressed else None
    db.flush()

    record_audit_event(
        db,
        tenant_id=ctx.tenant_id,
        actor_user_id=ctx.user_id,
        actor_email=ctx.email,
        action="evidence.suppress_observation" if suppressed else "evidence.restore_observation",
        object_type="observation",
        object_id=str(obs.id),
        outcome="success",
        request_id=ctx.request_id,
        details={"suppressed": suppressed, "reason": reason},
    )
    db.commit()
    return {
        "id": str(obs.id),
        "is_suppressed": obs.is_suppressed,
        "suppression_reason": obs.suppression_reason,
        "source_product": obs.source_product,
        "source_record_id": obs.source_record_id,
    }
