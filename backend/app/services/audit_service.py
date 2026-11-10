import csv
import hashlib
import io
import json
import uuid
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.core.logging import redact_dict
from app.core.permissions import Permission, require_permission
from app.db.models import AuditEvent
from app.services.context import ActorContext


def record_audit_event(
    db: Session,
    *,
    tenant_id: uuid.UUID,
    actor_user_id: uuid.UUID | None,
    actor_email: str,
    action: str,
    object_type: str,
    object_id: str,
    outcome: str,
    request_id: str,
    details: dict[str, Any] | None = None,
) -> AuditEvent:
    last_event = db.execute(
        select(AuditEvent)
        .where(AuditEvent.tenant_id == tenant_id)
        .order_by(desc(AuditEvent.created_at), desc(AuditEvent.id))
        .limit(1)
    ).scalar_one_or_none()

    prev_hash = last_event.event_hash if last_event is not None else "0" * 64
    safe_details = redact_dict(details or {})
    canonical = json.dumps(
        {
            "tenant_id": str(tenant_id),
            "actor_user_id": str(actor_user_id) if actor_user_id else None,
            "actor_email": actor_email,
            "action": action,
            "object_type": object_type,
            "object_id": object_id,
            "outcome": outcome,
            "request_id": request_id,
            "details": safe_details,
            "prev_hash": prev_hash,
        },
        sort_keys=True,
        default=str,
    )
    event_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    ev = AuditEvent(
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_email=actor_email,
        action=action,
        object_type=object_type,
        object_id=object_id,
        outcome=outcome,
        request_id=request_id,
        details=safe_details,
        prev_hash=prev_hash,
        event_hash=event_hash,
    )
    db.add(ev)
    db.flush()
    return ev


def list_audit_events(
    db: Session,
    ctx: ActorContext,
    *,
    action: str | None = None,
    outcome: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[AuditEvent], int]:
    require_permission(ctx.role, Permission.AUDIT_READ)
    stmt = select(AuditEvent).where(AuditEvent.tenant_id == ctx.tenant_id)
    if action:
        stmt = stmt.where(AuditEvent.action == action)
    if outcome:
        stmt = stmt.where(AuditEvent.outcome == outcome)

    rows = list(
        db.execute(stmt.order_by(desc(AuditEvent.created_at)).offset(offset).limit(limit)).scalars()
    )
    all_count = len(list(db.execute(stmt).scalars()))
    return rows, all_count


def export_audit_events(
    db: Session,
    ctx: ActorContext,
    *,
    export_format: str = "json",
) -> tuple[str, str]:
    require_permission(ctx.role, Permission.AUDIT_EXPORT)
    events = list(
        db.execute(
            select(AuditEvent)
            .where(AuditEvent.tenant_id == ctx.tenant_id)
            .order_by(AuditEvent.created_at.asc())
        ).scalars()
    )
    record_audit_event(
        db,
        tenant_id=ctx.tenant_id,
        actor_user_id=ctx.user_id,
        actor_email=ctx.email,
        action="audit.export",
        object_type="audit_log",
        object_id=str(ctx.tenant_id),
        outcome="success",
        request_id=ctx.request_id,
        details={"format": export_format, "exported_count": len(events)},
    )
    db.commit()

    if export_format == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(
            [
                "id",
                "created_at",
                "actor_email",
                "action",
                "object_type",
                "object_id",
                "outcome",
                "request_id",
                "prev_hash",
                "event_hash",
            ]
        )
        for ev in events:
            writer.writerow(
                [
                    str(ev.id),
                    ev.created_at.isoformat(),
                    ev.actor_email,
                    ev.action,
                    ev.object_type,
                    ev.object_id,
                    ev.outcome,
                    ev.request_id,
                    ev.prev_hash,
                    ev.event_hash,
                ]
            )
        return buf.getvalue(), "text/csv"

    payload = [
        {
            "id": str(ev.id),
            "tenant_id": str(ev.tenant_id),
            "actor_user_id": str(ev.actor_user_id) if ev.actor_user_id else None,
            "actor_email": ev.actor_email,
            "action": ev.action,
            "object_type": ev.object_type,
            "object_id": ev.object_id,
            "outcome": ev.outcome,
            "request_id": ev.request_id,
            "details": ev.details,
            "prev_hash": ev.prev_hash,
            "event_hash": ev.event_hash,
            "created_at": ev.created_at.isoformat(),
        }
        for ev in events
    ]
    return json.dumps(payload, indent=2), "application/json"
