from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.errors import ValidationAppError
from app.core.permissions import Permission, require_permission
from app.db.models import (
    Assessment,
    Asset,
    Identity,
    ImportJob,
    Observation,
    Relationship,
    Report,
    RetentionPolicy,
    RetentionRequest,
)
from app.services.audit_service import record_audit_event
from app.services.context import ActorContext

ALLOWED_DATA_CLASSES = frozenset({"imports", "observations", "reports", "identities", "assessments"})


def list_retention_policies(db: Session, ctx: ActorContext) -> dict[str, Any]:
    require_permission(ctx.role, Permission.RETENTION_MANAGE)
    policies = list(
        db.execute(select(RetentionPolicy).where(RetentionPolicy.tenant_id == ctx.tenant_id)).scalars()
    )
    requests = list(
        db.execute(
            select(RetentionRequest)
            .where(RetentionRequest.tenant_id == ctx.tenant_id)
            .order_by(RetentionRequest.created_at.desc())
        ).scalars()
    )
    return {
        "policies": [
            {
                "id": str(p.id),
                "data_class": p.data_class,
                "retention_days": p.retention_days,
                "lawful_basis": p.lawful_basis,
            }
            for p in policies
        ],
        "requests": [
            {
                "id": str(r.id),
                "request_type": r.request_type,
                "data_class": r.data_class,
                "status": r.status,
                "summary": r.summary,
                "created_at": r.created_at.isoformat(),
            }
            for r in requests
        ],
    }


def upsert_retention_policy(
    db: Session,
    ctx: ActorContext,
    *,
    data_class: str,
    retention_days: int,
    lawful_basis: str,
) -> dict[str, Any]:
    require_permission(ctx.role, Permission.RETENTION_MANAGE)
    if data_class not in ALLOWED_DATA_CLASSES:
        raise ValidationAppError(code="INVALID_DATA_CLASS", message=f"Unsupported data class '{data_class}'")
    if retention_days < 7 or retention_days > 3650:
        raise ValidationAppError(
            code="INVALID_RETENTION_DAYS",
            message="retention_days must be between 7 and 3650",
        )

    pol = db.execute(
        select(RetentionPolicy).where(
            RetentionPolicy.tenant_id == ctx.tenant_id,
            RetentionPolicy.data_class == data_class,
        )
    ).scalar_one_or_none()
    if pol is None:
        pol = RetentionPolicy(
            tenant_id=ctx.tenant_id,
            data_class=data_class,
            retention_days=retention_days,
            lawful_basis=lawful_basis,
        )
        db.add(pol)
    else:
        pol.retention_days = retention_days
        pol.lawful_basis = lawful_basis
    db.flush()

    record_audit_event(
        db,
        tenant_id=ctx.tenant_id,
        actor_user_id=ctx.user_id,
        actor_email=ctx.email,
        action="retention.policy_update",
        object_type="retention_policy",
        object_id=str(pol.id),
        outcome="success",
        request_id=ctx.request_id,
        details={"data_class": data_class, "retention_days": retention_days},
    )
    db.commit()
    return {
        "id": str(pol.id),
        "data_class": pol.data_class,
        "retention_days": pol.retention_days,
        "lawful_basis": pol.lawful_basis,
    }


def export_tenant_data_bundle(db: Session, ctx: ActorContext) -> dict[str, Any]:
    require_permission(ctx.role, Permission.RETENTION_MANAGE)
    assets = list(
        db.execute(
            select(Asset).where(Asset.tenant_id == ctx.tenant_id, Asset.deleted_at.is_(None))
        ).scalars()
    )
    identities = list(
        db.execute(
            select(Identity).where(Identity.tenant_id == ctx.tenant_id, Identity.deleted_at.is_(None))
        ).scalars()
    )
    rels = list(
        db.execute(select(Relationship).where(Relationship.tenant_id == ctx.tenant_id)).scalars()
    )
    imports = list(
        db.execute(select(ImportJob).where(ImportJob.tenant_id == ctx.tenant_id)).scalars()
    )
    reports = list(
        db.execute(select(Report).where(Report.tenant_id == ctx.tenant_id)).scalars()
    )

    req = RetentionRequest(
        tenant_id=ctx.tenant_id,
        request_type="export",
        data_class="all",
        status="completed",
        requested_by_user_id=ctx.user_id,
        summary={
            "assets": len(assets),
            "identities": len(identities),
            "relationships": len(rels),
            "imports": len(imports),
            "reports": len(reports),
        },
    )
    db.add(req)
    db.flush()
    record_audit_event(
        db,
        tenant_id=ctx.tenant_id,
        actor_user_id=ctx.user_id,
        actor_email=ctx.email,
        action="retention.export",
        object_type="tenant",
        object_id=str(ctx.tenant_id),
        outcome="success",
        request_id=ctx.request_id,
        details=req.summary,
    )
    db.commit()

    return {
        "tenant_id": str(ctx.tenant_id),
        "exported_at": datetime.now(UTC).isoformat(),
        "assets": [{"id": str(a.id), "canonical_key": a.canonical_key, "display_name": a.display_name} for a in assets],
        "identities": [
            {"id": str(i.id), "external_id": i.external_id, "display_name": i.display_name}
            for i in identities
        ],
        "relationships_count": len(rels),
        "imports_count": len(imports),
        "reports_count": len(reports),
    }


def request_data_deletion(
    db: Session,
    ctx: ActorContext,
    *,
    data_class: str,
) -> dict[str, Any]:
    require_permission(ctx.role, Permission.RETENTION_MANAGE)
    if data_class not in ALLOWED_DATA_CLASSES:
        raise ValidationAppError(
            code="UNSUPPORTED_DELETION_CLASS",
            message=f"Unsupported data_class '{data_class}'. Allowed: {', '.join(sorted(ALLOWED_DATA_CLASSES))}.",
        )

    affected = 0
    now = datetime.now(UTC)
    if data_class == "identities":
        rows = list(
            db.execute(
                select(Identity).where(Identity.tenant_id == ctx.tenant_id, Identity.deleted_at.is_(None))
            ).scalars()
        )
        for r in rows:
            r.deleted_at = now
            affected += 1
    elif data_class == "imports":
        rows_i = list(
            db.execute(select(ImportJob).where(ImportJob.tenant_id == ctx.tenant_id)).scalars()
        )
        for r in rows_i:
            if r.staged_payload or r.raw_metadata:
                r.staged_payload = {}
                affected += 1
    elif data_class == "observations":
        rows_o = list(
            db.execute(select(Observation).where(Observation.tenant_id == ctx.tenant_id)).scalars()
        )
        for o in rows_o:
            if not o.raw_payload.get("purged_by_retention"):
                o.raw_payload = {"purged_by_retention": True, "purged_at": now.isoformat()}
                o.is_suppressed = True
                o.suppressed_reason = "GDPR/retention deletion request"
                affected += 1
    elif data_class == "reports":
        res = db.execute(delete(Report).where(Report.tenant_id == ctx.tenant_id))
        affected = int(res.rowcount or 0)
    elif data_class == "assessments":
        res = db.execute(delete(Assessment).where(Assessment.tenant_id == ctx.tenant_id))
        affected = int(res.rowcount or 0)

    req = RetentionRequest(
        tenant_id=ctx.tenant_id,
        request_type="deletion",
        data_class=data_class,
        status="completed",
        requested_by_user_id=ctx.user_id,
        summary={"affected_records": affected},
    )
    db.add(req)
    db.flush()
    record_audit_event(
        db,
        tenant_id=ctx.tenant_id,
        actor_user_id=ctx.user_id,
        actor_email=ctx.email,
        action="retention.delete",
        object_type="retention_request",
        object_id=str(req.id),
        outcome="success",
        request_id=ctx.request_id,
        details={"data_class": data_class, "affected_records": affected},
    )
    db.commit()
    return {
        "request_id": str(req.id),
        "data_class": data_class,
        "status": req.status,
        "affected_records": affected,
    }


def enforce_retention_policies(
    db: Session,
    ctx: ActorContext,
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    require_permission(ctx.role, Permission.RETENTION_MANAGE)
    now = datetime.now(UTC)
    policies = list(
        db.execute(select(RetentionPolicy).where(RetentionPolicy.tenant_id == ctx.tenant_id)).scalars()
    )

    counts: dict[str, int] = {}
    for pol in policies:
        cutoff = now - timedelta(days=pol.retention_days)
        dc = pol.data_class
        affected = 0

        if dc == "identities":
            rows = list(
                db.execute(
                    select(Identity).where(
                        Identity.tenant_id == ctx.tenant_id,
                        Identity.deleted_at.is_(None),
                        Identity.last_seen < cutoff,
                    )
                ).scalars()
            )
            affected = len(rows)
            if not dry_run:
                for r in rows:
                    r.deleted_at = now
        elif dc == "imports":
            rows_i = list(
                db.execute(
                    select(ImportJob).where(
                        ImportJob.tenant_id == ctx.tenant_id,
                        ImportJob.created_at < cutoff,
                    )
                ).scalars()
            )
            for r in rows_i:
                if r.staged_payload:
                    affected += 1
                    if not dry_run:
                        r.staged_payload = {}
        elif dc == "observations":
            rows_o = list(
                db.execute(
                    select(Observation).where(
                        Observation.tenant_id == ctx.tenant_id,
                        Observation.collection_time < cutoff,
                    )
                ).scalars()
            )
            for o in rows_o:
                if not o.raw_payload.get("purged_by_retention"):
                    affected += 1
                    if not dry_run:
                        o.raw_payload = {"purged_by_retention": True, "purged_at": now.isoformat()}
        elif dc == "reports":
            if dry_run:
                affected = len(
                    list(
                        db.execute(
                            select(Report.id).where(
                                Report.tenant_id == ctx.tenant_id,
                                Report.created_at < cutoff,
                            )
                        ).scalars()
                    )
                )
            else:
                res = db.execute(
                    delete(Report).where(
                        Report.tenant_id == ctx.tenant_id,
                        Report.created_at < cutoff,
                    )
                )
                affected = int(res.rowcount or 0)
        elif dc == "assessments":
            if dry_run:
                affected = len(
                    list(
                        db.execute(
                            select(Assessment.id).where(
                                Assessment.tenant_id == ctx.tenant_id,
                                Assessment.time_window_end < cutoff,
                            )
                        ).scalars()
                    )
                )
            else:
                res = db.execute(
                    delete(Assessment).where(
                        Assessment.tenant_id == ctx.tenant_id,
                        Assessment.time_window_end < cutoff,
                    )
                )
                affected = int(res.rowcount or 0)

        counts[dc] = affected

    total_affected = sum(counts.values())
    req = RetentionRequest(
        tenant_id=ctx.tenant_id,
        request_type="enforce",
        data_class="all",
        status="completed",
        requested_by_user_id=ctx.user_id,
        summary={"dry_run": dry_run, "counts_by_class": counts, "total_affected": total_affected},
    )
    db.add(req)
    db.flush()
    record_audit_event(
        db,
        tenant_id=ctx.tenant_id,
        actor_user_id=ctx.user_id,
        actor_email=ctx.email,
        action="retention.enforce",
        object_type="retention_request",
        object_id=str(req.id),
        outcome="success",
        request_id=ctx.request_id,
        details={"dry_run": dry_run, "counts_by_class": counts, "total_affected": total_affected},
    )
    db.commit()
    return {
        "request_id": str(req.id),
        "dry_run": dry_run,
        "policies_evaluated": len(policies),
        "counts_by_class": counts,
        "total_affected": total_affected,
    }
