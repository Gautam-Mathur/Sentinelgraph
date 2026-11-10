import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session

from app.core.errors import NotFoundError, ValidationAppError
from app.core.permissions import Permission, require_permission
from app.db.models import Asset, Finding
from app.services.audit_service import record_audit_event
from app.services.context import ActorContext

VALID_FINDING_STATUSES = frozenset({"open", "mitigated", "accepted_risk", "false_positive"})


def _serialize_finding(finding: Finding, asset: Asset | None) -> dict[str, Any]:
    return {
        "id": str(finding.id),
        "tenant_id": str(finding.tenant_id),
        "assessment_id": str(finding.assessment_id),
        "asset_id": str(finding.asset_id),
        "asset_display_name": asset.display_name if asset else str(finding.asset_id),
        "asset_canonical_key": asset.canonical_key if asset else None,
        "cve_id": finding.cve_id,
        "cvss_version": finding.cvss_version,
        "cvss_vector": finding.cvss_vector,
        "cvss_score": finding.cvss_score,
        "severity": finding.severity,
        "affected_component": finding.affected_component,
        "status": finding.status,
        "scanner_name": finding.scanner_name,
        "scanner_context": finding.scanner_context,
        "evidence": finding.evidence,
        "exploitability_proven": bool((finding.evidence or {}).get("exploitability_proven", False)),
        "observed_at": finding.observed_at.isoformat(),
        "confidence": finding.confidence,
        "provenance": finding.provenance,
        "triage_note": finding.triage_note,
        "triaged_by_user_id": str(finding.triaged_by_user_id) if finding.triaged_by_user_id else None,
        "triaged_at": finding.triaged_at.isoformat() if finding.triaged_at else None,
    }


def list_findings(
    db: Session,
    ctx: ActorContext,
    *,
    assessment_id: uuid.UUID | None = None,
    asset_id: uuid.UUID | None = None,
    severity: str | None = None,
    status: str | None = None,
    cve_id: str | None = None,
    search: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    require_permission(ctx.role, Permission.ASSET_READ)
    stmt = (
        select(Finding)
        .join(Asset, Asset.id == Finding.asset_id)
        .where(
            Finding.tenant_id == ctx.tenant_id,
            Asset.tenant_id == ctx.tenant_id,
            Asset.deleted_at.is_(None),
        )
    )
    if assessment_id is not None:
        stmt = stmt.where(Finding.assessment_id == assessment_id)
    if asset_id is not None:
        stmt = stmt.where(Finding.asset_id == asset_id)
    if severity:
        stmt = stmt.where(Finding.severity == severity.strip().lower())
    if status:
        stmt = stmt.where(Finding.status == status.strip().lower())
    if cve_id:
        stmt = stmt.where(Finding.cve_id.ilike(f"%{cve_id.strip()}%"))
    if search:
        pat = f"%{search.strip()}%"
        stmt = stmt.where(
            or_(
                Finding.cve_id.ilike(pat),
                Finding.affected_component.ilike(pat),
                Finding.scanner_name.ilike(pat),
                Finding.scanner_context.ilike(pat),
                Asset.display_name.ilike(pat),
                Asset.canonical_key.ilike(pat),
            )
        )

    total = int(db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one())
    rows = list(
        db.execute(
            stmt.order_by(desc(Finding.cvss_score), desc(Finding.observed_at))
            .offset(offset)
            .limit(limit)
        ).scalars()
    )

    asset_ids = {f.asset_id for f in rows}
    assets_map: dict[uuid.UUID, Asset] = {}
    if asset_ids:
        for a in db.execute(
            select(Asset).where(Asset.tenant_id == ctx.tenant_id, Asset.id.in_(asset_ids))
        ).scalars():
            assets_map[a.id] = a

    return [_serialize_finding(f, assets_map.get(f.asset_id)) for f in rows], total


def triage_finding(
    db: Session,
    ctx: ActorContext,
    *,
    finding_id: uuid.UUID,
    status: str | None = None,
    triage_note: str | None = None,
) -> dict[str, Any]:
    require_permission(ctx.role, Permission.ASSET_WRITE)
    if status is None and triage_note is None:
        raise ValidationAppError(
            code="NO_UPDATE_FIELDS",
            message="Provide status and/or triage_note to update finding.",
        )

    finding = db.execute(
        select(Finding).where(Finding.id == finding_id, Finding.tenant_id == ctx.tenant_id)
    ).scalar_one_or_none()
    if finding is None:
        raise NotFoundError(code="FINDING_NOT_FOUND", message="Finding not found")

    old_status = finding.status
    if status is not None:
        clean_status = status.strip().lower()
        if clean_status not in VALID_FINDING_STATUSES:
            raise ValidationAppError(
                code="INVALID_FINDING_STATUS",
                message=f"Status must be one of {', '.join(sorted(VALID_FINDING_STATUSES))}.",
            )
        finding.status = clean_status

    if triage_note is not None:
        finding.triage_note = triage_note.strip()[:2000]

    finding.triaged_by_user_id = ctx.user_id
    finding.triaged_at = datetime.now(UTC)
    db.flush()

    asset = db.execute(
        select(Asset).where(Asset.id == finding.asset_id, Asset.tenant_id == ctx.tenant_id)
    ).scalar_one_or_none()

    record_audit_event(
        db,
        tenant_id=ctx.tenant_id,
        actor_user_id=ctx.user_id,
        actor_email=ctx.email,
        action="finding.triage",
        object_type="finding",
        object_id=str(finding.id),
        outcome="success",
        request_id=ctx.request_id,
        details={
            "cve_id": finding.cve_id,
            "old_status": old_status,
            "new_status": finding.status,
            "has_note": bool(finding.triage_note),
        },
    )
    db.commit()
    return _serialize_finding(finding, asset)
