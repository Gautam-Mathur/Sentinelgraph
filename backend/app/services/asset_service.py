import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import asc, desc, func, or_, select
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, NotFoundError, ValidationAppError
from app.core.permissions import Permission, require_permission
from app.db.models import Asset, AssetAddress, Finding, Service
from app.domain.models import AssetType, CriticalityLevel, EnvironmentType, LifecycleState
from app.services.audit_service import record_audit_event
from app.services.context import ActorContext

ASSET_SORT_ALLOWLIST = {
    "display_name": Asset.display_name,
    "criticality": Asset.criticality,
    "asset_type": Asset.asset_type,
    "environment": Asset.environment,
    "last_seen": Asset.last_seen,
    "created_at": Asset.created_at,
}


def list_assets(
    db: Session,
    ctx: ActorContext,
    *,
    asset_type: str | None = None,
    environment: str | None = None,
    criticality: str | None = None,
    search: str | None = None,
    is_external_entry: bool | None = None,
    is_crown_jewel: bool | None = None,
    sort_by: str = "created_at",
    sort_dir: str = "desc",
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    require_permission(ctx.role, Permission.ASSET_READ)
    if sort_by not in ASSET_SORT_ALLOWLIST:
        raise ValidationAppError(
            code="INVALID_SORT_FIELD",
            message=f"Sort field '{sort_by}' is not allowlisted.",
        )

    stmt = select(Asset).where(Asset.tenant_id == ctx.tenant_id, Asset.deleted_at.is_(None))
    if asset_type:
        stmt = stmt.where(Asset.asset_type == asset_type)
    if environment:
        stmt = stmt.where(Asset.environment == environment)
    if criticality:
        stmt = stmt.where(Asset.criticality == criticality)
    if is_external_entry is not None:
        stmt = stmt.where(Asset.is_external_entry == is_external_entry)
    if is_crown_jewel is not None:
        stmt = stmt.where(Asset.is_crown_jewel == is_crown_jewel)
    if search:
        pat = f"%{search.strip()}%"
        addr_subq = select(AssetAddress.asset_id).where(
            AssetAddress.tenant_id == ctx.tenant_id,
            AssetAddress.value.ilike(pat),
        )
        stmt = stmt.where(
            or_(
                Asset.display_name.ilike(pat),
                Asset.canonical_key.ilike(pat),
                Asset.owner.ilike(pat),
                Asset.id.in_(addr_subq),
            )
        )

    total = int(db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one())
    order_col = ASSET_SORT_ALLOWLIST[sort_by]
    order_expr = asc(order_col) if sort_dir == "asc" else desc(order_col)
    rows = list(db.execute(stmt.order_by(order_expr).offset(offset).limit(limit)).scalars())

    # Fetch addresses & services counts for returned assets
    items: list[dict[str, Any]] = []
    for asset in rows:
        svcs = list(
            db.execute(
                select(Service).where(Service.tenant_id == ctx.tenant_id, Service.asset_id == asset.id)
            ).scalars()
        )
        findings = list(
            db.execute(
                select(Finding).where(
                    Finding.tenant_id == ctx.tenant_id,
                    Finding.asset_id == asset.id,
                    Finding.status == "open",
                )
            ).scalars()
        )
        items.append(_serialize_asset(asset, svcs, findings))
    return items, total


def _serialize_asset(
    asset: Asset,
    services: list[Service],
    findings: list[Finding],
) -> dict[str, Any]:
    return {
        "id": str(asset.id),
        "tenant_id": str(asset.tenant_id),
        "canonical_key": asset.canonical_key,
        "display_name": asset.display_name,
        "asset_type": asset.asset_type,
        "environment": asset.environment,
        "criticality": asset.criticality,
        "owner": asset.owner,
        "business_unit": asset.business_unit,
        "lifecycle_state": asset.lifecycle_state,
        "first_seen": asset.first_seen.isoformat(),
        "last_seen": asset.last_seen.isoformat(),
        "confidence": asset.confidence,
        "is_external_entry": asset.is_external_entry,
        "is_crown_jewel": asset.is_crown_jewel,
        "raw_attributes": asset.raw_attributes,
        "source_refs": asset.source_refs,
        "addresses": [
            {
                "id": str(a.id),
                "address_type": a.address_type,
                "value": a.value,
                "is_primary": a.is_primary,
            }
            for a in asset.addresses
        ],
        "services": [
            {
                "id": str(s.id),
                "port": s.port,
                "protocol": s.protocol,
                "state": s.state,
                "service_name": s.service_name,
                "product": s.analyst_corrected_product or s.product,
                "version": s.analyst_corrected_version or s.version,
                "banner_raw": s.banner_raw,
                "analyst_corrected_product": s.analyst_corrected_product,
                "analyst_corrected_version": s.analyst_corrected_version,
                "confidence": s.confidence,
                "provenance": s.provenance,
            }
            for s in services
        ],
        "open_findings": [
            {
                "id": str(f.id),
                "cve_id": f.cve_id,
                "severity": f.severity,
                "cvss_score": f.cvss_score,
                "affected_component": f.affected_component,
                "status": f.status,
                "exploitability_proven": bool(f.evidence.get("exploitability_proven", False)),
            }
            for f in findings
        ],
    }


def get_asset_detail(db: Session, ctx: ActorContext, asset_id: uuid.UUID) -> dict[str, Any]:
    require_permission(ctx.role, Permission.ASSET_READ)
    asset = db.execute(
        select(Asset).where(
            Asset.id == asset_id,
            Asset.tenant_id == ctx.tenant_id,
            Asset.deleted_at.is_(None),
        )
    ).scalar_one_or_none()
    if asset is None:
        raise NotFoundError(code="ASSET_NOT_FOUND", message="Asset not found")

    svcs = list(
        db.execute(
            select(Service).where(Service.tenant_id == ctx.tenant_id, Service.asset_id == asset.id)
        ).scalars()
    )
    findings = list(
        db.execute(
            select(Finding).where(Finding.tenant_id == ctx.tenant_id, Finding.asset_id == asset.id)
        ).scalars()
    )
    return _serialize_asset(asset, svcs, findings)


def create_asset(
    db: Session,
    ctx: ActorContext,
    *,
    canonical_key: str,
    display_name: str,
    asset_type: str,
    environment: str,
    criticality: str,
    owner: str,
    business_unit: str,
    lifecycle_state: str,
    confidence: float,
    is_external_entry: bool,
    is_crown_jewel: bool,
    addresses: list[dict[str, Any]],
) -> dict[str, Any]:
    require_permission(ctx.role, Permission.ASSET_WRITE)
    # Enum validations
    AssetType(asset_type)
    EnvironmentType(environment)
    CriticalityLevel(criticality)
    LifecycleState(lifecycle_state)

    existing = db.execute(
        select(Asset).where(
            Asset.tenant_id == ctx.tenant_id,
            Asset.canonical_key == canonical_key.strip().lower(),
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise ConflictError(code="ASSET_EXISTS", message="Asset canonical_key already exists")

    now = datetime.now(UTC)
    asset = Asset(
        tenant_id=ctx.tenant_id,
        canonical_key=canonical_key.strip().lower(),
        display_name=display_name.strip(),
        asset_type=asset_type,
        environment=environment,
        criticality=criticality,
        owner=owner.strip(),
        business_unit=business_unit.strip(),
        lifecycle_state=lifecycle_state,
        first_seen=now,
        last_seen=now,
        confidence=confidence,
        is_external_entry=is_external_entry,
        is_crown_jewel=is_crown_jewel,
        raw_attributes={"created_via": "api"},
        source_refs=[
            {
                "source_product": "manual_analyst_entry",
                "source_record_id": canonical_key,
                "collection_time": now.isoformat(),
                "parser_version": "api_v1",
                "confidence": confidence,
            }
        ],
    )
    db.add(asset)
    db.flush()

    for addr in addresses:
        db.add(
            AssetAddress(
                tenant_id=ctx.tenant_id,
                asset_id=asset.id,
                address_type=addr["address_type"],
                value=addr["value"].strip(),
                is_primary=bool(addr.get("is_primary", False)),
                first_seen=now,
                last_seen=now,
                provenance={"source_product": "manual_analyst_entry"},
            )
        )
    db.flush()

    record_audit_event(
        db,
        tenant_id=ctx.tenant_id,
        actor_user_id=ctx.user_id,
        actor_email=ctx.email,
        action="asset.create",
        object_type="asset",
        object_id=str(asset.id),
        outcome="success",
        request_id=ctx.request_id,
        details={"canonical_key": asset.canonical_key, "criticality": asset.criticality},
    )
    db.commit()
    db.refresh(asset)
    return _serialize_asset(asset, [], [])


def update_asset(
    db: Session,
    ctx: ActorContext,
    *,
    asset_id: uuid.UUID,
    display_name: str | None = None,
    asset_type: str | None = None,
    environment: str | None = None,
    criticality: str | None = None,
    owner: str | None = None,
    business_unit: str | None = None,
    lifecycle_state: str | None = None,
    is_external_entry: bool | None = None,
    is_crown_jewel: bool | None = None,
    retire: bool = False,
) -> dict[str, Any]:
    require_permission(ctx.role, Permission.ASSET_WRITE)
    asset = db.execute(
        select(Asset).where(
            Asset.id == asset_id,
            Asset.tenant_id == ctx.tenant_id,
            Asset.deleted_at.is_(None),
        )
    ).scalar_one_or_none()
    if asset is None:
        raise NotFoundError(code="ASSET_NOT_FOUND", message="Asset not found")

    if asset_type is not None:
        try:
            AssetType(asset_type)
        except ValueError as exc:
            raise ValidationAppError(code="INVALID_ASSET_TYPE", message=f"Unsupported asset_type '{asset_type}'.") from exc
        asset.asset_type = asset_type
    if environment is not None:
        try:
            EnvironmentType(environment)
        except ValueError as exc:
            raise ValidationAppError(code="INVALID_ENVIRONMENT", message=f"Unsupported environment '{environment}'.") from exc
        asset.environment = environment
    if criticality is not None:
        try:
            CriticalityLevel(criticality)
        except ValueError as exc:
            raise ValidationAppError(code="INVALID_CRITICALITY", message=f"Unsupported criticality '{criticality}'.") from exc
        asset.criticality = criticality
    if lifecycle_state is not None:
        try:
            LifecycleState(lifecycle_state)
        except ValueError as exc:
            raise ValidationAppError(code="INVALID_LIFECYCLE_STATE", message=f"Unsupported lifecycle_state '{lifecycle_state}'.") from exc
        asset.lifecycle_state = lifecycle_state

    if display_name is not None:
        asset.display_name = display_name.strip()[:255]
    if owner is not None:
        asset.owner = owner.strip()[:200]
    if business_unit is not None:
        asset.business_unit = business_unit.strip()[:200]
    if is_external_entry is not None:
        asset.is_external_entry = is_external_entry
    if is_crown_jewel is not None:
        asset.is_crown_jewel = is_crown_jewel
    if retire:
        asset.lifecycle_state = LifecycleState.DECOMMISSIONED.value
        asset.deleted_at = datetime.now(UTC)

    db.flush()
    record_audit_event(
        db,
        tenant_id=ctx.tenant_id,
        actor_user_id=ctx.user_id,
        actor_email=ctx.email,
        action="asset.retire" if retire else "asset.update",
        object_type="asset",
        object_id=str(asset.id),
        outcome="success",
        request_id=ctx.request_id,
        details={
            "criticality": asset.criticality,
            "environment": asset.environment,
            "is_external_entry": asset.is_external_entry,
            "is_crown_jewel": asset.is_crown_jewel,
            "retired": retire,
        },
    )
    db.commit()
    svcs = list(
        db.execute(
            select(Service).where(Service.tenant_id == ctx.tenant_id, Service.asset_id == asset.id)
        ).scalars()
    )
    findings = list(
        db.execute(
            select(Finding).where(Finding.tenant_id == ctx.tenant_id, Finding.asset_id == asset.id)
        ).scalars()
    )
    payload = _serialize_asset(asset, svcs, findings)
    payload["retired"] = bool(asset.deleted_at is not None)
    return payload


def correct_service_banner(
    db: Session,
    ctx: ActorContext,
    *,
    service_id: uuid.UUID,
    corrected_product: str | None,
    corrected_version: str | None,
    confidence: float,
) -> dict[str, Any]:
    require_permission(ctx.role, Permission.ASSET_WRITE)
    svc = db.execute(
        select(Service).where(Service.id == service_id, Service.tenant_id == ctx.tenant_id)
    ).scalar_one_or_none()
    if svc is None:
        raise NotFoundError(code="SERVICE_NOT_FOUND", message="Service not found")

    svc.analyst_corrected_product = corrected_product
    svc.analyst_corrected_version = corrected_version
    svc.confidence = confidence
    db.flush()

    record_audit_event(
        db,
        tenant_id=ctx.tenant_id,
        actor_user_id=ctx.user_id,
        actor_email=ctx.email,
        action="service.correct_banner",
        object_type="service",
        object_id=str(svc.id),
        outcome="success",
        request_id=ctx.request_id,
        details={
            "port": svc.port,
            "protocol": svc.protocol,
            "corrected_product": corrected_product,
            "corrected_version": corrected_version,
        },
    )
    db.commit()
    return {
        "id": str(svc.id),
        "port": svc.port,
        "protocol": svc.protocol,
        "banner_raw": svc.banner_raw,
        "analyst_corrected_product": svc.analyst_corrected_product,
        "analyst_corrected_version": svc.analyst_corrected_version,
        "confidence": svc.confidence,
    }
