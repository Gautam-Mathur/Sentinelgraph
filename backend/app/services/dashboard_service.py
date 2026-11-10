from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.permissions import Permission, require_permission
from app.db.models import (
    Assessment,
    Asset,
    AssetAddress,
    AttackPath,
    Identity,
    ImportJob,
    Observation,
    Service,
)
from app.services.context import ActorContext


def get_dashboard_kpis(db: Session, ctx: ActorContext) -> dict[str, Any]:
    require_permission(ctx.role, Permission.ASSET_READ)
    stale_cutoff = datetime.now(UTC) - timedelta(days=30)

    assets_observed = int(
        db.execute(
            select(func.count()).select_from(Asset).where(
                Asset.tenant_id == ctx.tenant_id,
                Asset.deleted_at.is_(None),
            )
        ).scalar_one()
    )
    critical_assets = int(
        db.execute(
            select(func.count()).select_from(Asset).where(
                Asset.tenant_id == ctx.tenant_id,
                Asset.deleted_at.is_(None),
                or_(Asset.criticality == "critical", Asset.is_crown_jewel.is_(True)),
            )
        ).scalar_one()
    )
    exposed_services = int(
        db.execute(
            select(func.count()).select_from(Service).where(
                Service.tenant_id == ctx.tenant_id,
                Service.state == "open",
            )
        ).scalar_one()
    )
    high_confidence_paths = int(
        db.execute(
            select(func.count()).select_from(AttackPath).where(
                AttackPath.tenant_id == ctx.tenant_id,
                AttackPath.evidence_confidence >= 0.7,
            )
        ).scalar_one()
    )
    critical_asset_ids = list(
        db.execute(
            select(Asset.id).where(
                Asset.tenant_id == ctx.tenant_id,
                Asset.deleted_at.is_(None),
                or_(Asset.criticality == "critical", Asset.is_crown_jewel.is_(True)),
            )
        ).scalars()
    )
    paths_to_critical_assets = 0
    if critical_asset_ids:
        paths_to_critical_assets = int(
            db.execute(
                select(func.count()).select_from(AttackPath).where(
                    AttackPath.tenant_id == ctx.tenant_id,
                    AttackPath.target_node_kind == "asset",
                    AttackPath.target_node_id.in_(critical_asset_ids),
                )
            ).scalar_one()
        )
    stale_observations = int(
        db.execute(
            select(func.count()).select_from(Observation).where(
                Observation.tenant_id == ctx.tenant_id,
                Observation.collection_time < stale_cutoff,
                Observation.is_suppressed.is_(False),
            )
        ).scalar_one()
    )
    unreviewed_imports = int(
        db.execute(
            select(func.count()).select_from(ImportJob).where(
                ImportJob.tenant_id == ctx.tenant_id,
                ImportJob.status.in_(["uploaded", "preview_ready"]),
            )
        ).scalar_one()
    )

    committed_formats = list(
        db.execute(
            select(ImportJob.source_format, func.max(ImportJob.committed_at))
            .where(ImportJob.tenant_id == ctx.tenant_id, ImportJob.status == "committed")
            .group_by(ImportJob.source_format)
        ).all()
    )
    latest_obs_time = db.execute(
        select(func.max(Observation.collection_time)).where(Observation.tenant_id == ctx.tenant_id)
    ).scalar_one()
    assessments_count = int(
        db.execute(
            select(func.count()).select_from(Assessment).where(Assessment.tenant_id == ctx.tenant_id)
        ).scalar_one()
    )

    present_formats = {row[0] for row in committed_formats}
    expected_mvp_sources = {"nmap_xml", "network_topology_json", "identity_json", "vulnerability_json"}
    missing_sources = sorted(expected_mvp_sources - present_formats)

    return {
        "kpis": {
            "assets_observed": assets_observed,
            "critical_assets": critical_assets,
            "exposed_services": exposed_services,
            "high_confidence_paths": high_confidence_paths,
            "paths_to_critical_assets": paths_to_critical_assets,
            "stale_observations": stale_observations,
            "unreviewed_imports": unreviewed_imports,
        },
        "freshness_and_coverage": {
            "latest_observation_at": latest_obs_time.isoformat() if latest_obs_time else None,
            "assessments_count": assessments_count,
            "observed_source_formats": [
                {
                    "source_format": row[0],
                    "last_committed_at": row[1].isoformat() if row[1] else None,
                }
                for row in committed_formats
            ],
            "missing_recommended_sources": missing_sources,
            "coverage_status": "partial" if missing_sources else "multi_source",
            "completeness_notice": (
                "Inventory reflects authorised ingested sources only; partial source coverage may omit hidden paths."
            ),
        },
    }


def global_tenant_search(
    db: Session,
    ctx: ActorContext,
    *,
    query: str,
    limit: int = 25,
) -> dict[str, Any]:
    require_permission(ctx.role, Permission.ASSET_READ)
    q = query.strip()
    if not q:
        return {"query": q, "assets": [], "identities": [], "paths": []}

    pat = f"%{q}%"
    addr_asset_ids = select(AssetAddress.asset_id).where(
        AssetAddress.tenant_id == ctx.tenant_id,
        AssetAddress.value.ilike(pat),
    )
    assets = list(
        db.execute(
            select(Asset)
            .where(
                Asset.tenant_id == ctx.tenant_id,
                Asset.deleted_at.is_(None),
                or_(
                    Asset.display_name.ilike(pat),
                    Asset.canonical_key.ilike(pat),
                    Asset.id.in_(addr_asset_ids),
                ),
            )
            .limit(limit)
        ).scalars()
    )
    identities = list(
        db.execute(
            select(Identity)
            .where(
                Identity.tenant_id == ctx.tenant_id,
                Identity.deleted_at.is_(None),
                or_(
                    Identity.display_name.ilike(pat),
                    Identity.principal_name.ilike(pat),
                    Identity.external_id.ilike(pat),
                ),
            )
            .limit(limit)
        ).scalars()
    )
    paths = list(
        db.execute(
            select(AttackPath)
            .where(
                AttackPath.tenant_id == ctx.tenant_id,
                or_(
                    AttackPath.title.ilike(pat),
                    AttackPath.start_node_label.ilike(pat),
                    AttackPath.target_node_label.ilike(pat),
                ),
            )
            .limit(limit)
        ).scalars()
    )
    return {
        "query": q,
        "assets": [
            {
                "id": str(a.id),
                "display_name": a.display_name,
                "canonical_key": a.canonical_key,
                "asset_type": a.asset_type,
                "criticality": a.criticality,
            }
            for a in assets
        ],
        "identities": [
            {
                "id": str(i.id),
                "display_name": i.display_name,
                "principal_name": i.principal_name,
                "external_id": i.external_id,
                "privilege_level": i.privilege_level,
            }
            for i in identities
        ],
        "paths": [
            {
                "id": str(p.id),
                "title": p.title,
                "priority_score": p.priority_score,
                "assessment_id": str(p.assessment_id),
            }
            for p in paths
        ],
    }
