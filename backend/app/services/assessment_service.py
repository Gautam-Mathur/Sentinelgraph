import ipaddress
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.core.errors import NotFoundError, ValidationAppError
from app.core.permissions import Permission, require_permission
from app.core.telemetry import metrics
from app.db.models import (
    Assessment,
    Asset,
    AttackPath,
    Finding,
    Group,
    Identity,
    Relationship,
    Service,
)
from app.domain.graph_engine import build_networkx_graph
from app.domain.graph_intelligence import analyze_assessment_intelligence
from app.domain.models import (
    AlgorithmType,
    FactKind,
    GraphEdge,
    GraphNode,
    NodeKind,
    PathSearchConstraints,
    RelationType,
)
from app.services.audit_service import record_audit_event
from app.services.context import ActorContext


def _validate_scope_entries(entries: list[str]) -> list[str]:
    if not entries:
        raise ValidationAppError(
            code="SCOPE_REQUIRED",
            message="At least one approved CIDR or domain scope entry is required.",
        )
    normalized: list[str] = []
    for raw in entries:
        item = raw.strip().lower()
        if not item:
            continue
        try:
            normalized.append(str(ipaddress.ip_network(item, strict=False)))
        except ValueError:
            if "." not in item or " " in item or "/" in item:
                raise ValidationAppError(
                    code="INVALID_SCOPE_ENTRY",
                    message=f"Invalid scope entry '{raw}': must be valid CIDR or domain.",
                ) from None
            normalized.append(item)
    return normalized


def create_assessment(
    db: Session,
    ctx: ActorContext,
    *,
    name: str,
    description: str,
    approved_scope_cidrs: list[str],
    time_window_start: datetime,
    time_window_end: datetime,
    is_synthetic: bool,
) -> dict[str, Any]:
    require_permission(ctx.role, Permission.ASSESSMENT_CREATE)
    if time_window_end <= time_window_start:
        raise ValidationAppError(
            code="INVALID_TIME_WINDOW",
            message="time_window_end must be after time_window_start",
        )
    norm_scope = _validate_scope_entries(approved_scope_cidrs)

    assessment = Assessment(
        tenant_id=ctx.tenant_id,
        name=name.strip(),
        description=description.strip(),
        status="draft",
        approved_scope_cidrs=norm_scope,
        time_window_start=time_window_start,
        time_window_end=time_window_end,
        operator_user_id=ctx.user_id,
        is_synthetic=is_synthetic or ctx.tenant_is_demo,
    )
    db.add(assessment)
    db.flush()

    record_audit_event(
        db,
        tenant_id=ctx.tenant_id,
        actor_user_id=ctx.user_id,
        actor_email=ctx.email,
        action="assessment.create",
        object_type="assessment",
        object_id=str(assessment.id),
        outcome="success",
        request_id=ctx.request_id,
        details={"scope": norm_scope, "is_synthetic": assessment.is_synthetic},
    )
    db.commit()
    return _serialize_assessment(assessment)


def approve_assessment_scope(
    db: Session,
    ctx: ActorContext,
    *,
    assessment_id: uuid.UUID,
) -> dict[str, Any]:
    require_permission(ctx.role, Permission.ASSESSMENT_APPROVE_SCOPE)
    assessment = db.execute(
        select(Assessment).where(
            Assessment.id == assessment_id, Assessment.tenant_id == ctx.tenant_id
        )
    ).scalar_one_or_none()
    if assessment is None:
        raise NotFoundError(code="ASSESSMENT_NOT_FOUND", message="Assessment not found")

    if assessment.status == "draft":
        assessment.status = "scope_approved"
    assessment.approved_by_user_id = ctx.user_id
    assessment.approved_at = datetime.now(UTC)
    db.flush()

    record_audit_event(
        db,
        tenant_id=ctx.tenant_id,
        actor_user_id=ctx.user_id,
        actor_email=ctx.email,
        action="assessment.scope_approve",
        object_type="assessment",
        object_id=str(assessment.id),
        outcome="success",
        request_id=ctx.request_id,
        details={"approved_scope_cidrs": assessment.approved_scope_cidrs},
    )
    db.commit()
    return _serialize_assessment(assessment)


def list_assessments(db: Session, ctx: ActorContext) -> list[dict[str, Any]]:
    require_permission(ctx.role, Permission.ASSESSMENT_READ)
    rows = list(
        db.execute(
            select(Assessment)
            .where(Assessment.tenant_id == ctx.tenant_id)
            .order_by(desc(Assessment.created_at))
        ).scalars()
    )
    return [_serialize_assessment(a) for a in rows]


def get_assessment(db: Session, ctx: ActorContext, assessment_id: uuid.UUID) -> dict[str, Any]:
    require_permission(ctx.role, Permission.ASSESSMENT_READ)
    a = db.execute(
        select(Assessment).where(Assessment.id == assessment_id, Assessment.tenant_id == ctx.tenant_id)
    ).scalar_one_or_none()
    if a is None:
        raise NotFoundError(code="ASSESSMENT_NOT_FOUND", message="Assessment not found")
    return _serialize_assessment(a)


def load_domain_graph_inputs(
    db: Session,
    *,
    tenant_id: uuid.UUID,
    assessment_id: uuid.UUID,
) -> tuple[list[GraphNode], list[GraphEdge]]:
    stale_cutoff = datetime.now(UTC) - timedelta(days=30)
    assets = list(
        db.execute(
            select(Asset).where(Asset.tenant_id == tenant_id, Asset.deleted_at.is_(None))
        ).scalars()
    )
    identities = list(
        db.execute(
            select(Identity).where(Identity.tenant_id == tenant_id, Identity.deleted_at.is_(None))
        ).scalars()
    )
    groups = list(db.execute(select(Group).where(Group.tenant_id == tenant_id)).scalars())
    services = list(
        db.execute(
            select(Service).where(Service.tenant_id == tenant_id, Service.assessment_id == assessment_id)
        ).scalars()
    )
    findings = list(
        db.execute(
            select(Finding).where(
                Finding.tenant_id == tenant_id,
                Finding.assessment_id == assessment_id,
                Finding.status == "open",
            )
        ).scalars()
    )
    relationships = list(
        db.execute(
            select(Relationship).where(
                Relationship.tenant_id == tenant_id,
                (Relationship.assessment_id == assessment_id) | (Relationship.assessment_id.is_(None)),
            )
        ).scalars()
    )

    cves_by_asset: dict[uuid.UUID, list[Finding]] = {}
    for f in findings:
        cves_by_asset.setdefault(f.asset_id, []).append(f)

    nodes: list[GraphNode] = []
    for a in assets:
        asset_findings = cves_by_asset.get(a.id, [])
        max_cvss = max((float(f.cvss_score or 0.0) for f in asset_findings), default=0.0)
        nodes.append(
            GraphNode(
                node_kind=NodeKind.ASSET,
                node_id=str(a.id),
                label=a.display_name,
                criticality=a.criticality,
                environment=a.environment,
                is_external_entry=a.is_external_entry,
                is_crown_jewel=a.is_crown_jewel,
                stale_observation=a.last_seen < stale_cutoff,
                open_cve_count=len(asset_findings),
                max_cvss=max_cvss,
                metadata={
                    "asset_type": a.asset_type,
                    "canonical_key": a.canonical_key,
                    "owner": a.owner,
                    # Preserve CVE identity in the graph; a count alone cannot support
                    # a CVE-specific remediation simulation.
                    "vulnerability_status": {
                        str(f.cve_id).upper(): "open"
                        for f in asset_findings
                        if f.cve_id
                    },
                },
            )
        )

    for i in identities:
        nodes.append(
            GraphNode(
                node_kind=NodeKind.IDENTITY,
                node_id=str(i.id),
                label=i.display_name,
                criticality="high" if i.privilege_level in ("privileged", "domain_admin") else "medium",
                privilege_level=i.privilege_level,
                stale_observation=i.last_seen < stale_cutoff,
                metadata={
                    "identity_type": i.identity_type,
                    "principal_name": i.principal_name,
                    "provider": i.provider,
                    "enabled": i.enabled,
                    "auth_metadata": i.auth_metadata,
                    "privilege_indicators": i.privilege_indicators,
                },
            )
        )

    for g in groups:
        is_priv = any("admin" in ind.lower() for ind in g.privilege_indicators) or "admin" in g.display_name.lower()
        nodes.append(
            GraphNode(
                node_kind=NodeKind.GROUP,
                node_id=str(g.id),
                label=g.display_name,
                criticality="critical" if "domain admin" in g.display_name.lower() else ("high" if is_priv else "medium"),
                privilege_level="domain_admin" if "domain admin" in g.display_name.lower() else ("privileged" if is_priv else "standard"),
                stale_observation=g.last_seen < stale_cutoff,
                metadata={"group_type": g.group_type, "provider": g.provider},
            )
        )

    for s in services:
        nodes.append(
            GraphNode(
                node_kind=NodeKind.SERVICE,
                node_id=str(s.id),
                label=f"{s.service_name}:{s.port}/{s.protocol}",
                criticality="medium",
                metadata={
                    "port": s.port,
                    "protocol": s.protocol,
                    "product": s.analyst_corrected_product or s.product,
                    "version": s.analyst_corrected_version or s.version,
                },
            )
        )

    edges: list[GraphEdge] = []
    for r in relationships:
        edges.append(
            GraphEdge(
                edge_id=str(r.id),
                source_kind=NodeKind(r.source_kind),
                source_id=str(r.source_id),
                target_kind=NodeKind(r.target_kind),
                target_id=str(r.target_id),
                relation_type=RelationType(r.relation_type),
                fact_kind=FactKind(r.fact_kind),
                confidence=r.confidence,
                valid_from=r.valid_from,
                valid_to=r.valid_to,
                provenance=r.provenance,
                edge_metadata=r.edge_metadata,
                is_suppressed=r.is_suppressed,
            )
        )
    return nodes, edges


def build_assessment_graph(
    db: Session,
    ctx: ActorContext,
    *,
    assessment_id: uuid.UUID,
) -> dict[str, Any]:
    require_permission(ctx.role, Permission.GRAPH_BUILD)
    assessment = db.execute(
        select(Assessment).where(
            Assessment.id == assessment_id, Assessment.tenant_id == ctx.tenant_id
        )
    ).scalar_one_or_none()
    if assessment is None:
        raise NotFoundError(code="ASSESSMENT_NOT_FOUND", message="Assessment not found")
    if assessment.status == "draft":
        raise ValidationAppError(
            code="SCOPE_NOT_APPROVED",
            message="Assessment scope must be approved before building the attack-path graph.",
        )

    nodes, edges = load_domain_graph_inputs(db, tenant_id=ctx.tenant_id, assessment_id=assessment.id)
    nx_graph, stats = build_networkx_graph(nodes, edges)

    metrics.set_gauge("last_graph_nodes", float(stats.node_count))
    metrics.set_gauge("last_graph_edges", float(stats.edge_count))
    metrics.observe_ms("graph_build_ms", stats.build_duration_ms)

    assessment.graph_version += 1
    assessment.graph_built_at = datetime.now(UTC)
    assessment.status = "graph_built"
    assessment.graph_stats = {
        "node_count": stats.node_count,
        "edge_count": stats.edge_count,
        "suppressed_edge_count": stats.suppressed_edge_count,
        "expired_edge_count": stats.expired_edge_count,
        "scc_cycle_count": stats.scc_cycle_count,
        "scc_cycles": stats.scc_cycles,
        "top_bridge_nodes": stats.top_bridge_nodes,
        "top_bridge_edges": stats.top_bridge_edges,
        "build_duration_ms": stats.build_duration_ms,
    }
    db.flush()

    record_audit_event(
        db,
        tenant_id=ctx.tenant_id,
        actor_user_id=ctx.user_id,
        actor_email=ctx.email,
        action="graph.build",
        object_type="assessment",
        object_id=str(assessment.id),
        outcome="success",
        request_id=ctx.request_id,
        details={"graph_version": assessment.graph_version, "nodes": stats.node_count, "edges": stats.edge_count},
    )
    db.commit()

    return get_assessment_graph_payload(db, ctx, assessment_id=assessment.id)


def get_assessment_graph_payload(
    db: Session,
    ctx: ActorContext,
    *,
    assessment_id: uuid.UUID,
) -> dict[str, Any]:
    require_permission(ctx.role, Permission.ASSESSMENT_READ)
    assessment = db.execute(
        select(Assessment).where(
            Assessment.id == assessment_id, Assessment.tenant_id == ctx.tenant_id
        )
    ).scalar_one_or_none()
    if assessment is None:
        raise NotFoundError(code="ASSESSMENT_NOT_FOUND", message="Assessment not found")

    nodes, edges = load_domain_graph_inputs(db, tenant_id=ctx.tenant_id, assessment_id=assessment.id)
    nx_graph, stats = build_networkx_graph(nodes, edges)

    cy_nodes = []
    for _, data in nx_graph.nodes(data=True):
        n: GraphNode = data["node"]
        cy_nodes.append(
            {
                "key": n.key,
                "node_kind": n.node_kind.value,
                "node_id": n.node_id,
                "label": n.label,
                "criticality": n.criticality,
                "environment": n.environment,
                "is_external_entry": n.is_external_entry,
                "is_crown_jewel": n.is_crown_jewel,
                "privilege_level": n.privilege_level,
                "open_cve_count": n.open_cve_count,
                "metadata": n.metadata,
            }
        )

    cy_edges = []
    for _, _, _, data in nx_graph.edges(keys=True, data=True):
        e: GraphEdge = data["edge"]
        cy_edges.append(
            {
                "edge_id": e.edge_id,
                "source": e.source_key,
                "target": e.target_key,
                "relation_type": e.relation_type.value,
                "fact_kind": e.fact_kind.value,
                "confidence": e.confidence,
                "provenance": e.provenance,
                "edge_metadata": e.edge_metadata,
            }
        )

    return {
        "assessment": _serialize_assessment(assessment),
        "nodes": cy_nodes,
        "edges": cy_edges,
        "stats": assessment.graph_stats or {
            "node_count": stats.node_count,
            "edge_count": stats.edge_count,
            "scc_cycle_count": stats.scc_cycle_count,
            "top_bridge_nodes": stats.top_bridge_nodes,
            "top_bridge_edges": stats.top_bridge_edges,
        },
    }


def get_assessment_graph_intelligence(
    db: Session,
    ctx: ActorContext,
    *,
    assessment_id: uuid.UUID,
    min_confidence: float = 0.2,
    max_hops: int = 6,
    include_inferred: bool = True,
) -> dict[str, Any]:
    require_permission(ctx.role, Permission.ASSESSMENT_READ)
    assessment = db.execute(
        select(Assessment).where(
            Assessment.id == assessment_id, Assessment.tenant_id == ctx.tenant_id
        )
    ).scalar_one_or_none()
    if assessment is None:
        raise NotFoundError(code="ASSESSMENT_NOT_FOUND", message="Assessment not found")

    nodes, edges = load_domain_graph_inputs(db, tenant_id=ctx.tenant_id, assessment_id=assessment.id)

    persisted_paths = list(
        db.execute(
            select(AttackPath).where(
                AttackPath.tenant_id == ctx.tenant_id,
                AttackPath.assessment_id == assessment.id,
            )
        ).scalars()
    )
    hash_to_id = {ap.determinism_hash: str(ap.id) for ap in persisted_paths}

    start_keys_set = {n.key for n in nodes if n.is_external_entry}
    target_keys_set = {
        n.key
        for n in nodes
        if n.is_crown_jewel or n.criticality == "critical" or n.privilege_level == "domain_admin"
    }
    for ap in persisted_paths:
        start_keys_set.add(f"{ap.start_node_kind}:{ap.start_node_id}")
        target_keys_set.add(f"{ap.target_node_kind}:{ap.target_node_id}")

    constraints = PathSearchConstraints(
        start_node_keys=sorted(start_keys_set),
        target_node_keys=sorted(target_keys_set),
        algorithm=AlgorithmType.DIJKSTRA,
        min_confidence=min_confidence,
        max_hops=max_hops,
        max_candidates=200,
        top_k=50,
        include_inferred=include_inferred,
    )
    intel = analyze_assessment_intelligence(
        nodes=nodes,
        edges=edges,
        constraints=constraints,
        persisted_paths_meta=hash_to_id,
    )
    return {
        "assessment_id": str(assessment.id),
        "assessment_name": assessment.name,
        "graph_version": assessment.graph_version,
        **intel,
    }


def _serialize_assessment(a: Assessment) -> dict[str, Any]:
    return {
        "id": str(a.id),
        "tenant_id": str(a.tenant_id),
        "name": a.name,
        "description": a.description,
        "status": a.status,
        "approved_scope_cidrs": a.approved_scope_cidrs,
        "time_window_start": a.time_window_start.isoformat(),
        "time_window_end": a.time_window_end.isoformat(),
        "operator_user_id": str(a.operator_user_id),
        "approved_by_user_id": str(a.approved_by_user_id) if a.approved_by_user_id else None,
        "approved_at": a.approved_at.isoformat() if a.approved_at else None,
        "is_synthetic": a.is_synthetic,
        "graph_version": a.graph_version,
        "graph_built_at": a.graph_built_at.isoformat() if a.graph_built_at else None,
        "graph_stats": a.graph_stats,
        "created_at": a.created_at.isoformat(),
    }
