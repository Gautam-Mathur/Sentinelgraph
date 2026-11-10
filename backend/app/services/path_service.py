import contextlib
import uuid
from typing import Any

from sqlalchemy import delete, desc, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import NotFoundError, ValidationAppError
from app.core.permissions import Permission, require_permission
from app.core.telemetry import metrics
from app.db.models import Assessment, AttackPath, PathStep
from app.domain.graph_engine import build_networkx_graph, find_attack_paths
from app.domain.graph_intelligence import analyze_single_path_intelligence
from app.domain.models import AlgorithmType, PathSearchConstraints, RelationType
from app.services.assessment_service import load_domain_graph_inputs
from app.services.audit_service import record_audit_event
from app.services.context import ActorContext
from app.services.webhook_service import dispatch_webhook_events


def generate_paths_for_assessment(
    db: Session,
    ctx: ActorContext,
    *,
    assessment_id: uuid.UUID,
    start_node_keys: list[str] | None,
    target_node_keys: list[str] | None,
    algorithm: str,
    allowed_edge_types: list[str] | None,
    excluded_node_keys: list[str] | None,
    excluded_environments: list[str] | None,
    min_confidence: float,
    max_hops: int,
    max_candidates: int,
    top_k: int,
    include_inferred: bool,
    target_criticalities: list[str] | None = None,
) -> dict[str, Any]:
    require_permission(ctx.role, Permission.PATH_GENERATE)
    settings = get_settings()

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
            message="Assessment scope must be approved before generating attack paths.",
        )

    if max_hops < 1 or max_hops > settings.hard_max_hops:
        raise ValidationAppError(
            code="INVALID_MAX_HOPS",
            message=f"max_hops must be between 1 and {settings.hard_max_hops}.",
        )
    if max_candidates < 1 or max_candidates > settings.hard_max_candidates:
        raise ValidationAppError(
            code="INVALID_MAX_CANDIDATES",
            message=f"max_candidates must be between 1 and {settings.hard_max_candidates}.",
        )

    algo_enum = AlgorithmType(algorithm)
    allowed_rels = [RelationType(e) for e in allowed_edge_types] if allowed_edge_types else None

    nodes, edges = load_domain_graph_inputs(db, tenant_id=ctx.tenant_id, assessment_id=assessment.id)
    nx_graph, stats = build_networkx_graph(nodes, edges)

    # Auto-resolve start nodes (external entries) and target nodes (critical / crown jewels) if not explicitly specified
    resolved_starts = list(start_node_keys or [])
    if not resolved_starts:
        resolved_starts = [n.key for n in nodes if n.is_external_entry]
    resolved_targets = list(target_node_keys or [])
    if not resolved_targets:
        crit_filter = set(target_criticalities or ["critical"])
        resolved_targets = [
            n.key
            for n in nodes
            if n.is_crown_jewel or n.criticality in crit_filter or n.privilege_level == "domain_admin"
        ]

    constraints = PathSearchConstraints(
        start_node_keys=resolved_starts,
        target_node_keys=resolved_targets,
        algorithm=algo_enum,
        allowed_edge_types=allowed_rels,
        excluded_node_keys=excluded_node_keys or [],
        excluded_environments=excluded_environments or [],
        min_confidence=min_confidence,
        max_hops=max_hops,
        max_candidates=max_candidates,
        top_k=top_k,
        timeout_seconds=settings.path_search_timeout_seconds,
        include_inferred=include_inferred,
    )

    search_out = find_attack_paths(nx_graph, constraints)
    metrics.observe_ms("path_search_ms", search_out.duration_ms)
    metrics.inc("path_queries_total")

    # Replace previous path snapshot for this assessment atomically
    db.execute(
        delete(AttackPath).where(
            AttackPath.tenant_id == ctx.tenant_id,
            AttackPath.assessment_id == assessment.id,
        )
    )
    db.flush()

    created_paths: list[AttackPath] = []
    for res in search_out.paths:
        ap = AttackPath(
            tenant_id=ctx.tenant_id,
            assessment_id=assessment.id,
            title=res.title,
            start_node_kind=res.start_node_kind,
            start_node_id=uuid.UUID(res.start_node_id),
            start_node_label=res.start_node_label,
            target_node_kind=res.target_node_kind,
            target_node_id=uuid.UUID(res.target_node_id),
            target_node_label=res.target_node_label,
            algorithm=res.algorithm,
            algorithm_params=res.algorithm_params,
            scoring_version=res.scoring_version,
            priority_score=res.priority_score,
            impact_weight=res.impact_weight,
            exposure_factor=res.exposure_factor,
            privilege_factor=res.privilege_factor,
            evidence_confidence=res.evidence_confidence,
            missing_data_penalty=res.missing_data_penalty,
            hop_count=res.hop_count,
            is_truncated=res.is_truncated,
            assumptions=res.assumptions,
            explanation_narrative=res.explanation_narrative,
            explanation_trace=res.explanation_trace,
            determinism_hash=res.determinism_hash,
        )
        db.add(ap)
        db.flush()

        for st in res.steps:
            db.add(
                PathStep(
                    tenant_id=ctx.tenant_id,
                    attack_path_id=ap.id,
                    step_order=st.step_order,
                    relationship_id=uuid.UUID(st.relationship_id),
                    from_node_kind=st.from_node_kind,
                    from_node_id=uuid.UUID(st.from_node_id),
                    from_node_label=st.from_node_label,
                    to_node_kind=st.to_node_kind,
                    to_node_id=uuid.UUID(st.to_node_id),
                    to_node_label=st.to_node_label,
                    relation_type=st.relation_type,
                    fact_kind=st.fact_kind,
                    confidence=st.confidence,
                    preconditions=st.preconditions,
                    assumptions=st.assumptions,
                    evidence_refs=st.evidence_refs,
                    narrative=st.narrative,
                )
            )
        created_paths.append(ap)

    record_audit_event(
        db,
        tenant_id=ctx.tenant_id,
        actor_user_id=ctx.user_id,
        actor_email=ctx.email,
        action="path.generate",
        object_type="assessment",
        object_id=str(assessment.id),
        outcome="success",
        request_id=ctx.request_id,
        details={
            "algorithm": algorithm,
            "paths_found": len(created_paths),
            "candidates_evaluated": search_out.candidates_evaluated,
            "is_truncated": search_out.is_truncated,
        },
    )
    db.commit()

    if created_paths:
        top_path = max(created_paths, key=lambda p: p.priority_score)
        with contextlib.suppress(Exception):
            dispatch_webhook_events(
                db,
                ctx,
                event_type="attack_path.high_risk",
                priority_score=float(top_path.priority_score),
                payload={
                    "assessment_id": str(assessment.id),
                    "assessment_name": assessment.name,
                    "top_path_id": str(top_path.id),
                    "top_path_title": top_path.title,
                    "priority_score": top_path.priority_score,
                    "paths_count": len(created_paths),
                },
            )

    return {
        "assessment_id": str(assessment.id),
        "paths_count": len(created_paths),
        "candidates_evaluated": search_out.candidates_evaluated,
        "is_truncated": search_out.is_truncated,
        "truncation_reason": search_out.truncation_reason,
        "duration_ms": search_out.duration_ms,
        "bridge_nodes": stats.top_bridge_nodes,
        "scc_cycles": stats.scc_cycles,
        "paths": [_serialize_attack_path(p) for p in created_paths],
    }


def list_attack_paths(
    db: Session,
    ctx: ActorContext,
    *,
    assessment_id: uuid.UUID | None = None,
    min_score: float | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    require_permission(ctx.role, Permission.PATH_READ)
    stmt = select(AttackPath).where(AttackPath.tenant_id == ctx.tenant_id)
    if assessment_id is not None:
        stmt = stmt.where(AttackPath.assessment_id == assessment_id)
    if min_score is not None:
        stmt = stmt.where(AttackPath.priority_score >= min_score)

    rows = list(
        db.execute(
            stmt.order_by(desc(AttackPath.priority_score), AttackPath.hop_count.asc())
            .offset(offset)
            .limit(limit)
        ).scalars()
    )
    return [_serialize_attack_path(p) for p in rows]


def get_attack_path_detail(db: Session, ctx: ActorContext, path_id: uuid.UUID) -> dict[str, Any]:
    require_permission(ctx.role, Permission.PATH_READ)
    ap = db.execute(
        select(AttackPath).where(AttackPath.id == path_id, AttackPath.tenant_id == ctx.tenant_id)
    ).scalar_one_or_none()
    if ap is None:
        raise NotFoundError(code="ATTACK_PATH_NOT_FOUND", message="Attack path not found")
    return _serialize_attack_path(ap, include_steps=True)


def get_attack_path_intelligence(
    db: Session, ctx: ActorContext, path_id: uuid.UUID
) -> dict[str, Any]:
    require_permission(ctx.role, Permission.PATH_READ)
    ap = db.execute(
        select(AttackPath).where(AttackPath.id == path_id, AttackPath.tenant_id == ctx.tenant_id)
    ).scalar_one_or_none()
    if ap is None:
        raise NotFoundError(code="ATTACK_PATH_NOT_FOUND", message="Attack path not found")

    nodes, edges = load_domain_graph_inputs(
        db, tenant_id=ctx.tenant_id, assessment_id=ap.assessment_id
    )
    start_key = f"{ap.start_node_kind}:{ap.start_node_id}"
    target_key = f"{ap.target_node_kind}:{ap.target_node_id}"

    start_keys = sorted({start_key, *(n.key for n in nodes if n.is_external_entry)})
    target_keys = sorted(
        {
            target_key,
            *(
                n.key
                for n in nodes
                if n.is_crown_jewel
                or n.criticality == "critical"
                or n.privilege_level == "domain_admin"
            ),
        }
    )

    algo_params = ap.algorithm_params or {}
    algo_raw = str(algo_params.get("algorithm") or ap.algorithm or "dijkstra")
    algo_enum = AlgorithmType(algo_raw if algo_raw in ("bfs", "dijkstra") else "dijkstra")
    min_conf = float(algo_params.get("min_confidence", 0.2))
    max_hops = max(ap.hop_count, int(algo_params.get("max_hops", 6)))
    include_inferred = bool(algo_params.get("include_inferred", True))

    constraints = PathSearchConstraints(
        start_node_keys=start_keys,
        target_node_keys=target_keys,
        algorithm=algo_enum,
        min_confidence=min(0.95, max(0.05, min_conf)),
        max_hops=min(12, max(1, max_hops)),
        max_candidates=200,
        top_k=50,
        include_inferred=include_inferred,
    )

    step_dicts = [
        {
            "step_order": s.step_order,
            "relationship_id": str(s.relationship_id) if s.relationship_id else "",
            "from_node_kind": s.from_node_kind,
            "from_node_id": str(s.from_node_id),
            "from_node_label": s.from_node_label,
            "to_node_kind": s.to_node_kind,
            "to_node_id": str(s.to_node_id),
            "to_node_label": s.to_node_label,
            "relation_type": s.relation_type,
            "fact_kind": s.fact_kind,
            "confidence": s.confidence,
            "narrative": s.narrative,
        }
        for s in ap.steps
    ]

    intel = analyze_single_path_intelligence(
        nodes=nodes,
        edges=edges,
        constraints=constraints,
        path_steps=step_dicts,
        start_key=start_key,
        target_key=target_key,
        priority_score=float(ap.priority_score),
        persisted_path_id=str(ap.id),
    )
    return {
        "assessment_id": str(ap.assessment_id),
        "path_title": ap.title,
        **intel,
    }


def _serialize_attack_path(ap: AttackPath, include_steps: bool = True) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": str(ap.id),
        "assessment_id": str(ap.assessment_id),
        "title": ap.title,
        "start_node_kind": ap.start_node_kind,
        "start_node_id": str(ap.start_node_id),
        "start_node_label": ap.start_node_label,
        "target_node_kind": ap.target_node_kind,
        "target_node_id": str(ap.target_node_id),
        "target_node_label": ap.target_node_label,
        "algorithm": ap.algorithm,
        "algorithm_params": ap.algorithm_params,
        "scoring_version": ap.scoring_version,
        "priority_score": ap.priority_score,
        "impact_weight": ap.impact_weight,
        "exposure_factor": ap.exposure_factor,
        "privilege_factor": ap.privilege_factor,
        "evidence_confidence": ap.evidence_confidence,
        "missing_data_penalty": ap.missing_data_penalty,
        "hop_count": ap.hop_count,
        "is_truncated": ap.is_truncated,
        "assumptions": ap.assumptions,
        "explanation_narrative": ap.explanation_narrative,
        "explanation_trace": ap.explanation_trace,
        "determinism_hash": ap.determinism_hash,
        "created_at": ap.created_at.isoformat(),
    }
    if include_steps:
        data["steps"] = [
            {
                "id": str(s.id),
                "step_order": s.step_order,
                "relationship_id": str(s.relationship_id) if s.relationship_id else None,
                "from_node_kind": s.from_node_kind,
                "from_node_id": str(s.from_node_id),
                "from_node_label": s.from_node_label,
                "to_node_kind": s.to_node_kind,
                "to_node_id": str(s.to_node_id),
                "to_node_label": s.to_node_label,
                "relation_type": s.relation_type,
                "fact_kind": s.fact_kind,
                "confidence": s.confidence,
                "preconditions": s.preconditions,
                "assumptions": s.assumptions,
                "evidence_refs": s.evidence_refs,
                "narrative": s.narrative,
            }
            for s in ap.steps
        ]
    return data
