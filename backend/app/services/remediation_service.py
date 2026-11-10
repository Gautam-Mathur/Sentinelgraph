import uuid
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.core.errors import NotFoundError
from app.core.permissions import Permission, require_permission
from app.db.models import Assessment, RemediationAction
from app.domain.models import AlgorithmType, PathSearchConstraints, RemediationTransformType
from app.domain.remediation_sim import (
    RemediationTransform,
    _summarize_metrics,
    simulate_remediation,
)
from app.services.assessment_service import load_domain_graph_inputs
from app.services.audit_service import record_audit_event
from app.services.context import ActorContext


def simulate_remediation_plan(
    db: Session,
    ctx: ActorContext,
    *,
    assessment_id: uuid.UUID,
    name: str,
    description: str,
    transforms_in: list[dict[str, Any]],
    min_confidence: float = 0.2,
    max_hops: int = 6,
) -> dict[str, Any]:
    require_permission(ctx.role, Permission.REMEDIATION_SIMULATE)
    assessment = db.execute(
        select(Assessment).where(
            Assessment.id == assessment_id, Assessment.tenant_id == ctx.tenant_id
        )
    ).scalar_one_or_none()
    if assessment is None:
        raise NotFoundError(code="ASSESSMENT_NOT_FOUND", message="Assessment not found")

    nodes, edges = load_domain_graph_inputs(db, tenant_id=ctx.tenant_id, assessment_id=assessment.id)
    starts = [n.key for n in nodes if n.is_external_entry]
    targets = [
        n.key
        for n in nodes
        if n.is_crown_jewel or n.criticality == "critical" or n.privilege_level == "domain_admin"
    ]
    constraints = PathSearchConstraints(
        start_node_keys=starts,
        target_node_keys=targets,
        algorithm=AlgorithmType.DIJKSTRA,
        min_confidence=min_confidence,
        max_hops=max_hops,
        top_k=50,
    )

    domain_transforms = [
        RemediationTransform(
            transform_type=RemediationTransformType(t["transform_type"]),
            relationship_id=t.get("relationship_id"),
            source_node_key=t.get("source_node_key"),
            target_node_key=t.get("target_node_key"),
            identity_id=t.get("identity_id"),
            asset_id=t.get("asset_id"),
            cve_id=t.get("cve_id"),
            new_confidence=t.get("new_confidence"),
            ports=t.get("ports"),
            notes=t.get("notes", ""),
        )
        for t in transforms_in
    ]

    comp = simulate_remediation(
        nodes=nodes,
        edges=edges,
        constraints=constraints,
        transforms=domain_transforms,
    )

    baseline_dict = {
        "total_paths": comp.baseline.total_paths,
        "reachable_critical_assets": comp.baseline.reachable_critical_assets,
        "reachable_critical_asset_labels": comp.baseline.reachable_critical_asset_labels,
        "highest_path_score": comp.baseline.highest_path_score,
        "high_confidence_paths": comp.baseline.high_confidence_paths,
        "key_bridge_nodes": comp.baseline.key_bridge_nodes,
    }
    modelled_dict = {
        "total_paths": comp.modelled.total_paths,
        "reachable_critical_assets": comp.modelled.reachable_critical_assets,
        "reachable_critical_asset_labels": comp.modelled.reachable_critical_asset_labels,
        "highest_path_score": comp.modelled.highest_path_score,
        "high_confidence_paths": comp.modelled.high_confidence_paths,
        "key_bridge_nodes": comp.modelled.key_bridge_nodes,
    }

    action_row = RemediationAction(
        tenant_id=ctx.tenant_id,
        assessment_id=assessment.id,
        name=name.strip(),
        description=description.strip(),
        status="simulated",
        transforms=transforms_in,
        baseline_metrics=baseline_dict,
        modelled_metrics=modelled_dict,
        delta_summary={**comp.delta_summary, "disclaimer": comp.disclaimer},
        is_modelled_only=True,
        created_by_user_id=ctx.user_id,
    )
    db.add(action_row)
    db.flush()

    record_audit_event(
        db,
        tenant_id=ctx.tenant_id,
        actor_user_id=ctx.user_id,
        actor_email=ctx.email,
        action="remediation.simulate",
        object_type="remediation_action",
        object_id=str(action_row.id),
        outcome="success",
        request_id=ctx.request_id,
        details={
            "assessment_id": str(assessment.id),
            "transforms_count": len(transforms_in),
            "paths_eliminated": comp.delta_summary["paths_eliminated"],
        },
    )
    db.commit()
    return _serialize_remediation(action_row)


def validate_remediation_against_assessment(
    db: Session,
    ctx: ActorContext,
    *,
    remediation_id: uuid.UUID,
    later_assessment_id: uuid.UUID,
) -> dict[str, Any]:
    require_permission(ctx.role, Permission.REMEDIATION_SIMULATE)
    rem = db.execute(
        select(RemediationAction).where(
            RemediationAction.id == remediation_id,
            RemediationAction.tenant_id == ctx.tenant_id,
        )
    ).scalar_one_or_none()
    if rem is None:
        raise NotFoundError(code="REMEDIATION_NOT_FOUND", message="Remediation action not found")

    later_assess = db.execute(
        select(Assessment).where(
            Assessment.id == later_assessment_id,
            Assessment.tenant_id == ctx.tenant_id,
        )
    ).scalar_one_or_none()
    if later_assess is None:
        raise NotFoundError(code="ASSESSMENT_NOT_FOUND", message="Later assessment not found")

    nodes, edges = load_domain_graph_inputs(db, tenant_id=ctx.tenant_id, assessment_id=later_assess.id)
    starts = [n.key for n in nodes if n.is_external_entry]
    targets = [
        n.key
        for n in nodes
        if n.is_crown_jewel or n.criticality == "critical" or n.privilege_level == "domain_admin"
    ]
    constraints = PathSearchConstraints(
        start_node_keys=starts,
        target_node_keys=targets,
        algorithm=AlgorithmType.DIJKSTRA,
        min_confidence=0.2,
        max_hops=6,
        top_k=50,
    )
    observed_later = _summarize_metrics(nodes, edges, constraints)

    modelled_paths = int(rem.modelled_metrics.get("total_paths", 0))
    baseline_paths = int(rem.baseline_metrics.get("total_paths", 0))
    verified = observed_later.total_paths <= modelled_paths and observed_later.total_paths < baseline_paths

    validation_result = {
        "later_assessment_id": str(later_assess.id),
        "later_assessment_name": later_assess.name,
        "observed_total_paths": observed_later.total_paths,
        "observed_reachable_critical_assets": observed_later.reachable_critical_assets,
        "observed_highest_path_score": observed_later.highest_path_score,
        "matches_modelled_reduction": verified,
        "summary": (
            "Later assessment confirms path reduction predicted by sandbox model."
            if verified
            else "Later assessment still shows residual attack paths exceeding modelled target."
        ),
    }

    rem.validation_assessment_id = later_assess.id
    rem.validation_result = validation_result
    rem.status = "validated_later" if verified else "simulated"
    db.flush()

    record_audit_event(
        db,
        tenant_id=ctx.tenant_id,
        actor_user_id=ctx.user_id,
        actor_email=ctx.email,
        action="remediation.validate",
        object_type="remediation_action",
        object_id=str(rem.id),
        outcome="success",
        request_id=ctx.request_id,
        details=validation_result,
    )
    db.commit()
    return _serialize_remediation(rem)


def list_remediations(
    db: Session,
    ctx: ActorContext,
    *,
    assessment_id: uuid.UUID | None = None,
) -> list[dict[str, Any]]:
    require_permission(ctx.role, Permission.REMEDIATION_READ)
    stmt = select(RemediationAction).where(RemediationAction.tenant_id == ctx.tenant_id)
    if assessment_id is not None:
        stmt = stmt.where(RemediationAction.assessment_id == assessment_id)
    rows = list(db.execute(stmt.order_by(desc(RemediationAction.created_at))).scalars())
    return [_serialize_remediation(r) for r in rows]


def _serialize_remediation(r: RemediationAction) -> dict[str, Any]:
    return {
        "id": str(r.id),
        "assessment_id": str(r.assessment_id),
        "name": r.name,
        "description": r.description,
        "status": r.status,
        "transforms": r.transforms,
        "baseline_metrics": r.baseline_metrics,
        "modelled_metrics": r.modelled_metrics,
        "delta_summary": r.delta_summary,
        "is_modelled_only": r.is_modelled_only,
        "validation_assessment_id": str(r.validation_assessment_id) if r.validation_assessment_id else None,
        "validation_result": r.validation_result,
        "created_at": r.created_at.isoformat(),
    }
