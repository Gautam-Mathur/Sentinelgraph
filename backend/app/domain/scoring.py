from dataclasses import dataclass

from app.domain.models import FactKind, GraphNode, PathStepData, RelationType

SCORING_VERSION = "v1.0.0"
SCORING_FORMULA = (
    "priority_score = clamp(0, 100, 100 * impact_weight * exposure_factor * "
    "privilege_factor * evidence_confidence * missing_data_penalty)"
)
SCORING_DISCLAIMER = (
    "Weighted, normalised priority ranking (0-100) for remediation triage. "
    "Not a calibrated statistical probability of breach."
)

CRITICALITY_WEIGHTS: dict[str, float] = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.25,
}


@dataclass(frozen=True)
class ScoreBreakdown:
    priority_score: float
    impact_weight: float
    exposure_factor: float
    privilege_factor: float
    evidence_confidence: float
    missing_data_penalty: float
    scoring_version: str = SCORING_VERSION
    formula: str = SCORING_FORMULA
    is_probability: bool = False
    disclaimer: str = SCORING_DISCLAIMER


def score_attack_path(
    *,
    start_node: GraphNode,
    target_node: GraphNode,
    steps: list[PathStepData],
    path_nodes: list[GraphNode],
) -> ScoreBreakdown:
    if not steps:
        return ScoreBreakdown(
            priority_score=0.0,
            impact_weight=0.25,
            exposure_factor=0.35,
            privilege_factor=0.4,
            evidence_confidence=0.1,
            missing_data_penalty=0.5,
        )

    # 1. Impact weight [0.25, 1.0]
    base_impact = CRITICALITY_WEIGHTS.get(target_node.criticality, 0.5)
    if target_node.is_crown_jewel:
        base_impact = 1.0
    elif target_node.privilege_level == "domain_admin":
        base_impact = max(base_impact, 0.95)
    impact_weight = round(min(1.0, max(0.25, base_impact)), 4)

    # 2. Exposure factor [0.35, 1.0]
    hop_count = len(steps)
    entry_exposure = 1.0 if start_node.is_external_entry else 0.6
    has_exposed_edge = any(
        s.relation_type in (RelationType.EXPOSES.value, RelationType.CONNECTS_TO.value)
        for s in steps
    )
    if has_exposed_edge and not start_node.is_external_entry:
        entry_exposure = max(entry_exposure, 0.72)
    hop_attenuation = max(0.45, 1.0 - 0.06 * max(0, hop_count - 1))
    exposure_factor = round(min(1.0, max(0.35, entry_exposure * hop_attenuation)), 4)

    # 3. Privilege factor [0.40, 1.0]
    priv_score = 0.62
    for step in steps:
        if step.relation_type == RelationType.CAN_ADMINISTER.value:
            priv_score = max(priv_score, 1.0)
        elif step.relation_type in (RelationType.HAS_ROLE.value, RelationType.TRUSTS.value):
            priv_score = max(priv_score, 0.85)
        elif step.relation_type == RelationType.MEMBER_OF.value:
            priv_score = max(priv_score, 0.75)
    if any(n.privilege_level in ("privileged", "domain_admin") for n in path_nodes):
        priv_score = max(priv_score, 0.9)
    privilege_factor = round(min(1.0, max(0.4, priv_score)), 4)

    # 4. Evidence confidence [0.10, 1.0]
    step_confs = [max(0.05, min(1.0, s.confidence)) for s in steps]
    min_conf = min(step_confs)
    avg_conf = sum(step_confs) / len(step_confs)
    combined_conf = 0.5 * min_conf + 0.5 * avg_conf
    inferred_count = sum(
        1 for s in steps if s.fact_kind == FactKind.INFERRED_RELATIONSHIP.value
    )
    if inferred_count > 0:
        inferred_penalty = max(0.5, 0.88**inferred_count)
        combined_conf *= inferred_penalty
    evidence_confidence = round(min(1.0, max(0.1, combined_conf)), 4)

    # 5. Missing-data penalty [0.50, 1.0]
    penalty = 1.0
    stale_nodes = sum(1 for n in path_nodes if n.stale_observation)
    uncorroborated_steps = sum(1 for s in steps if s.missing_corroboration)
    if stale_nodes > 0:
        penalty *= max(0.65, 0.92**stale_nodes)
    if uncorroborated_steps > 0:
        penalty *= max(0.65, 0.90**uncorroborated_steps)
    missing_data_penalty = round(min(1.0, max(0.5, penalty)), 4)

    raw = (
        100.0
        * impact_weight
        * exposure_factor
        * privilege_factor
        * evidence_confidence
        * missing_data_penalty
    )
    priority_score = round(min(100.0, max(0.0, raw)), 2)

    return ScoreBreakdown(
        priority_score=priority_score,
        impact_weight=impact_weight,
        exposure_factor=exposure_factor,
        privilege_factor=privilege_factor,
        evidence_confidence=evidence_confidence,
        missing_data_penalty=missing_data_penalty,
    )
