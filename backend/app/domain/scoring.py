from dataclasses import dataclass

from app.domain.models import FactKind, GraphNode, PathStepData, RelationType


@dataclass(frozen=True)
class ScoringModelConfig:
    version: str
    formula: str
    disclaimer: str
    criticality_weights: dict[str, float]
    default_impact: float
    impact_floor: float
    impact_ceiling: float
    external_entry_exposure: float
    internal_entry_exposure: float
    exposed_non_external_floor: float
    hop_decay_per_extra_hop: float
    hop_attenuation_floor: float
    exposure_floor: float
    exposure_ceiling: float
    privilege_base: float
    privilege_floor: float
    privilege_ceiling: float
    privilege_admin: float
    privilege_role_or_trust: float
    privilege_membership: float
    privileged_node_floor: float
    raw_edge_confidence_floor: float
    evidence_floor: float
    evidence_ceiling: float
    observed_min_weight: float
    observed_average_weight: float
    inferred_step_attenuation: float
    inferred_penalty_floor: float
    stale_node_attenuation: float
    uncorroborated_step_attenuation: float
    per_category_missing_penalty_floor: float
    missing_data_floor: float
    missing_data_ceiling: float
    score_floor: float
    score_ceiling: float
    score_precision: int


SCORING_MODEL = ScoringModelConfig(
    version="v1.0.0",
    formula=(
        "priority_score = clamp(0, 100, 100 * impact_weight * exposure_factor * "
        "privilege_factor * evidence_confidence * missing_data_penalty)"
    ),
    disclaimer=(
        "Weighted, normalised priority ranking (0-100) for remediation triage. "
        "Not a calibrated statistical probability of breach."
    ),
    criticality_weights={"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.25},
    default_impact=0.5,
    impact_floor=0.25,
    impact_ceiling=1.0,
    external_entry_exposure=1.0,
    internal_entry_exposure=0.6,
    exposed_non_external_floor=0.72,
    hop_decay_per_extra_hop=0.06,
    hop_attenuation_floor=0.45,
    exposure_floor=0.35,
    exposure_ceiling=1.0,
    privilege_base=0.62,
    privilege_floor=0.4,
    privilege_ceiling=1.0,
    privilege_admin=1.0,
    privilege_role_or_trust=0.85,
    privilege_membership=0.75,
    privileged_node_floor=0.9,
    raw_edge_confidence_floor=0.05,
    evidence_floor=0.1,
    evidence_ceiling=1.0,
    observed_min_weight=0.5,
    observed_average_weight=0.5,
    inferred_step_attenuation=0.88,
    inferred_penalty_floor=0.5,
    stale_node_attenuation=0.92,
    uncorroborated_step_attenuation=0.90,
    per_category_missing_penalty_floor=0.65,
    missing_data_floor=0.5,
    missing_data_ceiling=1.0,
    score_floor=0.0,
    score_ceiling=100.0,
    score_precision=2,
)

SCORING_VERSION = SCORING_MODEL.version
SCORING_FORMULA = SCORING_MODEL.formula
SCORING_DISCLAIMER = SCORING_MODEL.disclaimer
CRITICALITY_WEIGHTS = SCORING_MODEL.criticality_weights


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
    cfg = SCORING_MODEL
    if not steps:
        return ScoreBreakdown(
            priority_score=0.0,
            impact_weight=cfg.impact_floor,
            exposure_factor=cfg.exposure_floor,
            privilege_factor=cfg.privilege_floor,
            evidence_confidence=cfg.evidence_floor,
            missing_data_penalty=cfg.missing_data_floor,
        )

    # 1. Impact weight: target criticality, crown-jewel and domain-admin overrides.
    base_impact = cfg.criticality_weights.get(target_node.criticality, cfg.default_impact)
    if target_node.is_crown_jewel:
        base_impact = cfg.impact_ceiling
    elif target_node.privilege_level == "domain_admin":
        base_impact = max(base_impact, 0.95)
    impact_weight = round(min(cfg.impact_ceiling, max(cfg.impact_floor, base_impact)), 4)

    # 2. Exposure factor: entry exposure plus linear per-hop attenuation.
    hop_count = len(steps)
    entry_exposure = (
        cfg.external_entry_exposure if start_node.is_external_entry else cfg.internal_entry_exposure
    )
    has_exposed_edge = any(
        s.relation_type in (RelationType.EXPOSES.value, RelationType.CONNECTS_TO.value)
        for s in steps
    )
    if has_exposed_edge and not start_node.is_external_entry:
        entry_exposure = max(entry_exposure, cfg.exposed_non_external_floor)
    hop_attenuation = max(
        cfg.hop_attenuation_floor,
        1.0 - cfg.hop_decay_per_extra_hop * max(0, hop_count - 1),
    )
    exposure_factor = round(
        min(cfg.exposure_ceiling, max(cfg.exposure_floor, entry_exposure * hop_attenuation)), 4
    )

    # 3. Privilege factor: strongest privilege transition present on the path.
    priv_score = cfg.privilege_base
    for step in steps:
        if step.relation_type == RelationType.CAN_ADMINISTER.value:
            priv_score = max(priv_score, cfg.privilege_admin)
        elif step.relation_type in (RelationType.HAS_ROLE.value, RelationType.TRUSTS.value):
            priv_score = max(priv_score, cfg.privilege_role_or_trust)
        elif step.relation_type == RelationType.MEMBER_OF.value:
            priv_score = max(priv_score, cfg.privilege_membership)
    if any(n.privilege_level in ("privileged", "domain_admin") for n in path_nodes):
        priv_score = max(priv_score, cfg.privileged_node_floor)
    privilege_factor = round(
        min(cfg.privilege_ceiling, max(cfg.privilege_floor, priv_score)), 4
    )

    # 4. Evidence confidence: equally weighted minimum and arithmetic mean.
    step_confs = [
        max(cfg.raw_edge_confidence_floor, min(cfg.evidence_ceiling, s.confidence))
        for s in steps
    ]
    min_conf = min(step_confs)
    avg_conf = sum(step_confs) / len(step_confs)
    combined_conf = (
        cfg.observed_min_weight * min_conf + cfg.observed_average_weight * avg_conf
    )
    inferred_count = sum(
        1 for s in steps if s.fact_kind == FactKind.INFERRED_RELATIONSHIP.value
    )
    if inferred_count > 0:
        inferred_penalty = max(
            cfg.inferred_penalty_floor, cfg.inferred_step_attenuation**inferred_count
        )
        combined_conf *= inferred_penalty
    evidence_confidence = round(
        min(cfg.evidence_ceiling, max(cfg.evidence_floor, combined_conf)), 4
    )

    # 5. Missing-data penalty: independent stale-node and corroboration deductions.
    penalty = 1.0
    stale_nodes = sum(1 for n in path_nodes if n.stale_observation)
    uncorroborated_steps = sum(1 for s in steps if s.missing_corroboration)
    if stale_nodes > 0:
        penalty *= max(
            cfg.per_category_missing_penalty_floor,
            cfg.stale_node_attenuation**stale_nodes,
        )
    if uncorroborated_steps > 0:
        penalty *= max(
            cfg.per_category_missing_penalty_floor,
            cfg.uncorroborated_step_attenuation**uncorroborated_steps,
        )
    missing_data_penalty = round(
        min(cfg.missing_data_ceiling, max(cfg.missing_data_floor, penalty)), 4
    )

    raw = (
        100.0
        * impact_weight
        * exposure_factor
        * privilege_factor
        * evidence_confidence
        * missing_data_penalty
    )
    priority_score = round(
        min(cfg.score_ceiling, max(cfg.score_floor, raw)), cfg.score_precision
    )

    return ScoreBreakdown(
        priority_score=priority_score,
        impact_weight=impact_weight,
        exposure_factor=exposure_factor,
        privilege_factor=privilege_factor,
        evidence_confidence=evidence_confidence,
        missing_data_penalty=missing_data_penalty,
    )


def render_scoring_model_markdown() -> str:
    """Render the published scoring contract directly from the constants used by the scorer."""
    cfg = SCORING_MODEL
    weights = "\n".join(
        f"| `{name}` | {weight:.2f} |" for name, weight in cfg.criticality_weights.items()
    )
    return f"""# SentinelGraph Scoring Model (`{cfg.version}`)

<!-- GENERATED FILE: edit ScoringModelConfig in backend/app/domain/scoring.py, not this file. -->

## Purpose and non-probability guarantee

The priority score is a deterministic, normalised remediation-triage ranking on
[`{cfg.score_floor:.0f}, {cfg.score_ceiling:.0f}`]. It is **not** a breach probability,
exploit-likelihood percentage, prediction of compromise, or SLA estimate.

> {cfg.disclaimer}

## Published formula

```text
raw_score = 100.0 * impact_weight * exposure_factor * privilege_factor
            * evidence_confidence * missing_data_penalty
priority_score = round(clamp({cfg.score_floor:.1f}, {cfg.score_ceiling:.1f}, raw_score), {cfg.score_precision})
```

The implementation and this document share one typed configuration:
`SCORING_MODEL` in `backend/app/domain/scoring.py`. The rendered values below are
not a second, hand-maintained scoring specification.

## Component definitions

### 1. Impact weight

- Clamp range: [{cfg.impact_floor:.2f}, {cfg.impact_ceiling:.2f}].
- Target criticality weights:

| Criticality | Weight |
|---|---:|
{weights}
- Unknown criticality falls back to `{cfg.default_impact:.2f}`.
- Crown-jewel designation overrides the weight to `{cfg.impact_ceiling:.2f}`.
- A target with `privilege_level == "domain_admin"` receives at least `0.95`.

### 2. Exposure factor

- External-entry start: `{cfg.external_entry_exposure:.2f}`.
- Other start: `{cfg.internal_entry_exposure:.2f}`.
- If a non-external start has an `EXPOSES` or `CONNECTS_TO` step, its starting exposure is at least `{cfg.exposed_non_external_floor:.2f}`.
- Hop attenuation: `max({cfg.hop_attenuation_floor:.2f}, 1.0 - {cfg.hop_decay_per_extra_hop:.2f} * max(0, hop_count - 1))`.
- Final clamp range: [{cfg.exposure_floor:.2f}, {cfg.exposure_ceiling:.2f}].

### 3. Privilege factor

- Base: `{cfg.privilege_base:.2f}`; clamp range [{cfg.privilege_floor:.2f}, {cfg.privilege_ceiling:.2f}].
- `CAN_ADMINISTER`: at least `{cfg.privilege_admin:.2f}`.
- `HAS_ROLE` or `TRUSTS`: at least `{cfg.privilege_role_or_trust:.2f}`.
- `MEMBER_OF`: at least `{cfg.privilege_membership:.2f}`.
- A node with privilege level `privileged` or `domain_admin`: at least `{cfg.privileged_node_floor:.2f}`.

### 4. Evidence confidence

- Each edge confidence is clamped to [{cfg.raw_edge_confidence_floor:.2f}, {cfg.evidence_ceiling:.2f}].
- The combined value is `{cfg.observed_min_weight:.2f} * minimum_edge_confidence + {cfg.observed_average_weight:.2f} * arithmetic_mean_edge_confidence`.
- Each inferred relationship applies attenuation `{cfg.inferred_step_attenuation:.2f} ** inferred_edge_count`, with a minimum multiplier of `{cfg.inferred_penalty_floor:.2f}`.
- Final clamp range: [{cfg.evidence_floor:.2f}, {cfg.evidence_ceiling:.2f}].

### 5. Missing-data penalty

- Start at `1.00`.
- Stale nodes multiply by `{cfg.stale_node_attenuation:.2f} ** stale_node_count`.
- Steps missing corroboration multiply by `{cfg.uncorroborated_step_attenuation:.2f} ** uncorroborated_step_count`.
- Each category's multiplier is floored at `{cfg.per_category_missing_penalty_floor:.2f}`; final clamp range is [{cfg.missing_data_floor:.2f}, {cfg.missing_data_ceiling:.2f}].

## Reproducibility and interpretation

Each path stores the scoring version, component values, formula, and
`is_probability: false` in its explanation trace. Determinism hashes include the
scoring version. Changing any scoring constant or calculation requires an intentional
version decision and regression review.

The score is a heuristic ranking for triage. It has not been calibrated to empirical
breach frequencies and must not be interpreted as a probability.
"""
