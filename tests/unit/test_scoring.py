from app.domain.models import FactKind, GraphNode, NodeKind, PathStepData, RelationType
from app.domain.scoring import SCORING_VERSION, score_attack_path


def _node(nid: str, *, entry: bool = False, crown: bool = False, crit: str = "medium", stale: bool = False) -> GraphNode:
    return GraphNode(
        node_kind=NodeKind.ASSET,
        node_id=nid,
        label=nid,
        criticality=crit,
        is_external_entry=entry,
        is_crown_jewel=crown,
        stale_observation=stale,
    )


def _step(order: int, rel: RelationType, fact: FactKind, conf: float, missing_corr: bool = False) -> PathStepData:
    return PathStepData(
        step_order=order,
        relationship_id=f"rel-{order}",
        from_node_kind="asset",
        from_node_id="a1",
        from_node_label="a1",
        to_node_kind="asset",
        to_node_id="a2",
        to_node_label="a2",
        relation_type=rel.value,
        fact_kind=fact.value,
        confidence=conf,
        preconditions=["pre"],
        assumptions=[],
        evidence_refs=[],
        narrative="step",
        missing_corroboration=missing_corr,
    )


def test_scoring_is_deterministic_and_not_probability() -> None:
    s_node = _node("entry", entry=True)
    t_node = _node("crown", crown=True, crit="critical")
    steps = [
        _step(1, RelationType.CONNECTS_TO, FactKind.OBSERVED_FACT, 0.92),
        _step(2, RelationType.CAN_ADMINISTER, FactKind.OBSERVED_FACT, 0.95),
    ]
    b1 = score_attack_path(start_node=s_node, target_node=t_node, steps=steps, path_nodes=[s_node, t_node])
    b2 = score_attack_path(start_node=s_node, target_node=t_node, steps=steps, path_nodes=[s_node, t_node])
    assert b1 == b2
    assert b1.scoring_version == SCORING_VERSION
    assert b1.is_probability is False
    assert 0.0 <= b1.priority_score <= 100.0


def test_inferred_and_missing_data_penalties_reduce_score() -> None:
    s_node = _node("entry", entry=True)
    t_node = _node("crown", crown=True, crit="critical")
    obs_steps = [
        _step(1, RelationType.CONNECTS_TO, FactKind.OBSERVED_FACT, 0.90),
        _step(2, RelationType.CAN_ADMINISTER, FactKind.OBSERVED_FACT, 0.90),
    ]
    inf_steps = [
        _step(1, RelationType.CONNECTS_TO, FactKind.INFERRED_RELATIONSHIP, 0.90, missing_corr=True),
        _step(2, RelationType.CAN_ADMINISTER, FactKind.OBSERVED_FACT, 0.90),
    ]
    obs_score = score_attack_path(
        start_node=s_node, target_node=t_node, steps=obs_steps, path_nodes=[s_node, t_node]
    )
    inf_score = score_attack_path(
        start_node=s_node,
        target_node=_node("crown", crown=True, crit="critical", stale=True),
        steps=inf_steps,
        path_nodes=[s_node, _node("crown", crown=True, crit="critical", stale=True)],
    )
    assert inf_score.evidence_confidence < obs_score.evidence_confidence
    assert inf_score.missing_data_penalty < obs_score.missing_data_penalty
    assert inf_score.priority_score < obs_score.priority_score
