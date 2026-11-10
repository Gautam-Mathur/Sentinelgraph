from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from app.domain.graph_engine import build_networkx_graph, find_attack_paths
from app.domain.models import (
    GraphEdge,
    GraphNode,
    PathSearchConstraints,
    RelationType,
    RemediationTransformType,
)


@dataclass(frozen=True)
class RemediationTransform:
    transform_type: RemediationTransformType
    relationship_id: str | None = None
    source_node_key: str | None = None
    target_node_key: str | None = None
    identity_id: str | None = None
    asset_id: str | None = None
    cve_id: str | None = None
    new_confidence: float | None = None
    ports: list[int] | None = None
    notes: str = ""


@dataclass
class SimulationMetrics:
    total_paths: int
    reachable_critical_assets: int
    reachable_critical_asset_labels: list[str]
    highest_path_score: float
    high_confidence_paths: int
    key_bridge_nodes: list[dict[str, Any]]


@dataclass
class SimulationComparison:
    baseline: SimulationMetrics
    modelled: SimulationMetrics
    delta_summary: dict[str, Any]
    applied_transforms: list[dict[str, Any]]
    is_modelled_only: bool = True
    disclaimer: str = (
        "Modelled impact computed in an isolated sandbox graph copy. "
        "Not verified remediation on live systems."
    )


def _summarize_metrics(
    nodes: list[GraphNode],
    edges: list[GraphEdge],
    constraints: PathSearchConstraints,
) -> SimulationMetrics:
    graph, build_stats = build_networkx_graph(nodes, edges, as_of=constraints.as_of)
    search_out = find_attack_paths(graph, constraints)
    node_map = {n.key: n for n in nodes}

    critical_targets: set[str] = set()
    high_conf_count = 0
    highest_score = 0.0
    for path in search_out.paths:
        highest_score = max(highest_score, path.priority_score)
        if path.evidence_confidence >= 0.7:
            high_conf_count += 1
        tkey = f"{path.target_node_kind}:{path.target_node_id}"
        tnode = node_map.get(tkey)
        if tnode and (tnode.criticality == "critical" or tnode.is_crown_jewel):
            critical_targets.add(tnode.label)

    return SimulationMetrics(
        total_paths=len(search_out.paths),
        reachable_critical_assets=len(critical_targets),
        reachable_critical_asset_labels=sorted(critical_targets),
        highest_path_score=round(highest_score, 2),
        high_confidence_paths=high_conf_count,
        key_bridge_nodes=build_stats.top_bridge_nodes[:5],
    )


def apply_sandbox_transforms(
    nodes: list[GraphNode],
    edges: list[GraphEdge],
    transforms: list[RemediationTransform],
    min_confidence_threshold: float = 0.2,
) -> tuple[list[GraphNode], list[GraphEdge], list[dict[str, Any]]]:
    sandbox_nodes = deepcopy(nodes)
    sandbox_edges = deepcopy(edges)
    applied_log: list[dict[str, Any]] = []

    for tx in transforms:
        affected = 0
        if tx.transform_type == RemediationTransformType.REMOVE_RELATIONSHIP:
            before = len(sandbox_edges)
            sandbox_edges = [e for e in sandbox_edges if e.edge_id != tx.relationship_id]
            affected = before - len(sandbox_edges)

        elif tx.transform_type == RemediationTransformType.DOWNGRADE_RELATIONSHIP:
            new_conf = tx.new_confidence if tx.new_confidence is not None else 0.15
            kept: list[GraphEdge] = []
            for e in sandbox_edges:
                if e.edge_id == tx.relationship_id:
                    e.confidence = max(0.05, min(1.0, new_conf))
                    affected += 1
                    if e.confidence >= min_confidence_threshold:
                        kept.append(e)
                else:
                    kept.append(e)
            sandbox_edges = kept

        elif tx.transform_type == RemediationTransformType.DISABLE_ROLE:
            kept = []
            for e in sandbox_edges:
                matches_identity = tx.identity_id and (
                    e.source_id == tx.identity_id or e.target_id == tx.identity_id
                )
                matches_rel = tx.relationship_id and e.edge_id == tx.relationship_id
                is_role_edge = e.relation_type in (
                    RelationType.HAS_ROLE,
                    RelationType.MEMBER_OF,
                    RelationType.CAN_ADMINISTER,
                )
                if (matches_identity and is_role_edge) or matches_rel:
                    affected += 1
                    continue
                kept.append(e)
            sandbox_edges = kept

        elif tx.transform_type == RemediationTransformType.ROTATE_SERVICE_IDENTITY:
            kept = []
            for e in sandbox_edges:
                matches_identity = tx.identity_id and (
                    e.source_id == tx.identity_id or e.target_id == tx.identity_id
                )
                matches_rel = tx.relationship_id and e.edge_id == tx.relationship_id
                if (matches_identity and e.relation_type in (RelationType.HAS_ROLE, RelationType.TRUSTS)) or matches_rel:
                    affected += 1
                    continue
                kept.append(e)
            sandbox_edges = kept

        elif tx.transform_type == RemediationTransformType.SEGMENT_NETWORK:
            kept = []
            for e in sandbox_edges:
                if e.relation_type not in (RelationType.CONNECTS_TO, RelationType.EXPOSES):
                    kept.append(e)
                    continue
                src_match = not tx.source_node_key or e.source_key == tx.source_node_key
                tgt_match = not tx.target_node_key or e.target_key == tx.target_node_key
                rel_match = not tx.relationship_id or e.edge_id == tx.relationship_id
                if (tx.relationship_id and rel_match) or (
                    (tx.source_node_key or tx.target_node_key) and src_match and tgt_match
                ):
                    affected += 1
                    continue
                kept.append(e)
            sandbox_edges = kept

        elif tx.transform_type == RemediationTransformType.PATCH_VULNERABILITY:
            for n in sandbox_nodes:
                if tx.asset_id and n.node_id == tx.asset_id and n.open_cve_count > 0:
                    n.open_cve_count = max(0, n.open_cve_count - 1)
                    affected += 1
            for e in sandbox_edges:
                linked_cve = e.edge_metadata.get("requires_cve")
                if tx.cve_id and linked_cve == tx.cve_id:
                    e.confidence = max(0.1, round(e.confidence * 0.25, 3))
                    affected += 1
            sandbox_edges = [e for e in sandbox_edges if e.confidence >= min_confidence_threshold]

        applied_log.append(
            {
                "transform_type": tx.transform_type.value,
                "affected_elements": affected,
                "notes": tx.notes,
            }
        )

    return sandbox_nodes, sandbox_edges, applied_log


def simulate_remediation(
    *,
    nodes: list[GraphNode],
    edges: list[GraphEdge],
    constraints: PathSearchConstraints,
    transforms: list[RemediationTransform],
) -> SimulationComparison:
    baseline = _summarize_metrics(nodes, edges, constraints)
    sb_nodes, sb_edges, applied_log = apply_sandbox_transforms(
        nodes, edges, transforms, min_confidence_threshold=constraints.min_confidence
    )
    modelled = _summarize_metrics(sb_nodes, sb_edges, constraints)

    delta_summary = {
        "paths_eliminated": baseline.total_paths - modelled.total_paths,
        "critical_assets_unlinked": (
            baseline.reachable_critical_assets - modelled.reachable_critical_assets
        ),
        "highest_score_reduction": round(
            baseline.highest_path_score - modelled.highest_path_score, 2
        ),
        "high_confidence_paths_reduced": (
            baseline.high_confidence_paths - modelled.high_confidence_paths
        ),
    }

    return SimulationComparison(
        baseline=baseline,
        modelled=modelled,
        delta_summary=delta_summary,
        applied_transforms=applied_log,
    )
