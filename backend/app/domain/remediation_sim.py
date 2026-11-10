from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from app.domain.graph_engine import build_networkx_graph, find_attack_paths, verify_reachability
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
    # Legacy field: number of enumerated candidates returned, not necessarily the graph's total paths.
    total_paths: int
    reachable_critical_assets: int
    reachable_critical_asset_labels: list[str]
    highest_path_score: float
    high_confidence_paths: int
    key_bridge_nodes: list[dict[str, Any]]
    path_search_complete: bool
    path_search_truncation_reason: str | None
    path_count_semantics: str
    reachability_status: str
    reachable_within_max_hops: bool
    reachable_unbounded: bool
    confirmed_reachable_unbounded: bool
    reachability_verification_complete: bool
    reachable_target_keys: list[str]
    witness_path_edge_ids: list[str]
    conditional_witness_edge_ids: list[str]
    reachability_examined_nodes: int
    reachability_examined_edges: int


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
    reachability = verify_reachability(graph, constraints)
    node_map = {n.key: n for n in nodes}

    critical_targets = {
        node_map[key].label
        for key in reachability.reachable_target_keys
        if key in node_map
        and (node_map[key].criticality == "critical" or node_map[key].is_crown_jewel)
    }
    high_conf_count = 0
    highest_score = 0.0
    for path in search_out.paths:
        highest_score = max(highest_score, path.priority_score)
        if path.evidence_confidence >= 0.7:
            high_conf_count += 1

    return SimulationMetrics(
        total_paths=len(search_out.paths),
        reachable_critical_assets=len(critical_targets),
        reachable_critical_asset_labels=sorted(critical_targets),
        highest_path_score=round(highest_score, 2),
        high_confidence_paths=high_conf_count,
        key_bridge_nodes=build_stats.top_bridge_nodes[:5],
        path_search_complete=not search_out.is_truncated,
        path_search_truncation_reason=search_out.truncation_reason,
        path_count_semantics="returned_candidate_count_not_total",
        reachability_status=reachability.status,
        reachable_within_max_hops=reachability.reachable_within_max_hops,
        reachable_unbounded=reachability.reachable_unbounded,
        confirmed_reachable_unbounded=reachability.confirmed_reachable_unbounded,
        reachability_verification_complete=reachability.complete,
        reachable_target_keys=reachability.reachable_target_keys,
        witness_path_edge_ids=reachability.witness_path_edge_ids,
        conditional_witness_edge_ids=reachability.conditional_witness_edge_ids,
        reachability_examined_nodes=reachability.examined_nodes,
        reachability_examined_edges=reachability.examined_edges,
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
        status = "applied"
        reason: str | None = None
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
            if not tx.cve_id:
                status = "not_applied"
                reason = "cve_id_required: a vulnerability must be identified before it can be patched."
            else:
                cve = tx.cve_id.upper()
                active_states = {"open", "unpatched", "vulnerable", "confirmed"}

                for node in sandbox_nodes:
                    if tx.asset_id is not None and node.node_id != tx.asset_id:
                        continue
                    node_states = node.metadata.get("vulnerability_status")
                    state_map = (
                        node_states if isinstance(node_states, dict) else {}
                    )
                    matching_key = next(
                        (key for key in state_map if str(key).upper() == cve),
                        None,
                    )
                    remediated_values = node.metadata.get("remediated_cves")
                    remediated_list = (
                        remediated_values if isinstance(remediated_values, list) else []
                    )
                    already_recorded = any(
                        str(value).upper() == cve for value in remediated_list
                    )
                    if matching_key is None and not already_recorded:
                        continue

                    states = dict(state_map)
                    prior_state = (
                        str(states.get(matching_key)).lower()
                        if matching_key is not None
                        else "patched"
                    )
                    states[cve] = "patched"
                    node.metadata["vulnerability_status"] = states
                    remediated = list(remediated_list)
                    if not already_recorded:
                        remediated.append(cve)
                    node.metadata["remediated_cves"] = remediated
                    if prior_state in active_states and node.open_cve_count > 0:
                        count_map = node.metadata.get("vulnerability_finding_counts")
                        raw_count = (
                            count_map.get(matching_key or cve, 1)
                            if isinstance(count_map, dict)
                            else 1
                        )
                        try:
                            finding_count = max(1, int(raw_count))
                        except (TypeError, ValueError):
                            finding_count = 1
                        node.open_cve_count = max(0, node.open_cve_count - finding_count)
                        if isinstance(count_map, dict):
                            updated_counts = dict(count_map)
                            updated_counts[cve] = 0
                            node.metadata["vulnerability_finding_counts"] = updated_counts
                    affected += 1

                for edge in sandbox_edges:
                    linked_cve = edge.edge_metadata.get("requires_cve")
                    if not isinstance(linked_cve, str) or linked_cve.upper() != cve:
                        continue
                    if tx.asset_id:
                        required_scope = str(
                            edge.edge_metadata.get("requires_cve_on") or ""
                        ).lower()
                        if required_scope == "source" and tx.asset_id != edge.source_id:
                            continue
                        if required_scope == "target" and tx.asset_id != edge.target_id:
                            continue
                        if required_scope not in {"source", "target"} and tx.asset_id not in (
                            edge.source_id,
                            edge.target_id,
                        ):
                            continue
                    raw_states = edge.edge_metadata.get("vulnerability_status")
                    state_map = raw_states if isinstance(raw_states, dict) else {}
                    states = dict(state_map)
                    states[cve] = "patched"
                    edge.edge_metadata["vulnerability_status"] = states
                    raw_remediated = edge.edge_metadata.get("remediated_cves")
                    remediated = (
                        list(raw_remediated) if isinstance(raw_remediated, list) else []
                    )
                    if not any(str(value).upper() == cve for value in remediated):
                        remediated.append(cve)
                    edge.edge_metadata["remediated_cves"] = remediated
                    affected += 1

                if affected == 0:
                    status = "not_applied"
                    reason = (
                        "no_matching_vulnerability_reference: the CVE was not present "
                        "in the scoped asset findings or a matching requires_cve relationship."
                    )

        applied_log.append(
            {
                "transform_type": tx.transform_type.value,
                "affected_elements": affected,
                "status": status,
                "reason": reason,
                "asset_id": tx.asset_id,
                "cve_id": tx.cve_id,
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

    sampled_paths_eliminated = baseline.total_paths - modelled.total_paths
    delta_summary = {
        # Backward-compatible metric. This is a delta over returned candidates only.
        "paths_eliminated": sampled_paths_eliminated,
        "sampled_paths_eliminated": sampled_paths_eliminated,
        "paths_eliminated_is_complete": (
            baseline.path_search_complete and modelled.path_search_complete
        ),
        "possible_reachability_eliminated": (
            baseline.reachable_unbounded and not modelled.reachable_unbounded
        ),
        "possible_residual_reachability": modelled.reachable_unbounded,
        "confirmed_residual_reachability": modelled.confirmed_reachable_unbounded,
        "reachability_verification_complete": (
            baseline.reachability_verification_complete
            and modelled.reachability_verification_complete
        ),
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
