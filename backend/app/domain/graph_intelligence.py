from dataclasses import replace
from itertools import combinations
from typing import Any

from app.domain.graph_engine import (
    GraphBuildStats,
    build_networkx_graph,
    find_attack_paths,
    verify_reachability,
)
from app.domain.models import (
    AttackPathResult,
    FactKind,
    GraphEdge,
    GraphNode,
    PathSearchConstraints,
    RelationType,
    RemediationTransformType,
)
from app.domain.preconditions import evaluate_edge_preconditions, precondition_summary
from app.domain.remediation_sim import (
    RemediationTransform,
    apply_sandbox_transforms,
    simulate_remediation,
)


def _safe_ports(raw_ports: Any) -> list[int] | None:
    if not isinstance(raw_ports, list):
        return None
    out: list[int] = []
    for p in raw_ports:
        try:
            val = int(p)
        except (TypeError, ValueError):
            continue
        if 1 <= val <= 65535:
            out.append(val)
    return out or None


def recommended_transform_for_edge(
    edge: GraphEdge,
    node_map: dict[str, GraphNode],
) -> tuple[dict[str, Any], str, int]:
    """Map a graph edge to the most idiomatic remediation transform, label, and effort weight."""
    src_lbl = node_map[edge.source_key].label if edge.source_key in node_map else edge.source_key
    tgt_lbl = node_map[edge.target_key].label if edge.target_key in node_map else edge.target_key

    if edge.relation_type in (RelationType.CONNECTS_TO, RelationType.EXPOSES):
        ports_list = _safe_ports(edge.edge_metadata.get("ports"))
        note = f"Segment network traffic ({edge.relation_type.value}) from {src_lbl} to {tgt_lbl}"[:450]
        tx: dict[str, Any] = {
            "transform_type": RemediationTransformType.SEGMENT_NETWORK.value,
            "relationship_id": edge.edge_id,
            "ports": ports_list,
            "notes": note,
        }
        return tx, f"Segment {src_lbl} -> {tgt_lbl}", 2

    if edge.relation_type in (RelationType.MEMBER_OF, RelationType.CAN_ADMINISTER):
        note = f"Revoke standing privilege ({edge.relation_type.value}) from {src_lbl} to {tgt_lbl}"[:450]
        tx = {
            "transform_type": RemediationTransformType.DISABLE_ROLE.value,
            "relationship_id": edge.edge_id,
            "notes": note,
        }
        return tx, f"Revoke {edge.relation_type.value}: {src_lbl} -> {tgt_lbl}", 1

    if edge.relation_type in (RelationType.HAS_ROLE, RelationType.TRUSTS):
        note = (
            f"Rotate / isolate identity or trust edge ({edge.relation_type.value}) "
            f"{src_lbl} -> {tgt_lbl}"
        )[:450]
        tx = {
            "transform_type": RemediationTransformType.ROTATE_SERVICE_IDENTITY.value,
            "relationship_id": edge.edge_id,
            "notes": note,
        }
        action_verb = "Isolate Trust" if edge.relation_type == RelationType.TRUSTS else "Rotate Identity"
        return tx, f"{action_verb}: {src_lbl} -> {tgt_lbl}", 2

    note = f"Sever {edge.relation_type.value} dependency between {src_lbl} and {tgt_lbl}"[:450]
    tx = {
        "transform_type": RemediationTransformType.REMOVE_RELATIONSHIP.value,
        "relationship_id": edge.edge_id,
        "notes": note,
    }
    return tx, f"Sever {edge.relation_type.value}: {src_lbl} -> {tgt_lbl}", 3


def _dict_to_domain_transform(spec: dict[str, Any]) -> RemediationTransform:
    return RemediationTransform(
        transform_type=RemediationTransformType(str(spec["transform_type"])),
        relationship_id=spec.get("relationship_id"),
        source_node_key=spec.get("source_node_key"),
        target_node_key=spec.get("target_node_key"),
        identity_id=spec.get("identity_id"),
        asset_id=spec.get("asset_id"),
        cve_id=spec.get("cve_id"),
        new_confidence=spec.get("new_confidence"),
        ports=spec.get("ports"),
        notes=str(spec.get("notes", "")),
    )


def _extract_path_edge_ids(path: AttackPathResult) -> list[str]:
    return [s.relationship_id for s in path.steps]


def _extract_path_node_keys(path: AttackPathResult) -> list[str]:
    if not path.steps:
        return [f"{path.start_node_kind}:{path.start_node_id}"]
    keys = [f"{path.steps[0].from_node_kind}:{path.steps[0].from_node_id}"]
    for st in path.steps:
        keys.append(f"{st.to_node_kind}:{st.to_node_id}")
    return keys


def _paths_covered_without_edges(
    nodes: list[GraphNode],
    edges: list[GraphEdge],
    constraints: PathSearchConstraints,
    excluded_edge_ids: set[str],
) -> list[AttackPathResult]:
    filtered_edges = [e for e in edges if e.edge_id not in excluded_edge_ids]
    graph, _ = build_networkx_graph(nodes, filtered_edges, as_of=constraints.as_of)
    return find_attack_paths(graph, constraints).paths


def _verify_and_augment_cut_set(
    *,
    nodes: list[GraphNode],
    edges: list[GraphEdge],
    constraints: PathSearchConstraints,
    initial_edge_ids: list[str],
    edge_map: dict[str, GraphEdge],
    node_map: dict[str, GraphNode],
    baseline_paths: list[AttackPathResult],
) -> dict[str, Any]:
    """Run real sandbox simulation & iteratively patch any unmasked deeper bypasses."""
    chosen_ids = list(dict.fromkeys(initial_edge_ids))
    transforms_dicts: list[dict[str, Any]] = []
    for eid in chosen_ids:
        e_obj = edge_map.get(eid)
        if e_obj is not None:
            tx_dict, _, _ = recommended_transform_for_edge(e_obj, node_map)
            transforms_dicts.append(tx_dict)

    domain_txs = [_dict_to_domain_transform(t) for t in transforms_dicts]
    sim = simulate_remediation(
        nodes=nodes,
        edges=edges,
        constraints=constraints,
        transforms=domain_txs,
    )

    # A witness-path BFS, not the bounded candidate list, drives residual-route augmentation.
    # The guard remains intentionally bounded; any residual after it is reported as partial.
    rounds = 0
    while sim.modelled.reachable_unbounded and rounds < 2 and len(chosen_ids) < 6:
        witness_edges = [
            eid
            for eid in sim.modelled.witness_path_edge_ids
            if eid in edge_map and eid not in chosen_ids
        ]
        if not witness_edges:
            break
        best_extra = min(
            witness_edges,
            key=lambda eid: (
                recommended_transform_for_edge(edge_map[eid], node_map)[2],
                eid,
            ),
        )
        chosen_ids.append(best_extra)
        tx_extra, _, _ = recommended_transform_for_edge(edge_map[best_extra], node_map)
        transforms_dicts.append(tx_extra)
        domain_txs = [_dict_to_domain_transform(t) for t in transforms_dicts]
        sim = simulate_remediation(
            nodes=nodes,
            edges=edges,
            constraints=constraints,
            transforms=domain_txs,
        )
        rounds += 1

    # Prune any now-redundant transforms while maintaining identical residual_paths
    if len(chosen_ids) > 1:
        idx = len(chosen_ids) - 1
        while idx >= 0 and len(chosen_ids) > 1:
            trial_ids = [x for j, x in enumerate(chosen_ids) if j != idx]
            trial_txs = [
                _dict_to_domain_transform(recommended_transform_for_edge(edge_map[eid], node_map)[0])
                for eid in trial_ids
                if eid in edge_map
            ]
            if trial_txs:
                trial_sim = simulate_remediation(
                    nodes=nodes,
                    edges=edges,
                    constraints=constraints,
                    transforms=trial_txs,
                )
                reachability_no_worse = (
                    not trial_sim.modelled.reachable_unbounded
                    or sim.modelled.reachable_unbounded
                )
                if (
                    reachability_no_worse
                    and trial_sim.modelled.total_paths <= sim.modelled.total_paths
                ):
                    chosen_ids = trial_ids
                    transforms_dicts = [
                        recommended_transform_for_edge(edge_map[eid], node_map)[0]
                        for eid in chosen_ids
                        if eid in edge_map
                    ]
                    sim = trial_sim
            idx -= 1

    effort_score = 0
    steps_summary: list[str] = []
    for eid in chosen_ids:
        e_obj = edge_map.get(eid)
        if e_obj is None:
            continue
        _, lbl, eff = recommended_transform_for_edge(e_obj, node_map)
        effort_score += eff
        hits = sum(1 for p in baseline_paths if eid in _extract_path_edge_ids(p))
        steps_summary.append(f"{lbl} (breaks {hits}/{len(baseline_paths)} active paths)")

    base_total = sim.baseline.total_paths
    eliminated = sim.delta_summary["paths_eliminated"]
    coverage_pct = round((eliminated / base_total) * 100.0, 1) if base_total > 0 else 0.0

    model_cut_verified = (
        sim.modelled.reachability_verification_complete
        and not sim.modelled.reachable_unbounded
    )
    if model_cut_verified and len(chosen_ids) == 1:
        label = f"Single Model-Verified Chokepoint: {recommended_transform_for_edge(edge_map[chosen_ids[0]], node_map)[1]}"
        rationale = (
            "Independent multi-source BFS found no remaining possible route in the sandbox graph "
            "after this transform, under the configured scope and transition-precondition policy. "
            "This verifies the model only, not a live-system remediation."
        )
    elif model_cut_verified:
        label = f"{len(chosen_ids)}-Edge Model-Verified Candidate Cut"
        rationale = (
            "Independent multi-source BFS found no remaining possible route in the sandbox graph "
            "after these transforms. The candidate search is bounded and does not prove global "
            "minimum cut cardinality or validate a live-system change."
        )
    else:
        label = f"{len(chosen_ids)}-Edge Partial Candidate Cut ({coverage_pct}% sampled paths eliminated)"
        rationale = (
            f"Eliminates {eliminated} of {base_total} enumerated candidate paths, but BFS still "
            f"finds a possible residual route ({sim.modelled.reachability_status})."
        )

    return {
        "cut_key": tuple(sorted(chosen_ids)),
        "label": label,
        "cut_size": len(chosen_ids),
        "effort_score": effort_score,
        "baseline_paths": base_total,
        "paths_broken": eliminated,
        "residual_paths": sim.modelled.total_paths,
        "residual_paths_semantics": "enumerated_candidate_count_not_total",
        "reachability_status": sim.modelled.reachability_status,
        "reachable_unbounded": sim.modelled.reachable_unbounded,
        "reachable_within_max_hops": sim.modelled.reachable_within_max_hops,
        "confirmed_reachable_unbounded": sim.modelled.confirmed_reachable_unbounded,
        "reachability_verification_complete": sim.modelled.reachability_verification_complete,
        "witness_path_edge_ids": sim.modelled.witness_path_edge_ids,
        "conditional_witness_edge_ids": sim.modelled.conditional_witness_edge_ids,
        "path_search_complete": sim.modelled.path_search_complete,
        "path_search_truncation_reason": sim.modelled.path_search_truncation_reason,
        "verification_status": (
            "MODEL_VERIFIED_CUT" if model_cut_verified
            else "PARTIAL_CUT" if sim.modelled.reachable_unbounded
            else "INDETERMINATE"
        ),
        "minimum_cut_proven": False,
        "coverage_pct": coverage_pct,
        "critical_assets_unlinked": sim.delta_summary["critical_assets_unlinked"],
        "highest_score_reduction": sim.delta_summary["highest_score_reduction"],
        "edge_ids": chosen_ids,
        "steps_summary": steps_summary,
        "transforms": transforms_dicts,
        "rationale": rationale,
    }


def _solve_candidate_cut_sets(
    *,
    nodes: list[GraphNode],
    edges: list[GraphEdge],
    constraints: PathSearchConstraints,
    baseline_paths: list[AttackPathResult],
    edge_map: dict[str, GraphEdge],
    node_map: dict[str, GraphNode],
    max_sets: int = 5,
) -> list[dict[str, Any]]:
    if not baseline_paths:
        # Candidate enumeration can time out or hit max_candidates before yielding
        # a single path. Do not suppress remediation suggestions when independent
        # BFS still proves that a possible route exists.
        baseline_graph, _ = build_networkx_graph(nodes, edges, as_of=constraints.as_of)
        baseline_reachability = verify_reachability(baseline_graph, constraints)
        if not baseline_reachability.reachable_unbounded:
            return []
        witness_ids = [
            edge_id for edge_id in baseline_reachability.witness_path_edge_ids
            if edge_id in edge_map
        ]
        candidate_sets = [[edge_id] for edge_id in witness_ids[:max_sets]]
        verified_cuts: list[dict[str, Any]] = []
        for raw_set in candidate_sets:
            verified = _verify_and_augment_cut_set(
                nodes=nodes,
                edges=edges,
                constraints=constraints,
                initial_edge_ids=raw_set,
                edge_map=edge_map,
                node_map=node_map,
                baseline_paths=[],
            )
            verified_cuts.append(verified)
        verified_cuts.sort(
            key=lambda cut: (
                cut["reachable_unbounded"],
                cut["cut_size"],
                cut["effort_score"],
                cut["cut_key"],
            )
        )
        results: list[dict[str, Any]] = []
        for idx, cut in enumerate(verified_cuts[:max_sets], start=1):
            cut_out = {key: value for key, value in cut.items() if key != "cut_key"}
            cut_out["id"] = f"cut-{idx}"
            cut_out["baseline_reachability_witness"] = baseline_reachability.witness_path_edge_ids
            cut_out["baseline_reachability_verification_complete"] = baseline_reachability.complete
            cut_out["path_search_complete"] = False
            results.append(cut_out)
        return results

    num_paths = len(baseline_paths)
    all_mask = (1 << num_paths) - 1

    edge_masks: dict[str, int] = {}
    edge_risk_sum: dict[str, float] = {}
    for p_idx, path in enumerate(baseline_paths):
        bit = 1 << p_idx
        for st in path.steps:
            eid = st.relationship_id
            if eid not in edge_map:
                continue
            prev = edge_masks.get(eid, 0)
            if not (prev & bit):
                edge_masks[eid] = prev | bit
                edge_risk_sum[eid] = edge_risk_sum.get(eid, 0.0) + path.priority_score

    if not edge_masks:
        return []

    cand_edges = sorted(
        edge_masks.keys(),
        key=lambda eid: (
            -edge_masks[eid].bit_count(),
            -edge_risk_sum.get(eid, 0.0),
            recommended_transform_for_edge(edge_map[eid], node_map)[2],
            eid,
        ),
    )[:30]

    candidate_sets: list[list[str]] = []

    # 1. Size-1 singleton chokepoints covering all discovered paths
    singletons: set[str] = set()
    for eid in cand_edges:
        if edge_masks[eid] == all_mask:
            candidate_sets.append([eid])
            singletons.add(eid)

    # 2. Non-redundant size-2 hitting sets (excluding singletons so true multi-branch cuts surface too)
    non_singletons = [eid for eid in cand_edges if eid not in singletons]
    size2_pairs: list[tuple[int, float, list[str]]] = []
    for e_a, e_b in combinations(non_singletons[:20], 2):
        if (edge_masks[e_a] | edge_masks[e_b]) == all_mask:
            eff = (
                recommended_transform_for_edge(edge_map[e_a], node_map)[2]
                + recommended_transform_for_edge(edge_map[e_b], node_map)[2]
            )
            overlap_risk = edge_risk_sum.get(e_a, 0.0) + edge_risk_sum.get(e_b, 0.0)
            size2_pairs.append((eff, -overlap_risk, [e_a, e_b]))
    size2_pairs.sort(key=lambda item: (item[0], item[1], item[2]))
    for _, _, pair in size2_pairs[:4]:
        candidate_sets.append(pair)

    # 3. Greedy hitting set fallback for cuts requiring >=3 edges (or without singletons)
    if non_singletons and not size2_pairs:
        uncovered = all_mask
        greedy_cut: list[str] = []
        pool = list(non_singletons)
        while uncovered and pool and len(greedy_cut) < 6:
            best_e = max(
                pool,
                key=lambda eid: (
                    (edge_masks[eid] & uncovered).bit_count(),
                    -recommended_transform_for_edge(edge_map[eid], node_map)[2],
                    edge_risk_sum.get(eid, 0.0),
                ),
            )
            gain = edge_masks[best_e] & uncovered
            if gain == 0:
                break
            greedy_cut.append(best_e)
            uncovered &= ~gain
            pool.remove(best_e)
        if greedy_cut and uncovered == 0:
            candidate_sets.append(greedy_cut)

    # 4. Also allow highest-impact partial edge if graph paths could not be fully covered
    if not candidate_sets and cand_edges:
        candidate_sets.append([cand_edges[0]])

    verified_cuts: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, ...]] = set()
    for raw_set in candidate_sets:
        if len(verified_cuts) >= max_sets + 2:
            break
        verified = _verify_and_augment_cut_set(
            nodes=nodes,
            edges=edges,
            constraints=constraints,
            initial_edge_ids=raw_set,
            edge_map=edge_map,
            node_map=node_map,
            baseline_paths=baseline_paths,
        )
        ckey = tuple(verified["cut_key"])
        if ckey in seen_keys:
            continue
        seen_keys.add(ckey)
        verified_cuts.append(verified)

    verified_cuts.sort(
        key=lambda c: (
            c["residual_paths"],
            c["cut_size"],
            c["effort_score"],
            -c["paths_broken"],
            c["cut_key"],
        )
    )
    results: list[dict[str, Any]] = []
    for idx, c in enumerate(verified_cuts[:max_sets], start=1):
        c_out = {k: v for k, v in c.items() if k != "cut_key"}
        c_out["id"] = f"cut-{idx}"
        results.append(c_out)
    return results


def _run_assessment_sensitivity_matrix(
    *,
    nodes: list[GraphNode],
    edges: list[GraphEdge],
    constraints: PathSearchConstraints,
    baseline_paths: list[AttackPathResult],
) -> list[dict[str, Any]]:
    base_count = len(baseline_paths)
    base_max = max((p.priority_score for p in baseline_paths), default=0.0)
    scenarios: list[dict[str, Any]] = []

    # 1. Exclude inferred relationships
    c_obs = replace(constraints, include_inferred=False)
    g_obs, _ = build_networkx_graph(nodes, edges, as_of=constraints.as_of)
    obs_paths = find_attack_paths(g_obs, c_obs).paths
    obs_targets = sorted({p.target_node_label for p in obs_paths})
    obs_max = max((p.priority_score for p in obs_paths), default=0.0)
    scenarios.append(
        {
            "scenario_id": "observed_only",
            "label": "Exclude Inferred Heuristic Edges",
            "assumption_tested": "Inferred edges represent real traversable trust or delegation links.",
            "baseline_paths": base_count,
            "remaining_paths": len(obs_paths),
            "paths_eliminated": base_count - len(obs_paths),
            "highest_score_remaining": round(obs_max, 2),
            "score_reduction": round(base_max - obs_max, 2),
            "critical_targets_remaining": obs_targets,
            "verdict": (
                "All active paths depend on inferred heuristics; direct observation refutes them."
                if base_count > 0 and len(obs_paths) == 0
                else (
                    f"Drops {base_count - len(obs_paths)} of {base_count} path(s); "
                    f"{len(obs_paths)} purely observed path(s) remain."
                    if base_count > len(obs_paths)
                    else "No inferred edges sit on the active paths."
                )
            ),
        }
    )

    # 2. High-confidence threshold (>= 0.75)
    c_hc = replace(constraints, min_confidence=max(0.75, constraints.min_confidence))
    hc_paths = find_attack_paths(g_obs, c_hc).paths
    hc_targets = sorted({p.target_node_label for p in hc_paths})
    hc_max = max((p.priority_score for p in hc_paths), default=0.0)
    scenarios.append(
        {
            "scenario_id": "high_confidence_only",
            "label": "Require >= 75% Edge Confidence",
            "assumption_tested": "Low/moderate confidence edges (<0.75) remain valid in runtime state.",
            "baseline_paths": base_count,
            "remaining_paths": len(hc_paths),
            "paths_eliminated": base_count - len(hc_paths),
            "highest_score_remaining": round(hc_max, 2),
            "score_reduction": round(base_max - hc_max, 2),
            "critical_targets_remaining": hc_targets,
            "verdict": (
                f"{base_count - len(hc_paths)} path(s) drop below 75% edge evidence confidence."
                if base_count > len(hc_paths)
                else "All active path edges meet >= 75% evidence confidence."
            ),
        }
    )

    # 3. Uncorroborated ACLs blocked
    uncorr_edges = [
        e
        for e in edges
        if not e.is_suppressed
        and e.relation_type in (RelationType.CONNECTS_TO, RelationType.EXPOSES)
        and not e.edge_metadata.get("acl_rule")
    ]
    if uncorr_edges:
        uncorr_ids = {e.edge_id for e in uncorr_edges}
        acl_rem = _paths_covered_without_edges(nodes, edges, constraints, uncorr_ids)
        acl_max = max((p.priority_score for p in acl_rem), default=0.0)
        scenarios.append(
            {
                "scenario_id": "uncorroborated_acls_blocked",
                "label": "Assume Missing-ACL Network Edges Are Firewalled",
                "assumption_tested": f"{len(uncorr_edges)} network edge(s) lack explicit ACL rule IDs.",
                "baseline_paths": base_count,
                "remaining_paths": len(acl_rem),
                "paths_eliminated": base_count - len(acl_rem),
                "highest_score_remaining": round(acl_max, 2),
                "score_reduction": round(base_max - acl_max, 2),
                "critical_targets_remaining": sorted({p.target_node_label for p in acl_rem}),
                "verdict": (
                    f"Blocking {len(uncorr_edges)} uncorroborated network edge(s) eliminates "
                    f"{base_count - len(acl_rem)} path(s)."
                ),
            }
        )

    # 4. CVE-contingent transitions patched
    cves = sorted(
        {
            str(e.edge_metadata["requires_cve"])
            for e in edges
            if not e.is_suppressed and e.edge_metadata.get("requires_cve")
        }
    )
    if cves:
        cve_txs = [
            RemediationTransform(
                transform_type=RemediationTransformType.PATCH_VULNERABILITY,
                cve_id=cve,
                notes=f"Model patching {cve}",
            )
            for cve in cves
        ]
        sim_cve = simulate_remediation(
            nodes=nodes,
            edges=edges,
            constraints=constraints,
            transforms=cve_txs,
        )
        scenarios.append(
            {
                "scenario_id": "cve_edges_patched",
                "label": f"Patch Referenced Edge CVEs ({', '.join(cves[:3])})",
                "assumption_tested": (
                    "CVE-contingent edges represent exploitable footholds (unproven invariant)."
                ),
                "baseline_paths": sim_cve.baseline.total_paths,
                "remaining_paths": sim_cve.modelled.total_paths,
                "paths_eliminated": sim_cve.delta_summary["paths_eliminated"],
                "highest_score_remaining": sim_cve.modelled.highest_path_score,
                "score_reduction": sim_cve.delta_summary["highest_score_reduction"],
                "critical_targets_remaining": sim_cve.modelled.reachable_critical_asset_labels,
                "verdict": (
                    f"Patching {', '.join(cves[:3])} drops peak score by "
                    f"-{sim_cve.delta_summary['highest_score_reduction']} and eliminates "
                    f"{sim_cve.delta_summary['paths_eliminated']} path(s) below confidence floor."
                ),
            }
        )

    return scenarios


def analyze_assessment_intelligence(
    *,
    nodes: list[GraphNode],
    edges: list[GraphEdge],
    constraints: PathSearchConstraints,
    persisted_paths_meta: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Compute structural causality, edge blast radius, cut-sets, and sensitivity counterfactuals."""
    # Ensure cut-set computation evaluates a generous candidate bound matching simulation metrics
    analysis_constraints = replace(constraints, top_k=max(constraints.top_k, 50))
    stats: GraphBuildStats
    nx_graph, stats = build_networkx_graph(nodes, edges, as_of=constraints.as_of)
    search_out = find_attack_paths(nx_graph, analysis_constraints)
    baseline_paths = search_out.paths
    baseline_reachability = verify_reachability(nx_graph, analysis_constraints)

    node_map = {n.key: n for n in nodes}
    edge_map: dict[str, GraphEdge] = {}
    for _, _, _, data in nx_graph.edges(keys=True, data=True):
        e_obj: GraphEdge = data["edge"]
        edge_map[e_obj.edge_id] = e_obj

    hash_to_db_id = persisted_paths_meta or {}

    # 1. Edge blast radius across active paths (counterfactual checked per active edge)
    edge_path_indices: dict[str, list[int]] = {}
    for p_idx, path in enumerate(baseline_paths):
        for eid in set(_extract_path_edge_ids(path)):
            edge_path_indices.setdefault(eid, []).append(p_idx)

    edge_blast_radius: dict[str, dict[str, Any]] = {}
    single_chokepoint_ids: list[str] = []
    for eid, p_indices in sorted(
        edge_path_indices.items(), key=lambda kv: (-len(kv[1]), kv[0])
    ):
        e_obj = edge_map.get(eid)
        if e_obj is None:
            continue
        filtered_edges = [edge for edge in edges if edge.edge_id != eid]
        residual_graph, _ = build_networkx_graph(
            nodes, filtered_edges, as_of=analysis_constraints.as_of
        )
        residual_search = find_attack_paths(residual_graph, analysis_constraints)
        residual_count = len(residual_search.paths)
        residual_reachability = verify_reachability(residual_graph, analysis_constraints)
        is_singleton = (
            baseline_reachability.reachable_unbounded
            and residual_reachability.complete
            and not residual_reachability.reachable_unbounded
        )
        if is_singleton:
            single_chokepoint_ids.append(eid)

        targets_hit = sorted({baseline_paths[i].target_node_label for i in p_indices})
        cum_risk = round(sum(baseline_paths[i].priority_score for i in p_indices), 2)
        max_risk = round(max(baseline_paths[i].priority_score for i in p_indices), 2)
        tx_dict, action_lbl, _ = recommended_transform_for_edge(e_obj, node_map)

        edge_blast_radius[eid] = {
            "edge_id": eid,
            "source_key": e_obj.source_key,
            "source_label": node_map[e_obj.source_key].label
            if e_obj.source_key in node_map
            else e_obj.source_key,
            "target_key": e_obj.target_key,
            "target_label": node_map[e_obj.target_key].label
            if e_obj.target_key in node_map
            else e_obj.target_key,
            "relation_type": e_obj.relation_type.value,
            "fact_kind": e_obj.fact_kind.value,
            "confidence": e_obj.confidence,
            "betweenness_centrality": stats.edge_betweenness.get(eid, 0.0),
            "paths_traversed_count": len(p_indices),
            "total_paths": len(baseline_paths),
            "path_coverage_pct": round((len(p_indices) / len(baseline_paths)) * 100.0, 1)
            if baseline_paths
            else 0.0,
            "critical_targets_affected": targets_hit,
            "cumulative_risk_score": cum_risk,
            "max_path_score": max_risk,
            "residual_paths_if_cut": residual_count,
            "residual_paths_semantics": "enumerated_candidate_count_not_total",
            "residual_reachability": residual_reachability.status,
            "residual_reachable": residual_reachability.reachable_unbounded,
            "reachability_verification_complete": residual_reachability.complete,
            "residual_witness_edge_ids": residual_reachability.witness_path_edge_ids,
            "is_single_point_chokepoint": is_singleton,
            "action_label": action_lbl,
            "recommended_transform": tx_dict,
        }

    # 2. Bounded candidate cut sets, independently checked by reachability BFS.
    cut_sets = _solve_candidate_cut_sets(
        nodes=nodes,
        edges=edges,
        constraints=analysis_constraints,
        baseline_paths=baseline_paths,
        edge_map=edge_map,
        node_map=node_map,
        max_sets=5,
    )

    # 3. Path Overlay entries for Graph Explorer
    paths_overlay: list[dict[str, Any]] = []
    for p in baseline_paths:
        cap_chain = list(p.explanation_trace.get("capability_chain", []))
        stages = [str(c.get("stage_name", "")) for c in cap_chain if c.get("stage_name")]
        paths_overlay.append(
            {
                "path_id": hash_to_db_id.get(p.determinism_hash),
                "determinism_hash": p.determinism_hash,
                "title": p.title,
                "priority_score": p.priority_score,
                "hop_count": p.hop_count,
                "evidence_confidence": p.evidence_confidence,
                "start_node_key": f"{p.start_node_kind}:{p.start_node_id}",
                "target_node_key": f"{p.target_node_kind}:{p.target_node_id}",
                "start_node_label": p.start_node_label,
                "target_node_label": p.target_node_label,
                "node_keys": _extract_path_node_keys(p),
                "edge_ids": _extract_path_edge_ids(p),
                "has_inferred": any(
                    st.fact_kind == FactKind.INFERRED_RELATIONSHIP.value for st in p.steps
                ),
                "capability_stages": stages,
            }
        )

    # 4. Assessment-wide Assumption Sensitivity & Fragility Summary
    sensitivity = _run_assessment_sensitivity_matrix(
        nodes=nodes,
        edges=edges,
        constraints=analysis_constraints,
        baseline_paths=baseline_paths,
    )

    assumption_agg: dict[tuple[str, str], dict[str, Any]] = {}
    for p in baseline_paths:
        for asm in p.explanation_trace.get("assumptions_register", []):
            cat = str(asm.get("category", "other"))
            if cat == "plausibility_invariant":
                continue
            stmt = str(asm.get("statement", ""))
            key = (cat, str(asm.get("relationship_id") or stmt))
            if key not in assumption_agg:
                assumption_agg[key] = {
                    "assumption_id": asm.get("assumption_id"),
                    "category": cat,
                    "fragility": asm.get("fragility", "moderate"),
                    "relationship_id": asm.get("relationship_id"),
                    "statement": stmt,
                    "verification_action": asm.get("verification_action"),
                    "affected_paths_count": 0,
                    "can_challenge_edge": bool(asm.get("can_challenge_edge")),
                }
            assumption_agg[key]["affected_paths_count"] += 1

    fragility_rank = {"critical": 0, "high": 1, "moderate": 2, "low": 3}
    assumptions_summary = sorted(
        assumption_agg.values(),
        key=lambda a: (
            fragility_rank.get(str(a["fragility"]), 9),
            -int(a["affected_paths_count"]),
            str(a["statement"]),
        ),
    )

    crown_jewels = sorted(
        node_map[key].label
        for key in baseline_reachability.reachable_target_keys
        if key in node_map
        and (node_map[key].is_crown_jewel or node_map[key].criticality == "critical")
    )
    inferred_paths = sum(
        1
        for p in baseline_paths
        if any(s.fact_kind == FactKind.INFERRED_RELATIONSHIP.value for s in p.steps)
    )
    uncorr_acl_count = sum(
        1
        for e in edge_map.values()
        if e.relation_type in (RelationType.CONNECTS_TO, RelationType.EXPOSES)
        and not e.edge_metadata.get("acl_rule")
    )
    stale_nodes_count = sum(1 for n in nodes if n.stale_observation)

    return {
        "graph_stats": {
            "node_count": stats.node_count,
            "edge_count": stats.edge_count,
            "suppressed_edge_count": stats.suppressed_edge_count,
            "expired_edge_count": stats.expired_edge_count,
            "scc_cycle_count": stats.scc_cycle_count,
            "scc_cycles": stats.scc_cycles,
            "top_bridge_nodes": stats.top_bridge_nodes,
            "top_bridge_edges": stats.top_bridge_edges,
            "build_duration_ms": stats.build_duration_ms,
        },
        "summary": {
            # Legacy count retained for clients; it is a count of returned candidates.
            "total_active_paths": len(baseline_paths),
            "path_count_semantics": "returned_candidate_count_not_total",
            "path_search_complete": not search_out.is_truncated,
            "path_search_truncation_reason": search_out.truncation_reason,
            "single_point_chokepoints_scope": "edges_present_in_returned_path_candidates",
            "inferred_path_count_semantics": "returned_candidate_count_not_total",
            "baseline_possible_reachability": baseline_reachability.reachable_unbounded,
            "baseline_reachable_within_max_hops": baseline_reachability.reachable_within_max_hops,
            "baseline_confirmed_reachability": baseline_reachability.confirmed_reachable_unbounded,
            "reachability_verification_complete": baseline_reachability.complete,
            "reachable_target_keys": baseline_reachability.reachable_target_keys,
            "reachable_crown_jewels": crown_jewels,
            "single_point_chokepoints_count": len(single_chokepoint_ids),
            # The heuristic candidate solver does not prove a global minimum cut.
            "min_cut_size": None,
            "candidate_cut_size": cut_sets[0]["cut_size"] if cut_sets else None,
            "minimum_cut_proven": False,
            "inferred_dependent_paths": inferred_paths,
            "observed_only_paths": len(baseline_paths) - inferred_paths,
            "uncorroborated_acl_edges": uncorr_acl_count,
            "stale_nodes_count": stale_nodes_count,
        },
        "paths_overlay": paths_overlay,
        "edge_blast_radius": edge_blast_radius,
        "cut_sets": cut_sets,
        "sensitivity_analysis": sensitivity,
        "assumptions_summary": assumptions_summary,
    }


def analyze_single_path_intelligence(
    *,
    nodes: list[GraphNode],
    edges: list[GraphEdge],
    constraints: PathSearchConstraints,
    path_steps: list[dict[str, Any]],
    start_key: str,
    target_key: str,
    priority_score: float,
    persisted_path_id: str | None = None,
) -> dict[str, Any]:
    """Deep causal explanation, bypass-aware assumption fragility, and cut-set solver for one path."""
    full_intel = analyze_assessment_intelligence(
        nodes=nodes,
        edges=edges,
        constraints=constraints,
    )
    node_map = {n.key: n for n in nodes}
    live_edge_map: dict[str, GraphEdge] = {
        e.edge_id: e for e in edges if not e.is_suppressed
    }
    all_edge_map: dict[str, GraphEdge] = {e.edge_id: e for e in edges}

    path_edge_ids = [str(s["relationship_id"]) for s in path_steps if s.get("relationship_id")]
    missing_or_suppressed_steps = [eid for eid in path_edge_ids if eid not in live_edge_map]
    stale_path_notice: str | None = None
    if missing_or_suppressed_steps:
        stale_path_notice = (
            f"{len(missing_or_suppressed_steps)} edge(s) on this cached path have since been suppressed "
            "or removed from the active graph. Rebuild graph & regenerate paths to refresh persisted paths."
        )

    # Same-(start, target) pair baseline routes so we detect bypasses around each step!
    pair_constraints = PathSearchConstraints(
        start_node_keys=[start_key],
        target_node_keys=[target_key],
        algorithm=constraints.algorithm,
        min_confidence=constraints.min_confidence,
        max_hops=constraints.max_hops,
        max_candidates=constraints.max_candidates,
        top_k=25,
        include_inferred=constraints.include_inferred,
        allowed_edge_types=constraints.allowed_edge_types,
        excluded_node_keys=constraints.excluded_node_keys,
        excluded_environments=constraints.excluded_environments,
        allow_unknown_preconditions=constraints.allow_unknown_preconditions,
        as_of=constraints.as_of,
    )
    g_live, _ = build_networkx_graph(nodes, edges, as_of=constraints.as_of)
    same_pair_out = find_attack_paths(g_live, pair_constraints)
    same_pair_paths = same_pair_out.paths
    same_pair_reachability = verify_reachability(g_live, pair_constraints)

    blast_map: dict[str, dict[str, Any]] = full_intel["edge_blast_radius"]

    capability_chain: list[dict[str, Any]] = []
    per_step_sensitivity: list[dict[str, Any]] = []
    step_assumption_items: list[dict[str, Any]] = []
    step_bypass_lookup: dict[str, dict[str, Any]] = {}

    from app.domain.path_semantics import (
        describe_capability_transition,
        extract_step_assumptions_structured,
    )

    for st in path_steps:
        step_order = int(st["step_order"])
        rel_id = str(st.get("relationship_id") or "")
        src_k = f"{st['from_node_kind']}:{st['from_node_id']}"
        tgt_k = f"{st['to_node_kind']}:{st['to_node_id']}"
        edge_obj = all_edge_map.get(rel_id)
        src_n = node_map.get(src_k)
        tgt_n = node_map.get(tgt_k)

        # Counterfactual removal of this single edge
        if rel_id in live_edge_map:
            pair_after_edges = [edge for edge in edges if edge.edge_id != rel_id]
            pair_after_graph, _ = build_networkx_graph(
                nodes, pair_after_edges, as_of=pair_constraints.as_of
            )
            pair_after_out = find_attack_paths(pair_after_graph, pair_constraints)
            pair_after = pair_after_out.paths
            pair_after_reachability = verify_reachability(
                pair_after_graph, pair_constraints
            )
            assess_after_info = blast_map.get(rel_id)
            if assess_after_info:
                assess_rem = int(assess_after_info["residual_paths_if_cut"])
                assessment_reachable_remaining = bool(
                    assess_after_info["residual_reachable"]
                )
                assessment_reachability_complete = bool(
                    assess_after_info["reachability_verification_complete"]
                )
                assess_hits = int(assess_after_info["paths_traversed_count"])
            else:
                assessment_graph, _ = build_networkx_graph(
                    nodes, pair_after_edges, as_of=constraints.as_of
                )
                assessment_after = verify_reachability(assessment_graph, constraints)
                assessment_reachable_remaining = assessment_after.reachable_unbounded
                assessment_reachability_complete = assessment_after.complete
                assess_rem = len(
                    _paths_covered_without_edges(nodes, edges, constraints, {rel_id})
                )
                assess_hits = 1
        else:
            pair_after = same_pair_paths
            pair_after_out = same_pair_out
            pair_after_reachability = same_pair_reachability
            assess_rem = len(full_intel["paths_overlay"])
            baseline_reachability = bool(
                full_intel["summary"]["baseline_possible_reachability"]
            )
            assessment_reachable_remaining = baseline_reachability
            assessment_reachability_complete = bool(
                full_intel["summary"]["reachability_verification_complete"]
            )
            assess_hits = 0

        bypasses_preview = [
            " -> ".join([bp.start_node_label, *[bs.to_node_label for bs in bp.steps]])
            for bp in pair_after[:3]
        ]
        bypass_summary = {
            "step_order": step_order,
            "relationship_id": rel_id,
            "transition": f"{st['from_node_label']} --[{st['relation_type']}]--> {st['to_node_label']}",
            "this_path_eliminated": rel_id in live_edge_map,
            # Route counts below are candidate-enumeration counts, not total route counts.
            "same_pair_bypasses_remaining": len(pair_after),
            "same_pair_path_search_complete": not pair_after_out.is_truncated,
            "same_pair_reachability_status": pair_after_reachability.status,
            "same_pair_reachable": pair_after_reachability.reachable_unbounded,
            "same_pair_reachability_verification_complete": pair_after_reachability.complete,
            "bypass_routes_preview": bypasses_preview,
            "assessment_paths_broken": assess_hits,
            "assessment_paths_remaining": assess_rem,
            "assessment_reachable_remaining": assessment_reachable_remaining,
            "assessment_reachability_verification_complete": assessment_reachability_complete,
            "is_pair_bridge_chokepoint": (
                not pair_after_reachability.reachable_unbounded
                and pair_after_reachability.complete
                and rel_id in live_edge_map
            ),
            "is_assessment_chokepoint": (
                not assessment_reachable_remaining
                and assessment_reachability_complete
                and rel_id in live_edge_map
                and bool(full_intel["summary"]["baseline_possible_reachability"])
            ),
        }
        per_step_sensitivity.append(bypass_summary)
        step_bypass_lookup[rel_id] = bypass_summary

        if edge_obj and src_n and tgt_n:
            cap = describe_capability_transition(
                step_order=step_order, edge=edge_obj, src_node=src_n, tgt_node=tgt_n
            )
            cap["precondition_outcomes"] = evaluate_edge_preconditions(edge_obj)
            cap["precondition_summary"] = precondition_summary(cap["precondition_outcomes"])
            cap["paths_in_assessment_count"] = assess_hits
            cap["same_pair_bypasses_if_removed"] = len(pair_after)
            cap["same_pair_path_search_complete"] = not pair_after_out.is_truncated
            cap["same_pair_reachable_if_removed"] = pair_after_reachability.reachable_unbounded
            cap["same_pair_reachability_verification_complete"] = pair_after_reachability.complete
            cap["is_pair_bridge_chokepoint"] = bypass_summary["is_pair_bridge_chokepoint"]
            cap["is_assessment_chokepoint"] = bypass_summary["is_assessment_chokepoint"]
            cap["edge_betweenness"] = blast_map.get(rel_id, {}).get("betweenness_centrality", 0.0)
            capability_chain.append(cap)

            raw_asms = extract_step_assumptions_structured(
                step_order=step_order, edge=edge_obj, src_node=src_n, tgt_node=tgt_n
            )
            for a in raw_asms:
                if (
                    not pair_after_reachability.reachable_unbounded
                    and pair_after_reachability.complete
                    and rel_id in live_edge_map
                ):
                    a["if_falsified"] = (
                        f"Disproving/blocking Step {step_order} eliminates this path with 0 alternate bypasses "
                        f"from {node_map[start_key].label if start_key in node_map else start_key} to "
                        f"{node_map[target_key].label if target_key in node_map else target_key} "
                        f"({assess_rem} assessment path(s) remain elsewhere)."
                    )
                else:
                    a["if_falsified"] = (
                        f"Disproving Step {step_order} closes THIS path, but {len(pair_after)} alternate "
                        f"bypass route(s) still connect entry to target"
                        + (f" (e.g. {bypasses_preview[0]})." if bypasses_preview else ".")
                    )
                step_assumption_items.append(a)
        else:
            capability_chain.append(
                {
                    "step_order": step_order,
                    "relationship_id": rel_id,
                    "source_key": src_k,
                    "source_label": st["from_node_label"],
                    "target_key": tgt_k,
                    "target_label": st["to_node_label"],
                    "relation_type": st["relation_type"],
                    "fact_kind": st["fact_kind"],
                    "confidence": st["confidence"],
                    "stage_name": "Cached Transition",
                    "mechanism": st.get("narrative", ""),
                    "paths_in_assessment_count": assess_hits,
                    "same_pair_bypasses_if_removed": len(pair_after),
                    "same_pair_path_search_complete": not pair_after_out.is_truncated,
                    "same_pair_reachable_if_removed": pair_after_reachability.reachable_unbounded,
                    "same_pair_reachability_verification_complete": pair_after_reachability.complete,
                    "is_pair_bridge_chokepoint": False,
                    "is_assessment_chokepoint": False,
                    "edge_betweenness": 0.0,
                }
            )

    # Prepend top structural caveat
    assumptions_register: list[dict[str, Any]] = [
        {
            "assumption_id": "asm-plausibility-invariant",
            "category": "plausibility_invariant",
            "fragility": "low",
            "step_order": None,
            "relationship_id": None,
            "node_key": target_key,
            "statement": (
                f"Plausible exposure hypothesis (Priority Score {priority_score}/100) — "
                "does NOT claim live exploitability or statistical probability."
            ),
            "if_falsified": "Structural ranking guardrail (score becomes advisory only).",
            "verification_action": "Confirm mitigating runtime controls and step evidence provenance.",
            "can_challenge_edge": False,
        },
        *step_assumption_items,
    ]

    # Recommended remediations covering THIS path: merge full assessment cut-sets covering this path + per-step surgical breaks
    path_edge_set = set(path_edge_ids)
    recommended_remediations: list[dict[str, Any]] = []
    seen_cut_keys: set[tuple[str, ...]] = set()

    for cs in full_intel["cut_sets"]:
        cs_edges = list(cs["edge_ids"])
        if any(eid in path_edge_set for eid in cs_edges):
            ck = tuple(sorted(cs_edges))
            seen_cut_keys.add(ck)
            recommended_remediations.append(
                {
                    **cs,
                    "scope": "full_cut_set",
                    "eliminates_all_bypasses": cs["residual_paths"] == 0,
                }
            )

    # Also offer single-step surgical fixes on this path that weren't already singleton cut-sets
    for st in path_steps:
        eid = str(st.get("relationship_id") or "")
        e_obj = live_edge_map.get(eid)
        if e_obj is None:
            continue
        ck = (eid,)
        if ck in seen_cut_keys:
            continue
        seen_cut_keys.add(ck)
        tx_dict, action_lbl, eff = recommended_transform_for_edge(e_obj, node_map)
        bp = step_bypass_lookup.get(eid, {})
        byp_rem = int(bp.get("same_pair_bypasses_remaining", 0))
        assess_hits = int(bp.get("assessment_paths_broken", 1))
        assess_rem = int(bp.get("assessment_paths_remaining", 0))
        base_total = int(full_intel["summary"]["total_active_paths"]) or 1
        recommended_remediations.append(
            {
                "id": f"step-{st['step_order']}",
                "scope": "single_step",
                "label": f"Step {st['step_order']}: {action_lbl}",
                "cut_size": 1,
                "effort_score": eff,
                "baseline_paths": base_total,
                "paths_broken": assess_hits,
                "residual_paths": assess_rem,
                "same_pair_bypasses_remaining": byp_rem,
                "coverage_pct": round((assess_hits / base_total) * 100.0, 1),
                "critical_assets_unlinked": 1 if assess_rem == 0 else 0,
                "highest_score_reduction": priority_score if assess_rem == 0 else 0.0,
                "edge_ids": [eid],
                "steps_summary": [f"{action_lbl} (Step {st['step_order']} of this path)"],
                "transforms": [tx_dict],
                "eliminates_all_bypasses": byp_rem == 0,
                "rationale": (
                    f"Closes this path with 0 alternate bypasses between {start_key} and {target_key}."
                    if byp_rem == 0
                    else f"Breaks Step {st['step_order']}, but {byp_rem} parallel bypass route(s) still reach {node_map[target_key].label if target_key in node_map else target_key}."
                ),
            }
        )

    # Focused Subgraph: include nodes/edges from this path AND parallel same-pair bypasses!
    sub_node_keys: set[str] = {start_key, target_key}
    sub_edge_ids: set[str] = set(path_edge_ids)
    for st in path_steps:
        sub_node_keys.add(f"{st['from_node_kind']}:{st['from_node_id']}")
        sub_node_keys.add(f"{st['to_node_kind']}:{st['to_node_id']}")
    for alt_p in same_pair_paths[:8]:
        for k in _extract_path_node_keys(alt_p):
            sub_node_keys.add(k)
        for eid in _extract_path_edge_ids(alt_p):
            sub_edge_ids.add(eid)
    # Include cut-set edges that affect this path too so the user can preview cuts on canvas!
    for rec in recommended_remediations[:3]:
        for eid in rec["edge_ids"]:
            if eid in live_edge_map:
                e_obj = live_edge_map[eid]
                sub_edge_ids.add(eid)
                sub_node_keys.add(e_obj.source_key)
                sub_node_keys.add(e_obj.target_key)

    sub_nodes_out = [
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
        for n in nodes
        if n.key in sub_node_keys
    ]
    sub_edges_out = [
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
        for e in all_edge_map.values()
        if e.source_key in sub_node_keys
        and e.target_key in sub_node_keys
        and (not e.is_suppressed or e.edge_id in path_edge_set)
    ]

    pair_bypasses_other = max(0, len(same_pair_paths) - (0 if stale_path_notice else 1))
    chokepoint_steps = [
        c["step_order"] for c in capability_chain if c.get("is_pair_bridge_chokepoint")
    ]
    start_lbl = node_map[start_key].label if start_key in node_map else start_key
    tgt_lbl = node_map[target_key].label if target_key in node_map else target_key
    stages_flow = " -> ".join(str(c["stage_name"]) for c in capability_chain)
    why_summary = (
        f"An adversary entering via '{start_lbl}' chains {len(path_steps)} transition(s) "
        f"({stages_flow}) to compromise '{tgt_lbl}'. "
        + (
            f"Steps {chokepoint_steps} act as unique bridge bottlenecks for this entry/target pair; breaking any one cuts all routes between them."
            if chokepoint_steps
            else f"Parallel bypasses exist ({pair_bypasses_other} other route(s) connect '{start_lbl}' to '{tgt_lbl}'), so remediating requires either a multi-edge cut-set or shared upstream/downstream chokepoint."
        )
    )

    return {
        "path_id": persisted_path_id,
        "stale_path_notice": stale_path_notice,
        "why_exists": {
            "summary": why_summary,
            "capability_chain": capability_chain,
            "structural_context": {
                "total_assessment_paths": full_intel["summary"]["total_active_paths"],
                "same_pair_total_paths": len(same_pair_paths),
                "same_pair_path_count_semantics": "returned_candidate_count_not_total",
                "same_pair_path_search_complete": not same_pair_out.is_truncated,
                "same_pair_reachable": same_pair_reachability.reachable_unbounded,
                "same_pair_reachability_verification_complete": same_pair_reachability.complete,
                "parallel_bypass_paths_count": pair_bypasses_other,
                "chokepoint_step_orders": chokepoint_steps,
                "scc_cycle_count": full_intel["graph_stats"]["scc_cycle_count"],
            },
        },
        "assumptions_register": assumptions_register,
        "per_step_sensitivity": per_step_sensitivity,
        "assessment_sensitivity": full_intel["sensitivity_analysis"],
        "recommended_remediations": recommended_remediations,
        "edge_blast_radius": blast_map,
        "subgraph": {
            "nodes": sub_nodes_out,
            "edges": sub_edges_out,
            "highlighted_node_keys": list(
                dict.fromkeys(
                    [start_key, *[f"{s['to_node_kind']}:{s['to_node_id']}" for s in path_steps]]
                )
            ),
            "highlighted_edge_ids": path_edge_ids,
        },
    }
