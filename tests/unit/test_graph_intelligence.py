from dataclasses import replace
from datetime import UTC, datetime, timedelta

from app.domain.graph_intelligence import (
    analyze_assessment_intelligence,
    analyze_single_path_intelligence,
)
from app.domain.models import (
    AlgorithmType,
    FactKind,
    GraphEdge,
    GraphNode,
    NodeKind,
    PathSearchConstraints,
    RelationType,
    RemediationTransformType,
)
from app.domain.remediation_sim import RemediationTransform, simulate_remediation


def _build_diamond_with_bridge() -> tuple[list[GraphNode], list[GraphEdge]]:
    now = datetime.now(UTC)
    nodes = [
        GraphNode(NodeKind.ASSET, "web", "web-dmz", criticality="medium", is_external_entry=True),
        GraphNode(NodeKind.ASSET, "app", "app-core", criticality="high"),
        GraphNode(
            NodeKind.IDENTITY,
            "svc1",
            "svc-etl-observed",
            criticality="medium",
            privilege_level="elevated",
            metadata={"auth_metadata": {"mfa_enforced": False}, "privilege_indicators": ["db_ops"]},
        ),
        GraphNode(NodeKind.IDENTITY, "svc2", "svc-dc-inferred", criticality="high", privilege_level="admin"),
        GraphNode(NodeKind.ASSET, "db", "db-crown", criticality="critical", is_crown_jewel=True),
    ]
    edges = [
        # Single-edge upstream bridge between web and app
        GraphEdge(
            "e_bridge",
            NodeKind.ASSET,
            "web",
            NodeKind.ASSET,
            "app",
            RelationType.CONNECTS_TO,
            FactKind.OBSERVED_FACT,
            0.95,
            now - timedelta(days=1),
            edge_metadata={"ports": [8080]},  # uncorroborated (no acl_rule)
        ),
        # Branch A: observed CVE-contingent + admin
        GraphEdge(
            "e_a1",
            NodeKind.ASSET,
            "app",
            NodeKind.IDENTITY,
            "svc1",
            RelationType.HAS_ROLE,
            FactKind.OBSERVED_FACT,
            0.9,
            now - timedelta(days=1),
            edge_metadata={"requires_cve": "CVE-2023-28709"},
        ),
        GraphEdge(
            "e_a2",
            NodeKind.IDENTITY,
            "svc1",
            NodeKind.ASSET,
            "db",
            RelationType.CAN_ADMINISTER,
            FactKind.OBSERVED_FACT,
            0.92,
            now - timedelta(days=1),
        ),
        # Branch B: inferred bypass with moderate confidence
        GraphEdge(
            "e_b1",
            NodeKind.ASSET,
            "app",
            NodeKind.IDENTITY,
            "svc2",
            RelationType.TRUSTS,
            FactKind.INFERRED_RELATIONSHIP,
            0.62,
            now - timedelta(days=1),
        ),
        GraphEdge(
            "e_b2",
            NodeKind.IDENTITY,
            "svc2",
            NodeKind.ASSET,
            "db",
            RelationType.CAN_ADMINISTER,
            FactKind.OBSERVED_FACT,
            0.88,
            now - timedelta(days=1),
            edge_metadata={"acl_rule": "ACL-ADMIN-DB"},
        ),
    ]
    return nodes, edges


def test_single_chokepoint_vs_parallel_branch_cut_sets() -> None:
    nodes, edges = _build_diamond_with_bridge()
    constraints = PathSearchConstraints(
        start_node_keys=["asset:web"],
        target_node_keys=["asset:db"],
        algorithm=AlgorithmType.DIJKSTRA,
        min_confidence=0.2,
        max_hops=6,
        top_k=20,
        include_inferred=True,
    )
    intel = analyze_assessment_intelligence(nodes=nodes, edges=edges, constraints=constraints)

    assert intel["summary"]["total_active_paths"] == 2
    assert intel["summary"]["min_cut_size"] is None\n    assert intel["summary"]["candidate_cut_size"] == 1\n    assert intel["summary"]["minimum_cut_proven"] is False
    assert intel["summary"]["single_point_chokepoints_count"] == 1

    blast = intel["edge_blast_radius"]
    assert blast["e_bridge"]["is_single_point_chokepoint"] is True
    assert blast["e_bridge"]["residual_paths_if_cut"] == 0
    assert blast["e_bridge"]["residual_reachable"] is False
    assert blast["e_bridge"]["reachability_verification_complete"] is True
    assert blast["e_bridge"]["recommended_transform"]["transform_type"] == "segment_network"

    # Parallel branch edges alone leave the alternate route alive
    assert blast["e_a2"]["is_single_point_chokepoint"] is False
    assert blast["e_a2"]["residual_paths_if_cut"] == 1
    assert blast["e_b1"]["is_single_point_chokepoint"] is False
    assert blast["e_b1"]["residual_paths_if_cut"] == 1

    top_cut = intel["cut_sets"][0]
    assert top_cut["cut_size"] == 1
    assert top_cut["residual_paths"] == 0
    assert top_cut["verification_status"] == "MODEL_VERIFIED_CUT"
    assert top_cut["minimum_cut_proven"] is False
    assert top_cut["reachable_unbounded"] is False
    assert top_cut["edge_ids"] == ["e_bridge"]


def test_disjoint_parallel_branches_require_two_edge_cut_set() -> None:
    now = datetime.now(UTC)
    nodes = [
        GraphNode(NodeKind.ASSET, "web", "web-dmz", criticality="medium", is_external_entry=True),
        GraphNode(NodeKind.IDENTITY, "id1", "id-left", criticality="medium"),
        GraphNode(NodeKind.IDENTITY, "id2", "id-right", criticality="medium"),
        GraphNode(NodeKind.ASSET, "db", "db-crown", criticality="critical", is_crown_jewel=True),
    ]
    edges = [
        GraphEdge("l1", NodeKind.ASSET, "web", NodeKind.IDENTITY, "id1", RelationType.HAS_ROLE, FactKind.OBSERVED_FACT, 0.9, now),
        GraphEdge("l2", NodeKind.IDENTITY, "id1", NodeKind.ASSET, "db", RelationType.CAN_ADMINISTER, FactKind.OBSERVED_FACT, 0.9, now),
        GraphEdge("r1", NodeKind.ASSET, "web", NodeKind.IDENTITY, "id2", RelationType.HAS_ROLE, FactKind.OBSERVED_FACT, 0.85, now),
        GraphEdge("r2", NodeKind.IDENTITY, "id2", NodeKind.ASSET, "db", RelationType.CAN_ADMINISTER, FactKind.OBSERVED_FACT, 0.85, now),
    ]
    constraints = PathSearchConstraints(
        start_node_keys=["asset:web"],
        target_node_keys=["asset:db"],
        max_hops=5,
        top_k=20,
    )
    intel = analyze_assessment_intelligence(nodes=nodes, edges=edges, constraints=constraints)

    assert intel["summary"]["total_active_paths"] == 2
    assert intel["summary"]["single_point_chokepoints_count"] == 0
    assert intel["summary"]["min_cut_size"] is None\n    assert intel["summary"]["candidate_cut_size"] == 2\n    assert intel["summary"]["minimum_cut_proven"] is False

    top_cut = intel["cut_sets"][0]
    assert top_cut["cut_size"] == 2
    assert top_cut["residual_paths"] == 0
    assert top_cut["verification_status"] == "MODEL_VERIFIED_CUT"
    assert top_cut["minimum_cut_proven"] is False
    assert top_cut["paths_broken"] == 2

    # Confirm returned cut transforms eliminate all paths under real sandbox simulation
    domain_txs = [
        RemediationTransform(
            transform_type=RemediationTransformType(t["transform_type"]),
            relationship_id=t.get("relationship_id"),
            ports=t.get("ports"),
            notes=str(t.get("notes", "")),
        )
        for t in top_cut["transforms"]
    ]
    sim = simulate_remediation(nodes=nodes, edges=edges, constraints=constraints, transforms=domain_txs)
    assert sim.modelled.total_paths == 0
    assert sim.delta_summary["paths_eliminated"] == 2


def test_sensitivity_analysis_counters_inferred_acls_and_cves() -> None:
    nodes, edges = _build_diamond_with_bridge()
    constraints = PathSearchConstraints(
        start_node_keys=["asset:web"],
        target_node_keys=["asset:db"],
        max_hops=6,
        top_k=20,
        include_inferred=True,
    )
    intel = analyze_assessment_intelligence(nodes=nodes, edges=edges, constraints=constraints)
    by_id = {s["scenario_id"]: s for s in intel["sensitivity_analysis"]}

    assert by_id["observed_only"]["baseline_paths"] == 2
    assert by_id["observed_only"]["remaining_paths"] == 1
    assert by_id["observed_only"]["paths_eliminated"] == 1

    assert by_id["high_confidence_only"]["remaining_paths"] == 1
    assert by_id["uncorroborated_acls_blocked"]["remaining_paths"] == 0
    assert "cve_edges_patched" in by_id


def test_single_path_intelligence_causal_chain_bypasses_and_stale_notice() -> None:
    nodes, edges = _build_diamond_with_bridge()
    constraints = PathSearchConstraints(
        start_node_keys=["asset:web"],
        target_node_keys=["asset:db"],
        max_hops=6,
        top_k=20,
        include_inferred=True,
    )
    path_steps = [
        {
            "step_order": 1,
            "relationship_id": "e_bridge",
            "from_node_kind": "asset",
            "from_node_id": "web",
            "from_node_label": "web-dmz",
            "to_node_kind": "asset",
            "to_node_id": "app",
            "to_node_label": "app-core",
            "relation_type": "CONNECTS_TO",
            "fact_kind": "observed_fact",
            "confidence": 0.95,
            "narrative": "web reaches app",
        },
        {
            "step_order": 2,
            "relationship_id": "e_a1",
            "from_node_kind": "asset",
            "from_node_id": "app",
            "from_node_label": "app-core",
            "to_node_kind": "identity",
            "to_node_id": "svc1",
            "to_node_label": "svc-etl-observed",
            "relation_type": "HAS_ROLE",
            "fact_kind": "observed_fact",
            "confidence": 0.9,
            "narrative": "app holds svc1 role",
        },
        {
            "step_order": 3,
            "relationship_id": "e_a2",
            "from_node_kind": "identity",
            "from_node_id": "svc1",
            "from_node_label": "svc-etl-observed",
            "to_node_kind": "asset",
            "to_node_id": "db",
            "to_node_label": "db-crown",
            "relation_type": "CAN_ADMINISTER",
            "fact_kind": "observed_fact",
            "confidence": 0.92,
            "narrative": "svc1 administers db",
        },
    ]

    p_intel = analyze_single_path_intelligence(
        nodes=nodes,
        edges=edges,
        constraints=constraints,
        path_steps=path_steps,
        start_key="asset:web",
        target_key="asset:db",
        priority_score=84.5,
        persisted_path_id="path-1",
    )

    assert p_intel["stale_path_notice"] is None
    assert p_intel["why_exists"]["structural_context"]["same_pair_total_paths"] == 2
    assert p_intel["why_exists"]["structural_context"]["parallel_bypass_paths_count"] == 1
    assert p_intel["why_exists"]["structural_context"]["chokepoint_step_orders"] == [1]

    categories = {a["category"] for a in p_intel["assumptions_register"]}
    assert "plausibility_invariant" in categories
    assert "uncorroborated_acl" in categories
    assert "cve_exploitability_unproven" in categories
    assert "standing_privilege_unscoped" in categories

    # Parallel branch edges (e_b1, e_b2) should be included in focused subgraph alongside main steps
    sub_edge_ids = {e["edge_id"] for e in p_intel["subgraph"]["edges"]}
    assert {"e_bridge", "e_a1", "e_a2", "e_b1", "e_b2"}.issubset(sub_edge_ids)

    # Recommended remediations include both full cut-sets and single-step options with bypass warning
    step3_rec = next(r for r in p_intel["recommended_remediations"] if r.get("edge_ids") == ["e_a2"])
    assert step3_rec["eliminates_all_bypasses"] is False
    assert step3_rec["same_pair_bypasses_remaining"] == 1

    # Now suppress e_bridge and verify graceful stale notice instead of crash
    edges_sup = [
        replace(e, is_suppressed=True) if e.edge_id == "e_bridge" else e
        for e in edges
    ]
    stale_intel = analyze_single_path_intelligence(
        nodes=nodes,
        edges=edges_sup,
        constraints=constraints,
        path_steps=path_steps,
        start_key="asset:web",
        target_key="asset:db",
        priority_score=84.5,
    )
    assert stale_intel["stale_path_notice"] is not None
    assert "suppressed" in stale_intel["stale_path_notice"]
