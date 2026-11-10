from datetime import UTC, datetime, timedelta

from app.domain.graph_engine import build_networkx_graph, find_attack_paths, verify_reachability
from app.domain.models import (
    AlgorithmType,
    FactKind,
    GraphEdge,
    GraphNode,
    NodeKind,
    PathSearchConstraints,
    RelationType,
)


def _sample_graph_data() -> tuple[list[GraphNode], list[GraphEdge]]:
    now = datetime.now(UTC)
    nodes = [
        GraphNode(NodeKind.ASSET, "web", "web-dmz", criticality="medium", is_external_entry=True),
        GraphNode(NodeKind.ASSET, "app", "app-mid", criticality="high"),
        GraphNode(NodeKind.IDENTITY, "svc", "svc-etl", criticality="medium", privilege_level="elevated"),
        GraphNode(NodeKind.ASSET, "db", "db-crown", criticality="critical", is_crown_jewel=True),
    ]
    edges = [
        GraphEdge("e1", NodeKind.ASSET, "web", NodeKind.ASSET, "app", RelationType.CONNECTS_TO, FactKind.OBSERVED_FACT, 0.95, now - timedelta(days=1)),
        GraphEdge("e2", NodeKind.ASSET, "app", NodeKind.IDENTITY, "svc", RelationType.HAS_ROLE, FactKind.OBSERVED_FACT, 0.9, now - timedelta(days=1)),
        GraphEdge("e3", NodeKind.IDENTITY, "svc", NodeKind.ASSET, "db", RelationType.CAN_ADMINISTER, FactKind.OBSERVED_FACT, 0.92, now - timedelta(days=1)),
        # Cycle edge svc <-> app for Tarjan SCC detection
        GraphEdge("e_cycle", NodeKind.IDENTITY, "svc", NodeKind.ASSET, "app", RelationType.TRUSTS, FactKind.INFERRED_RELATIONSHIP, 0.6, now - timedelta(days=1)),
        # Suppressed and expired edges that MUST be excluded
        GraphEdge("e_sup", NodeKind.ASSET, "web", NodeKind.ASSET, "db", RelationType.CONNECTS_TO, FactKind.OBSERVED_FACT, 0.99, now - timedelta(days=1), is_suppressed=True),
        GraphEdge("e_exp", NodeKind.ASSET, "web", NodeKind.ASSET, "db", RelationType.CONNECTS_TO, FactKind.OBSERVED_FACT, 0.99, now - timedelta(days=10), valid_to=now - timedelta(days=1)),
    ]
    return nodes, edges


def test_suppressed_and_expired_edges_excluded_and_scc_detected() -> None:
    nodes, edges = _sample_graph_data()
    graph, stats = build_networkx_graph(nodes, edges)
    assert stats.suppressed_edge_count == 1
    assert stats.expired_edge_count == 1
    assert stats.edge_count == 4
    assert stats.scc_cycle_count == 1
    assert len(stats.top_bridge_nodes) >= 1
    assert not graph.has_edge("asset:web", "asset:db")


def test_dijkstra_and_bfs_deterministic_and_hop_bounded() -> None:
    nodes, edges = _sample_graph_data()
    graph, _ = build_networkx_graph(nodes, edges)

    out_dijk = find_attack_paths(
        graph,
        PathSearchConstraints(
            start_node_keys=["asset:web"],
            target_node_keys=["asset:db"],
            algorithm=AlgorithmType.DIJKSTRA,
            max_hops=5,
        ),
    )
    out_bfs = find_attack_paths(
        graph,
        PathSearchConstraints(
            start_node_keys=["asset:web"],
            target_node_keys=["asset:db"],
            algorithm=AlgorithmType.BFS,
            max_hops=5,
        ),
    )
    assert len(out_dijk.paths) == 1
    assert out_dijk.paths[0].hop_count == 3
    assert out_dijk.paths[0].determinism_hash == find_attack_paths(
        graph,
        PathSearchConstraints(
            start_node_keys=["asset:web"],
            target_node_keys=["asset:db"],
            algorithm=AlgorithmType.DIJKSTRA,
            max_hops=5,
        ),
    ).paths[0].determinism_hash
    assert len(out_bfs.paths) == 1

    too_short = find_attack_paths(
        graph,
        PathSearchConstraints(
            start_node_keys=["asset:web"],
            target_node_keys=["asset:db"],
            max_hops=2,
        ),
    )
    assert too_short.paths == []



def test_unknown_transition_preconditions_are_conditional_not_confirmed() -> None:
    nodes, edges = _sample_graph_data()
    graph, _ = build_networkx_graph(nodes, edges)
    possible_constraints = PathSearchConstraints(
        start_node_keys=["asset:web"],
        target_node_keys=["asset:db"],
        max_hops=5,
        allow_unknown_preconditions=True,
    )
    possible = find_attack_paths(graph, possible_constraints)
    assert len(possible.paths) == 1
    outcomes = possible.paths[0].steps[0].precondition_outcomes
    assert outcomes
    assert {item["status"] for item in outcomes} == {"unknown"}

    confirmed_constraints = PathSearchConstraints(
        start_node_keys=["asset:web"],
        target_node_keys=["asset:db"],
        max_hops=5,
        allow_unknown_preconditions=False,
    )
    confirmed = find_attack_paths(graph, confirmed_constraints)
    assert confirmed.paths == []

    verification = verify_reachability(graph, possible_constraints)
    assert verification.reachable_unbounded is True
    assert verification.confirmed_reachable_unbounded is False
    assert verification.conditional_witness_edge_ids


def test_false_transition_precondition_blocks_path() -> None:
    nodes, edges = _sample_graph_data()
    edges[0].edge_metadata["network_reachable"] = False
    graph, _ = build_networkx_graph(nodes, edges)
    constraints = PathSearchConstraints(
        start_node_keys=["asset:web"],
        target_node_keys=["asset:db"],
        max_hops=5,
    )
    assert find_attack_paths(graph, constraints).paths == []
    verification = verify_reachability(graph, constraints)
    assert verification.reachable_unbounded is False
    assert verification.complete is True


def test_reachability_verifier_is_independent_of_candidate_cap_and_hop_limit() -> None:
    nodes, edges = _sample_graph_data()
    now = datetime.now(UTC)
    edges.append(
        GraphEdge(
            "e_direct",
            NodeKind.ASSET,
            "web",
            NodeKind.ASSET,
            "db",
            RelationType.CONNECTS_TO,
            FactKind.OBSERVED_FACT,
            0.99,
            now - timedelta(days=1),
            edge_metadata={"network_reachable": True},
        )
    )
    graph, _ = build_networkx_graph(nodes, edges)
    capped = find_attack_paths(
        graph,
        PathSearchConstraints(
            start_node_keys=["asset:web"],
            target_node_keys=["asset:db"],
            max_hops=5,
            max_candidates=1,
            top_k=1,
        ),
    )
    assert capped.is_truncated is True
    assert len(capped.paths) == 1

    verification = verify_reachability(
        graph,
        PathSearchConstraints(
            start_node_keys=["asset:web"],
            target_node_keys=["asset:db"],
            max_hops=1,
            max_candidates=1,
            top_k=1,
        ),
    )
    assert verification.reachable_unbounded is True
    assert verification.reachable_within_max_hops is True
    assert verification.complete is True

    too_short = verify_reachability(
        graph,
        PathSearchConstraints(
            start_node_keys=["asset:web"],
            target_node_keys=["asset:db"],
            max_hops=0,
        ),
    )
    assert too_short.reachable_unbounded is True
    assert too_short.reachable_within_max_hops is False
    assert too_short.status == "REACHABLE_OUTSIDE_HOP_LIMIT"



def test_explicit_preconditions_do_not_override_mandatory_cve_gate() -> None:
    now = datetime.now(UTC)
    nodes = [
        GraphNode(NodeKind.ASSET, "web", "web", is_external_entry=True),
        GraphNode(NodeKind.ASSET, "db", "db", criticality="critical"),
    ]
    edge = GraphEdge(
        "explicit-cve",
        NodeKind.ASSET,
        "web",
        NodeKind.ASSET,
        "db",
        RelationType.CONNECTS_TO,
        FactKind.OBSERVED_FACT,
        0.95,
        now,
        edge_metadata={
            "preconditions": [{"kind": "network_reachable", "status": True}],
            "requires_cve": "CVE-2024-56789",
        },
    )
    graph, _ = build_networkx_graph(nodes, [edge])
    constraints = PathSearchConstraints(
        start_node_keys=["asset:web"],
        target_node_keys=["asset:db"],
        max_hops=1,
        allow_unknown_preconditions=False,
    )
    # The custom network precondition is true, but the separate mandatory CVE state
    # remains unknown and therefore cannot pass confirmed-only traversal.
    assert find_attack_paths(graph, constraints).paths == []
    edge.edge_metadata["vulnerability_status"] = {"CVE-2024-56789": "open"}
    edge.edge_metadata["network_reachable"] = True
    edge.edge_metadata["acl_action"] = "allow"
    graph_open, _ = build_networkx_graph(nodes, [edge])
    assert len(find_attack_paths(graph_open, constraints).paths) == 1

    # Explicit custom preconditions cannot override a contradictory ACL deny.
    edge.edge_metadata["acl_action"] = "deny"
    graph_denied, _ = build_networkx_graph(nodes, [edge])
    assert find_attack_paths(graph_denied, constraints).paths == []



def test_conflicting_network_and_acl_evidence_blocks_transition() -> None:
    now = datetime.now(UTC)
    nodes = [
        GraphNode(NodeKind.ASSET, "web", "web", is_external_entry=True),
        GraphNode(NodeKind.ASSET, "db", "db", criticality="critical"),
    ]
    edge = GraphEdge(
        "conflicting-network-evidence",
        NodeKind.ASSET,
        "web",
        NodeKind.ASSET,
        "db",
        RelationType.CONNECTS_TO,
        FactKind.OBSERVED_FACT,
        0.99,
        now,
        edge_metadata={
            "network_reachable": True,
            "acl_action": "deny",
            "acl_rule": "FW-42",
        },
    )
    graph, _ = build_networkx_graph(nodes, [edge])
    constraints = PathSearchConstraints(
        start_node_keys=["asset:web"],
        target_node_keys=["asset:db"],
        max_hops=1,
    )
    assert find_attack_paths(graph, constraints).paths == []
    result = verify_reachability(graph, constraints)
    assert result.complete is True
    assert result.reachable_unbounded is False



def test_cve_precondition_uses_endpoint_finding_state_without_edge_duplication() -> None:
    now = datetime.now(UTC)
    nodes = [
        GraphNode(
            NodeKind.ASSET,
            "web",
            "web",
            is_external_entry=True,
            metadata={"vulnerability_status": {"CVE-2024-24680": "open"}},
        ),
        GraphNode(NodeKind.ASSET, "db", "db", criticality="critical"),
    ]
    edge = GraphEdge(
        "node-cve",
        NodeKind.ASSET,
        "web",
        NodeKind.ASSET,
        "db",
        RelationType.CONNECTS_TO,
        FactKind.OBSERVED_FACT,
        0.94,
        now,
        edge_metadata={"network_reachable": True, "requires_cve": "CVE-2024-24680"},
    )
    strict = PathSearchConstraints(
        start_node_keys=["asset:web"],
        target_node_keys=["asset:db"],
        max_hops=1,
        allow_unknown_preconditions=False,
    )
    graph, _ = build_networkx_graph(nodes, [edge])
    assert len(find_attack_paths(graph, strict).paths) == 1

    nodes[0].metadata["vulnerability_status"]["CVE-2024-24680"] = "patched"
    graph_patched, _ = build_networkx_graph(nodes, [edge])
    assert find_attack_paths(graph_patched, strict).paths == []



def test_explicit_admin_precondition_does_not_bypass_admin_state() -> None:
    now = datetime.now(UTC)
    nodes = [
        GraphNode(NodeKind.IDENTITY, "operator", "operator"),
        GraphNode(NodeKind.ASSET, "server", "server", criticality="critical"),
    ]
    edge = GraphEdge(
        "admin-gate",
        NodeKind.IDENTITY,
        "operator",
        NodeKind.ASSET,
        "server",
        RelationType.CAN_ADMINISTER,
        FactKind.OBSERVED_FACT,
        0.95,
        now,
        edge_metadata={
            "preconditions": [{"kind": "mfa_gate", "status": True}],
        },
    )
    graph, _ = build_networkx_graph(nodes, [edge])
    constraints = PathSearchConstraints(
        start_node_keys=["identity:operator"],
        target_node_keys=["asset:server"],
        max_hops=1,
        allow_unknown_preconditions=False,
    )
    # MFA is satisfied, but whether the admin capability is enabled remains unknown.
    assert find_attack_paths(graph, constraints).paths == []
    edge.edge_metadata["admin_enabled"] = True
    graph_enabled, _ = build_networkx_graph(nodes, [edge])
    assert len(find_attack_paths(graph_enabled, constraints).paths) == 1
