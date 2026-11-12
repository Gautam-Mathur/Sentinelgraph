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


def test_parallel_relationship_centrality_is_keyed_and_weight_aware() -> None:
    now = datetime.now(UTC)
    nodes = [
        GraphNode(NodeKind.ASSET, "web", "web", is_external_entry=True),
        GraphNode(NodeKind.ASSET, "app", "app"),
    ]
    edges = [
        GraphEdge(
            "fast-connect",
            NodeKind.ASSET,
            "web",
            NodeKind.ASSET,
            "app",
            RelationType.CONNECTS_TO,
            FactKind.OBSERVED_FACT,
            0.99,
            now,
            edge_metadata={"network_reachable": True},
        ),
        GraphEdge(
            "slow-expose",
            NodeKind.ASSET,
            "web",
            NodeKind.ASSET,
            "app",
            RelationType.EXPOSES,
            FactKind.OBSERVED_FACT,
            0.30,
            now,
            edge_metadata={"network_reachable": True},
        ),
    ]

    graph, stats = build_networkx_graph(nodes, edges)

    assert graph.number_of_edges() == 2
    assert set(stats.edge_betweenness) == {"fast-connect", "slow-expose"}
    assert stats.edge_betweenness["fast-connect"] > stats.edge_betweenness["slow-expose"]
    assert stats.edge_betweenness["slow-expose"] == 0.0
    by_id = {item["edge_id"]: item for item in stats.top_bridge_edges}
    assert by_id["fast-connect"]["betweenness_centrality"] == stats.edge_betweenness["fast-connect"]
    assert "slow-expose" not in by_id  # zero-centrality edges are intentionally omitted from bridge highlights


def test_explicitly_false_cve_precondition_is_excluded_from_active_graph() -> None:
    now = datetime.now(UTC)
    nodes = [
        GraphNode(
            NodeKind.ASSET,
            "web",
            "web",
            is_external_entry=True,
            metadata={"vulnerability_status": {"CVE-2024-12345": "patched"}},
        ),
        GraphNode(NodeKind.ASSET, "app", "app", criticality="critical", is_crown_jewel=True),
    ]
    edge = GraphEdge(
        "patched-cve-edge",
        NodeKind.ASSET,
        "web",
        NodeKind.ASSET,
        "app",
        RelationType.CONNECTS_TO,
        FactKind.OBSERVED_FACT,
        0.90,
        now,
        edge_metadata={
            "network_reachable": True,
            "requires_cve": "CVE-2024-12345",
        },
    )

    graph, stats = build_networkx_graph(nodes, [edge])

    assert edge.confidence == 0.90
    assert graph.number_of_edges() == 0
    assert stats.edge_count == 0
    assert stats.blocked_precondition_edge_count == 1
    assert find_attack_paths(
        graph,
        PathSearchConstraints(
            start_node_keys=["asset:web"],
            target_node_keys=["asset:app"],
            max_hops=2,
        ),
    ).paths == []


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

    # Reachability verification always reports possible routes, even when the
    # caller requested confirmed-only candidate enumeration.
    strict_verification = verify_reachability(graph, confirmed_constraints)
    assert strict_verification.reachable_unbounded is True
    assert strict_verification.confirmed_reachable_unbounded is False
    assert strict_verification.conditional_witness_edge_ids


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
    assert capped.candidate_search_complete is False
    assert capped.top_k_is_global is False
    assert capped.ranking_scope == "evaluated_candidate_pool"
    assert len(capped.paths) == 1
    assert capped.paths[0].algorithm_params["top_k_is_global"] is False

    # A top_k response can be globally ranked when candidate enumeration itself completed.
    exhaustive_top_k = find_attack_paths(
        graph,
        PathSearchConstraints(
            start_node_keys=["asset:web"],
            target_node_keys=["asset:db"],
            max_hops=5,
            max_candidates=10,
            top_k=1,
        ),
    )
    assert exhaustive_top_k.candidate_search_complete is True
    assert exhaustive_top_k.top_k_is_global is True
    assert exhaustive_top_k.ranking_scope == "global_candidate_universe"
    assert exhaustive_top_k.is_truncated is True  # response was clipped to top_k

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
            "pam_enforced": False,
            "mfa_required": True,
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

    # A typed positive assertion must not override contradictory observed MFA state.
    edge.edge_metadata["mfa_satisfied"] = False
    graph_conflicting, _ = build_networkx_graph(nodes, [edge])
    assert find_attack_paths(graph_conflicting, constraints).paths == []


def test_kleene_three_valued_compound_preconditions() -> None:
    from app.domain.preconditions import (
        FALSE,
        TRUE,
        UNKNOWN,
        edge_preconditions_allow,
        evaluate_precondition_expr,
    )

    now = datetime.now(UTC)
    src = GraphNode(NodeKind.ASSET, "src", "src", is_external_entry=True)
    tgt = GraphNode(
        NodeKind.ASSET,
        "tgt",
        "tgt",
        criticality="critical",
        metadata={"registry": {"spnego_enabled": True, "smb_signing": False}},
    )
    edge = GraphEdge(
        "expr-edge",
        NodeKind.ASSET,
        "src",
        NodeKind.ASSET,
        "tgt",
        RelationType.CONNECTS_TO,
        FactKind.OBSERVED_FACT,
        0.95,
        now,
    )

    # ALL(false, unknown) == FALSE
    s_all_false, _ = evaluate_precondition_expr(
        {
            "ALL": [
                {"field": "registry.smb_signing", "expected": True, "scope": "target"},
                {"field": "registry.missing_flag", "expected": True, "scope": "target"},
            ]
        },
        edge,
        src,
        tgt,
    )
    assert s_all_false == FALSE

    # ALL(true, unknown) == UNKNOWN
    s_all_unk, _ = evaluate_precondition_expr(
        {
            "ALL": [
                {"field": "registry.spnego_enabled", "expected": True, "scope": "target"},
                {"field": "registry.missing_flag", "expected": True, "scope": "target"},
            ]
        },
        edge,
        src,
        tgt,
    )
    assert s_all_unk == UNKNOWN

    # ANY(true, unknown) == TRUE
    s_any_true, _ = evaluate_precondition_expr(
        {
            "ANY": [
                {"field": "registry.missing_flag", "expected": True, "scope": "target"},
                {"field": "registry.spnego_enabled", "expected": True, "scope": "target"},
            ]
        },
        edge,
        src,
        tgt,
    )
    assert s_any_true == TRUE

    # NOT(unknown) == UNKNOWN, NOT(false) == TRUE
    assert evaluate_precondition_expr({"NOT": {"field": "registry.missing", "scope": "target"}}, edge, src, tgt)[0] == UNKNOWN
    assert evaluate_precondition_expr({"NOT": {"field": "registry.smb_signing", "expected": True, "scope": "target"}}, edge, src, tgt)[0] == TRUE

    # Composite edge expression with ANY + NOT gates
    edge.edge_metadata["network_reachable"] = True
    edge.edge_metadata["precondition_expr"] = {
        "ALL": [
            {"field": "registry.spnego_enabled", "expected": True, "scope": "target"},
            {"NOT": {"field": "registry.smb_signing", "expected": True, "scope": "target"}},
        ]
    }
    assert edge_preconditions_allow(edge, allow_unknown=False, source_node=src, target_node=tgt) is True

    # Flip smb_signing=True -> NOT(TRUE) == FALSE -> blocks edge even when allow_unknown=True
    tgt.metadata["registry"]["smb_signing"] = True
    assert edge_preconditions_allow(edge, allow_unknown=True, source_node=src, target_node=tgt) is False


def test_stateful_cross_hop_capability_tracking_and_diamond_reachability() -> None:
    now = datetime.now(UTC)
    nodes = [
        GraphNode(NodeKind.ASSET, "web", "web-entry", is_external_entry=True),
        GraphNode(NodeKind.ASSET, "app_a", "app-pivot"),
        GraphNode(NodeKind.IDENTITY, "app_b", "svc-cred-issuer"),
        GraphNode(NodeKind.ASSET, "db", "db-crown", criticality="critical", is_crown_jewel=True),
    ]
    # Direct fake branch: web -> app_a -> db lacks cred:etl
    # Valid longer branch: web -> app_b (adds cred:etl) -> app_a -> db
    edges = [
        GraphEdge(
            "e_web_a",
            NodeKind.ASSET,
            "web",
            NodeKind.ASSET,
            "app_a",
            RelationType.CONNECTS_TO,
            FactKind.OBSERVED_FACT,
            0.95,
            now,
            edge_metadata={"network_reachable": True},
        ),
        GraphEdge(
            "e_a_db",
            NodeKind.ASSET,
            "app_a",
            NodeKind.ASSET,
            "db",
            RelationType.CAN_ADMINISTER,
            FactKind.OBSERVED_FACT,
            0.95,
            now,
            edge_metadata={
                "admin_enabled": True,
                "pam_enforced": False,
                "mfa_required": False,
                "requires_capabilities": ["cred:etl"],
            },
        ),
        GraphEdge(
            "e_web_b",
            NodeKind.ASSET,
            "web",
            NodeKind.IDENTITY,
            "app_b",
            RelationType.HAS_ROLE,
            FactKind.OBSERVED_FACT,
            0.95,
            now,
            edge_metadata={
                "credential_available": True,
                "adds_capabilities": ["cred:etl"],
            },
        ),
        GraphEdge(
            "e_b_a",
            NodeKind.IDENTITY,
            "app_b",
            NodeKind.ASSET,
            "app_a",
            RelationType.CONNECTS_TO,
            FactKind.OBSERVED_FACT,
            0.95,
            now,
            edge_metadata={"network_reachable": True},
        ),
    ]

    # 1. Without the credential-granting branch, the short path web -> app_a -> db is fake and blocked.
    fake_only_graph, _ = build_networkx_graph(nodes, edges[:2])
    constraints = PathSearchConstraints(
        start_node_keys=["asset:web"],
        target_node_keys=["asset:db"],
        max_hops=4,
        allow_unknown_preconditions=False,
    )
    assert find_attack_paths(fake_only_graph, constraints).paths == []
    fake_verify = verify_reachability(fake_only_graph, constraints)
    assert fake_verify.reachable_unbounded is False
    assert fake_verify.confirmed_reachable_unbounded is False

    # 2. With the credential-issuing branch, BFS & A* must revisit app_a under the richer state
    #    and accept ONLY web -> app_b -> app_a -> db (never the 2-hop fake path).
    diamond_graph, _ = build_networkx_graph(nodes, edges)
    dijk_out = find_attack_paths(diamond_graph, constraints)
    bfs_out = find_attack_paths(
        diamond_graph,
        PathSearchConstraints(
            start_node_keys=["asset:web"],
            target_node_keys=["asset:db"],
            algorithm=AlgorithmType.BFS,
            max_hops=4,
            allow_unknown_preconditions=False,
        ),
    )
    assert len(dijk_out.paths) == 1
    assert len(bfs_out.paths) == 1
    assert [s.relationship_id for s in dijk_out.paths[0].steps] == ["e_web_b", "e_b_a", "e_a_db"]
    assert [s.relationship_id for s in bfs_out.paths[0].steps] == ["e_web_b", "e_b_a", "e_a_db"]
    assert "cred:etl" in dijk_out.paths[0].steps[0].capabilities_added

    diamond_verify = verify_reachability(diamond_graph, constraints)
    assert diamond_verify.reachable_unbounded is True
    assert diamond_verify.confirmed_reachable_unbounded is True
    assert diamond_verify.witness_path_edge_ids == ["e_web_b", "e_b_a", "e_a_db"]


def test_non_monotonic_revocation_expiry_mfa_and_registry_config_gates() -> None:
    now = datetime.now(UTC)
    nodes = [
        GraphNode(NodeKind.ASSET, "web", "web", is_external_entry=True),
        GraphNode(NodeKind.ASSET, "mid", "mid"),
        GraphNode(
            NodeKind.ASSET,
            "db",
            "db",
            criticality="critical",
            is_crown_jewel=True,
            metadata={"registry": {"winrm_enabled": False}},
        ),
    ]
    e1 = GraphEdge(
        "e1",
        NodeKind.ASSET,
        "web",
        NodeKind.ASSET,
        "mid",
        RelationType.CONNECTS_TO,
        FactKind.OBSERVED_FACT,
        0.95,
        now,
        edge_metadata={"network_reachable": True, "adds_capabilities": ["cred:svc"]},
    )
    e2 = GraphEdge(
        "e2",
        NodeKind.ASSET,
        "mid",
        NodeKind.ASSET,
        "db",
        RelationType.CONNECTS_TO,
        FactKind.OBSERVED_FACT,
        0.95,
        now,
        edge_metadata={
            "network_reachable": True,
            "requires_capabilities": ["cred:svc"],
            "removes_capabilities": ["cred:svc"],
        },
    )
    g1, _ = build_networkx_graph(nodes, [e1, e2])
    c1 = PathSearchConstraints(
        start_node_keys=["asset:web"],
        target_node_keys=["asset:db"],
        max_hops=3,
    )
    res_ok = find_attack_paths(g1, c1)
    assert len(res_ok.paths) == 1
    assert "cred:svc" in res_ok.paths[0].steps[1].capabilities_removed

    # Step 1 revokes cred:svc before Step 2 can consume it
    e1.edge_metadata["removes_capabilities"] = ["cred:svc"]
    e1.edge_metadata["adds_capabilities"] = []
    g_revoked, _ = build_networkx_graph(nodes, [e1, e2])
    assert find_attack_paths(g_revoked, c1).paths == []
    assert verify_reachability(g_revoked, c1).reachable_unbounded is False

    # Restore cred:svc, then verify token_expired, mfa_required=True without mfa_satisfied, and registry gate each block.
    e1.edge_metadata["adds_capabilities"] = ["cred:svc"]
    e1.edge_metadata.pop("removes_capabilities", None)
    e2.edge_metadata["token_expired"] = True
    g_exp, _ = build_networkx_graph(nodes, [e1, e2])
    assert find_attack_paths(g_exp, c1).paths == []

    e2.edge_metadata.pop("token_expired", None)
    e2.edge_metadata["mfa_required"] = True
    e2.edge_metadata["mfa_satisfied"] = False
    g_mfa, _ = build_networkx_graph(nodes, [e1, e2])
    assert find_attack_paths(g_mfa, c1).paths == []

    e2.edge_metadata["mfa_satisfied"] = True
    e2.edge_metadata["requires_config"] = {"registry.winrm_enabled": True}
    g_reg, _ = build_networkx_graph(nodes, [e1, e2])
    assert find_attack_paths(g_reg, c1).paths == []


def test_tight_max_candidates_does_not_starve_low_confidence_crown_jewel_in_structural_mode() -> None:
    now = datetime.now(UTC)
    nodes = [
        GraphNode(NodeKind.ASSET, "entry", "entry", is_external_entry=True),
        GraphNode(NodeKind.ASSET, "pivot", "pivot"),
        GraphNode(NodeKind.ASSET, "decoy", "decoy-low", criticality="low", is_crown_jewel=True),
        GraphNode(NodeKind.ASSET, "crown", "crown-prod", criticality="critical", is_crown_jewel=True),
    ]
    edges = [
        # 2-hop high-confidence decoy route (CONNECTS_TO -> DEPENDS_ON, structural cost = 1.0 + 1.0 = 2.0)
        GraphEdge(
            "d1",
            NodeKind.ASSET,
            "entry",
            NodeKind.ASSET,
            "pivot",
            RelationType.CONNECTS_TO,
            FactKind.OBSERVED_FACT,
            0.99,
            now,
            edge_metadata={"network_reachable": True},
        ),
        GraphEdge(
            "d2",
            NodeKind.ASSET,
            "pivot",
            NodeKind.ASSET,
            "decoy",
            RelationType.DEPENDS_ON,
            FactKind.OBSERVED_FACT,
            0.99,
            now,
        ),
        # 2-hop low-confidence inferred EXPOSES + CAN_ADMINISTER Crown Jewel route (structural cost = 0.95 + 0.85 = 1.80)
        GraphEdge(
            "c1",
            NodeKind.ASSET,
            "entry",
            NodeKind.ASSET,
            "crown",
            RelationType.CAN_ADMINISTER,
            FactKind.INFERRED_RELATIONSHIP,
            0.25,
            now,
            edge_metadata={"admin_enabled": True, "pam_enforced": False, "mfa_required": False},
        ),
    ]
    graph, _ = build_networkx_graph(nodes, edges)

    # Under structural mode with max_candidates=1, CAN_ADMINISTER (0.85) is discovered before high-conf decoy.
    out_struct = find_attack_paths(
        graph,
        PathSearchConstraints(
            start_node_keys=["asset:entry"],
            target_node_keys=["asset:decoy", "asset:crown"],
            max_hops=3,
            max_candidates=1,
            top_k=1,
            ranking_mode="structural",
        ),
    )
    assert len(out_struct.paths) == 1
    assert out_struct.paths[0].target_node_id == "crown"

    # Under legacy evidence_weighted mode with max_candidates=1, low-conf inferred cost pushes crown out.
    out_weighted = find_attack_paths(
        graph,
        PathSearchConstraints(
            start_node_keys=["asset:entry"],
            target_node_keys=["asset:decoy", "asset:crown"],
            max_hops=3,
            max_candidates=1,
            top_k=1,
            ranking_mode="evidence_weighted",
        ),
    )
    assert len(out_weighted.paths) == 1
    assert out_weighted.paths[0].target_node_id == "decoy"
