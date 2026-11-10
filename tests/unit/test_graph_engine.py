from datetime import UTC, datetime, timedelta

from app.domain.graph_engine import build_networkx_graph, find_attack_paths
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
