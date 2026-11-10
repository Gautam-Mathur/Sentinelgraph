import time
from datetime import UTC, datetime

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


def test_scale_baseline_2500_nodes_12000_edges_under_sla() -> None:
    now = datetime.now(UTC)
    num_nodes = 2500
    nodes: list[GraphNode] = []
    for idx in range(num_nodes):
        nodes.append(
            GraphNode(
                node_kind=NodeKind.ASSET,
                node_id=f"n-{idx:04d}",
                label=f"node-{idx:04d}",
                criticality="critical" if idx >= num_nodes - 5 else "medium",
                environment="prod",
                is_external_entry=(idx < 5),
                is_crown_jewel=(idx >= num_nodes - 5),
                privilege_level="standard",
            )
        )

    # Create ~12,000 deterministic edges forming sparse forward layers + cross-links
    edges: list[GraphEdge] = []
    edge_idx = 0
    for idx in range(num_nodes - 1):
        for offset in (1, 7, 31, 97, 251):
            tgt = min(num_nodes - 1, idx + offset)
            if tgt <= idx:
                continue
            edges.append(
                GraphEdge(
                    edge_id=f"e-{edge_idx:05d}",
                    source_kind=NodeKind.ASSET,
                    source_id=f"n-{idx:04d}",
                    target_kind=NodeKind.ASSET,
                    target_id=f"n-{tgt:04d}",
                    relation_type=RelationType.CONNECTS_TO,
                    fact_kind=FactKind.OBSERVED_FACT,
                    confidence=0.85,
                    valid_from=now,
                )
            )
            edge_idx += 1

    assert len(edges) > 10000

    t0 = time.perf_counter()
    graph, stats = build_networkx_graph(nodes, edges, as_of=now)
    build_ms = (time.perf_counter() - t0) * 1000.0

    assert stats.node_count == num_nodes
    assert stats.edge_count == len(edges)
    # Betweenness on 2500 nodes / 12000 edges typically finishes well under 30s; assert reasonable bound
    assert build_ms < 30000.0

    constraints = PathSearchConstraints(
        start_node_keys=["asset:n-0000"],
        target_node_keys=[f"asset:n-{num_nodes - 1:04d}"],
        algorithm=AlgorithmType.DIJKSTRA,
        max_hops=10,
        max_candidates=200,
        top_k=10,
        timeout_seconds=5.0,
    )
    out = find_attack_paths(graph, constraints)
    assert out.duration_ms < 5000.0
    assert len(out.paths) <= 10
    assert out.paths[0].hop_count <= 10
