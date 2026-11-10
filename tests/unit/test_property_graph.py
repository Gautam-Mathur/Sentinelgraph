import random
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


def test_random_graphs_satisfy_determinism_and_bound_invariants() -> None:
    rng = random.Random(20261110)  # noqa: S311
    now = datetime.now(UTC)

    for trial in range(25):
        n_nodes = rng.randint(5, 16)
        nodes = [
            GraphNode(
                node_kind=NodeKind.ASSET,
                node_id=f"n{i}",
                label=f"host-{i}",
                criticality="critical" if i == n_nodes - 1 else "medium",
                is_external_entry=(i == 0),
                is_crown_jewel=(i == n_nodes - 1),
            )
            for i in range(n_nodes)
        ]
        edges: list[GraphEdge] = []
        valid_ids: set[str] = set()
        for e_idx in range(n_nodes * 2):
            u = rng.randint(0, n_nodes - 1)
            v = rng.randint(0, n_nodes - 1)
            if u == v:
                continue
            eid = f"edge-{trial}-{e_idx}"
            fact = rng.choice([FactKind.OBSERVED_FACT, FactKind.INFERRED_RELATIONSHIP])
            conf = round(rng.uniform(0.15, 0.99), 2)
            edges.append(
                GraphEdge(
                    edge_id=eid,
                    source_kind=NodeKind.ASSET,
                    source_id=f"n{u}",
                    target_kind=NodeKind.ASSET,
                    target_id=f"n{v}",
                    relation_type=RelationType.CONNECTS_TO,
                    fact_kind=fact,
                    confidence=conf,
                    valid_from=now - timedelta(days=1),
                )
            )
            valid_ids.add(eid)

        max_hops = rng.randint(2, 6)
        min_conf = 0.3
        constraints = PathSearchConstraints(
            start_node_keys=["asset:n0"],
            target_node_keys=[f"asset:n{n_nodes - 1}"],
            algorithm=rng.choice([AlgorithmType.DIJKSTRA, AlgorithmType.BFS]),
            min_confidence=min_conf,
            max_hops=max_hops,
            max_candidates=100,
            top_k=5,
        )
        graph, _ = build_networkx_graph(nodes, edges)
        res1 = find_attack_paths(graph, constraints)
        res2 = find_attack_paths(graph, constraints)

        assert [p.determinism_hash for p in res1.paths] == [
            p.determinism_hash for p in res2.paths
        ]
        assert len(res1.paths) <= 5
        for path in res1.paths:
            assert 1 <= path.hop_count <= max_hops
            assert 0.0 <= path.priority_score <= 100.0
            for step in path.steps:
                assert step.relationship_id in valid_ids
                assert step.confidence >= min_conf
