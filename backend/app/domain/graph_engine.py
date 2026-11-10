import hashlib
import heapq
import json
import time
from collections import deque
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any

import networkx as nx

from app.domain.models import (
    AlgorithmType,
    AttackPathResult,
    FactKind,
    GraphEdge,
    GraphNode,
    PathSearchConstraints,
    PathStepData,
)
from app.domain.path_semantics import build_path_explanation, build_step_explanation
from app.domain.preconditions import (
    edge_preconditions_allow,
    evaluate_edge_preconditions,
    precondition_summary,
)
from app.domain.scoring import SCORING_VERSION, score_attack_path


@dataclass
class GraphBuildStats:
    node_count: int
    edge_count: int
    suppressed_edge_count: int
    expired_edge_count: int
    scc_cycle_count: int
    scc_cycles: list[list[str]]
    top_bridge_nodes: list[dict[str, Any]]
    build_duration_ms: float
    top_bridge_edges: list[dict[str, Any]] = field(default_factory=list)
    edge_betweenness: dict[str, float] = field(default_factory=dict)
    blocked_precondition_edge_count: int = 0


@dataclass
class PathSearchOutput:
    paths: list[AttackPathResult]
    candidates_evaluated: int
    is_truncated: bool
    truncation_reason: str | None
    duration_ms: float
    bridge_nodes: list[dict[str, Any]] = field(default_factory=list)
    scc_cycles: list[list[str]] = field(default_factory=list)
    candidate_search_complete: bool = True
    top_k_is_global: bool = True
    ranking_scope: str = "global_candidate_universe"


@dataclass
class ReachabilityVerification:
    reachable_unbounded: bool
    reachable_within_max_hops: bool
    confirmed_reachable_unbounded: bool
    complete: bool
    status: str
    witness_path_node_keys: list[str] = field(default_factory=list)
    witness_path_edge_ids: list[str] = field(default_factory=list)
    conditional_witness_edge_ids: list[str] = field(default_factory=list)
    confirmed_witness_edge_ids: list[str] = field(default_factory=list)
    reachable_target_keys: list[str] = field(default_factory=list)
    examined_nodes: int = 0
    examined_edges: int = 0
    max_hops: int = 0
    method: str = "multi_source_bfs"


def edge_traversal_cost(edge: GraphEdge) -> float:
    """Lower cost means higher attacker feasibility / higher evidence confidence."""
    conf = max(0.05, min(1.0, edge.confidence))
    fact_penalty = 1.45 if edge.fact_kind == FactKind.INFERRED_RELATIONSHIP else 1.0
    return round((1.15 - conf) * fact_penalty + 0.1, 6)


def build_networkx_graph(
    nodes: list[GraphNode],
    edges: list[GraphEdge],
    *,
    as_of: datetime | None = None,
) -> tuple[nx.MultiDiGraph, GraphBuildStats]:
    t0 = time.perf_counter()
    graph = nx.MultiDiGraph()
    ref_time = as_of or datetime.now(UTC)

    # Deterministic insertion ordering
    for node in sorted(nodes, key=lambda n: n.key):
        graph.add_node(node.key, node=node)

    suppressed_count = 0
    expired_count = 0
    blocked_precondition_count = 0
    active_edges = 0

    for edge in sorted(edges, key=lambda e: (e.source_key, e.target_key, e.edge_id)):
        if edge.is_suppressed:
            suppressed_count += 1
            continue
        if edge.valid_to is not None and edge.valid_to < ref_time:
            expired_count += 1
            continue
        if edge.valid_from > ref_time:
            continue
        if edge.source_key not in graph or edge.target_key not in graph:
            continue
        source_node: GraphNode = graph.nodes[edge.source_key]["node"]
        target_node: GraphNode = graph.nodes[edge.target_key]["node"]
        # Explicitly false transition prerequisites are not active graph relationships.
        # Unknown prerequisites remain visible as conditional hypotheses.
        if not edge_preconditions_allow(
            edge,
            allow_unknown=True,
            source_node=source_node,
            target_node=target_node,
        ):
            blocked_precondition_count += 1
            continue
        graph.add_edge(
            edge.source_key,
            edge.target_key,
            key=edge.edge_id,
            edge=edge,
            weight=edge_traversal_cost(edge),
        )
        active_edges += 1

    simple_di = nx.DiGraph()
    for node_key in sorted(graph.nodes):
        simple_di.add_node(node_key)
    for u, v, data in graph.edges(data=True):
        w = float(data["weight"])
        if simple_di.has_edge(u, v):
            if w < float(simple_di[u][v]["weight"]):
                simple_di[u][v]["weight"] = w
        else:
            simple_di.add_edge(u, v, weight=w)

    sccs = [sorted(comp) for comp in nx.strongly_connected_components(simple_di) if len(comp) > 1]
    sccs.sort(key=lambda c: (-len(c), c[0]))

    node_count = simple_di.number_of_nodes()
    if node_count > 400:
        centrality = nx.betweenness_centrality(
            simple_di, k=min(200, node_count), normalized=True, seed=42
        )
        raw_edge_centrality = nx.edge_betweenness_centrality(
            graph, k=min(200, node_count), normalized=True, weight="weight", seed=42
        )
    elif node_count > 1:
        centrality = nx.betweenness_centrality(simple_di, normalized=True)
        raw_edge_centrality = nx.edge_betweenness_centrality(
            graph, normalized=True, weight="weight"
        )
    else:
        centrality = {}
        raw_edge_centrality = {}

    bridge_nodes: list[dict[str, Any]] = []
    for nkey, score in sorted(centrality.items(), key=lambda kv: (-kv[1], kv[0])):
        if score <= 0.0:
            continue
        node_obj: GraphNode = graph.nodes[nkey]["node"]
        bridge_nodes.append(
            {
                "node_key": nkey,
                "label": node_obj.label,
                "node_kind": node_obj.node_kind.value,
                "betweenness_centrality": round(score, 4),
            }
        )
        if len(bridge_nodes) >= 10:
            break

    edge_betweenness_map: dict[str, float] = {}
    bridge_edges: list[dict[str, Any]] = []
    for u, v, edge_key, data in sorted(
        graph.edges(keys=True, data=True),
        key=lambda item: (
            -float(raw_edge_centrality.get((item[0], item[1], item[2]), 0.0)),
            str(item[2]),
        ),
    ):
        e_obj: GraphEdge = data["edge"]
        ec = round(float(raw_edge_centrality.get((u, v, edge_key), 0.0)), 4)
        edge_betweenness_map[e_obj.edge_id] = ec
        if ec > 0.0 and len(bridge_edges) < 10:
            src_lbl = graph.nodes[u]["node"].label
            tgt_lbl = graph.nodes[v]["node"].label
            bridge_edges.append(
                {
                    "edge_id": e_obj.edge_id,
                    "source_key": u,
                    "source_label": src_lbl,
                    "target_key": v,
                    "target_label": tgt_lbl,
                    "relation_type": e_obj.relation_type.value,
                    "betweenness_centrality": ec,
                }
            )

    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    stats = GraphBuildStats(
        node_count=graph.number_of_nodes(),
        edge_count=active_edges,
        suppressed_edge_count=suppressed_count,
        expired_edge_count=expired_count,
        scc_cycle_count=len(sccs),
        scc_cycles=sccs[:20],
        top_bridge_nodes=bridge_nodes,
        build_duration_ms=elapsed_ms,
        top_bridge_edges=bridge_edges,
        edge_betweenness=edge_betweenness_map,
        blocked_precondition_edge_count=blocked_precondition_count,
    )
    return graph, stats


def _edge_allowed(
    edge: GraphEdge,
    constraints: PathSearchConstraints,
    source_node: GraphNode | None = None,
    target_node: GraphNode | None = None,
) -> bool:
    if edge.is_suppressed or edge.confidence < constraints.min_confidence:
        return False
    if not constraints.include_inferred and edge.fact_kind == FactKind.INFERRED_RELATIONSHIP:
        return False
    if constraints.allowed_edge_types is not None and edge.relation_type not in constraints.allowed_edge_types:
        return False
    return edge_preconditions_allow(
        edge,
        allow_unknown=constraints.allow_unknown_preconditions,
        source_node=source_node,
        target_node=target_node,
    )


def _node_allowed(node: GraphNode, constraints: PathSearchConstraints) -> bool:
    if node.key in constraints.excluded_node_keys:
        return False
    return node.environment not in constraints.excluded_environments


def _compute_determinism_hash(
    start_key: str,
    target_key: str,
    edge_ids: list[str],
    algorithm: str,
    scoring_version: str,
    allow_unknown_preconditions: bool = True,
) -> str:
    canonical = json.dumps(
        {
            "start": start_key,
            "target": target_key,
            "edges": edge_ids,
            "algorithm": algorithm,
            "scoring_version": scoring_version,
            "allow_unknown_preconditions": allow_unknown_preconditions,
        },
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _compute_target_lower_bounds(
    graph: nx.MultiDiGraph,
    target_set: set[str],
    constraints: PathSearchConstraints,
) -> tuple[dict[str, float], dict[str, int]]:
    """Reverse multi-source bounds for admissible A* pruning and hop-budget cutoff."""
    rev_filtered = nx.DiGraph()
    for nkey, data in graph.nodes(data=True):
        if _node_allowed(data["node"], constraints):
            rev_filtered.add_node(nkey)

    for u, v, _, data in graph.edges(keys=True, data=True):
        if u not in rev_filtered or v not in rev_filtered:
            continue
        edge_obj: GraphEdge = data["edge"]
        if not _edge_allowed(
            edge_obj, constraints, graph.nodes[u]["node"], graph.nodes[v]["node"]
        ):
            continue
        w = float(data["weight"])
        if rev_filtered.has_edge(v, u):
            if w < float(rev_filtered[v][u]["weight"]):
                rev_filtered[v][u]["weight"] = w
        else:
            rev_filtered.add_edge(v, u, weight=w)

    valid_targets = [t for t in sorted(target_set) if t in rev_filtered]
    if not valid_targets:
        return {}, {}

    dist_to_target: dict[str, float] = nx.multi_source_dijkstra_path_length(
        rev_filtered, valid_targets, weight="weight"
    )
    hops_to_target: dict[str, int] = {t: 0 for t in valid_targets}
    bfs_q: deque[str] = deque(valid_targets)
    while bfs_q:
        u = bfs_q.popleft()
        d_next = hops_to_target[u] + 1
        for v in rev_filtered.neighbors(u):
            if v not in hops_to_target:
                hops_to_target[v] = d_next
                bfs_q.append(v)
    return dist_to_target, hops_to_target



def _bfs_reachability_witness(
    graph: nx.MultiDiGraph,
    constraints: PathSearchConstraints,
    *,
    allow_unknown_preconditions: bool,
    hop_limit: int | None,
) -> tuple[list[str], list[str], list[str], int, int, list[str]]:
    """Return one shortest witness using the same transition and scope filters as path search."""
    effective_constraints = replace(
        constraints, allow_unknown_preconditions=allow_unknown_preconditions
    )
    starts = sorted(
        key
        for key in constraints.start_node_keys
        if key in graph and _node_allowed(graph.nodes[key]["node"], effective_constraints)
    )
    targets = set(constraints.target_node_keys)
    queue: deque[tuple[str, int]] = deque()
    parent: dict[str, tuple[str, str] | None] = {}
    for start in starts:
        if start not in parent:
            parent[start] = None
            queue.append((start, 0))

    examined_nodes = 0
    examined_edges = 0
    found_target: str | None = None
    reached_targets: set[str] = set()
    while queue:
        current, depth = queue.popleft()
        examined_nodes += 1
        if current in targets and depth > 0:
            reached_targets.add(current)
            if found_target is None:
                found_target = current
        if hop_limit is not None and depth >= hop_limit:
            continue

        neighbors = sorted(
            graph.out_edges(current, keys=True, data=True),
            key=lambda item: (item[1], item[2]),
        )
        for _, next_key, edge_id, data in neighbors:
            examined_edges += 1
            if next_key in parent:
                continue
            edge: GraphEdge = data["edge"]
            next_node: GraphNode = graph.nodes[next_key]["node"]
            if not _node_allowed(next_node, effective_constraints):
                continue
            if not _edge_allowed(
                edge,
                effective_constraints,
                graph.nodes[current]["node"],
                next_node,
            ):
                continue
            parent[next_key] = (current, str(edge_id))
            queue.append((next_key, depth + 1))

    if found_target is None:
        return [], [], [], examined_nodes, examined_edges, sorted(reached_targets)

    node_path = [found_target]
    edge_path: list[str] = []
    cursor = found_target
    while parent[cursor] is not None:
        previous, edge_id = parent[cursor]  # type: ignore[misc]
        node_path.append(previous)
        edge_path.append(edge_id)
        cursor = previous
    node_path.reverse()
    edge_path.reverse()

    conditional_ids = [
        edge_id
        for idx, edge_id in enumerate(edge_path)
        if any(
            outcome["status"] == "unknown"
            for outcome in evaluate_edge_preconditions(
                graph.get_edge_data(node_path[idx], node_path[idx + 1], edge_id)["edge"],
                graph.nodes[node_path[idx]]["node"],
                graph.nodes[node_path[idx + 1]]["node"],
            )
        )
    ]
    return node_path, edge_path, conditional_ids, examined_nodes, examined_edges, sorted(reached_targets)


def verify_reachability(
    graph: nx.MultiDiGraph,
    constraints: PathSearchConstraints,
) -> ReachabilityVerification:
    """Independently verify reachability without enumerating all simple paths.

    Possible reachability includes unknown prerequisites as conditional assumptions;
    confirmed reachability requires every transition prerequisite to be known true.
    The unbounded pass prevents max_hops from being mistaken for graph disconnection.
    """
    possible_nodes, possible_edges, conditional_edges, examined_nodes, examined_edges, possible_targets = (
        _bfs_reachability_witness(
            graph,
            constraints,
            allow_unknown_preconditions=True,
            hop_limit=None,
        )
    )
    _, bounded_edges, _, bounded_examined_nodes, bounded_examined_edges, bounded_targets = (
        _bfs_reachability_witness(
            graph,
            constraints,
            allow_unknown_preconditions=True,
            hop_limit=constraints.max_hops,
        )
    )
    _, confirmed_edges, _, confirmed_examined_nodes, confirmed_examined_edges, confirmed_targets = (
        _bfs_reachability_witness(
            graph,
            constraints,
            allow_unknown_preconditions=False,
            hop_limit=None,
        )
    )
    reachable = bool(possible_targets)
    bounded_reachable = bool(bounded_targets)
    confirmed_reachable = bool(confirmed_targets)
    if reachable and bounded_reachable:
        status = "REACHABLE_PATH_EXISTS"
    elif reachable:
        status = "REACHABLE_OUTSIDE_HOP_LIMIT"
    else:
        status = "NO_REACHABILITY_WITHIN_MODEL"

    return ReachabilityVerification(
        reachable_unbounded=reachable,
        reachable_within_max_hops=bounded_reachable,
        confirmed_reachable_unbounded=confirmed_reachable,
        complete=True,
        status=status,
        witness_path_node_keys=possible_nodes,
        witness_path_edge_ids=possible_edges,
        conditional_witness_edge_ids=conditional_edges,
        confirmed_witness_edge_ids=confirmed_edges,
        reachable_target_keys=possible_targets,
        examined_nodes=max(examined_nodes, bounded_examined_nodes, confirmed_examined_nodes),
        examined_edges=max(examined_edges, bounded_examined_edges, confirmed_examined_edges),
        max_hops=constraints.max_hops,
    )


def find_attack_paths(
    graph: nx.MultiDiGraph,
    constraints: PathSearchConstraints,
) -> PathSearchOutput:
    t0 = time.perf_counter()
    deadline = t0 + max(0.05, constraints.timeout_seconds)

    start_keys = sorted(k for k in constraints.start_node_keys if k in graph)
    target_set = {k for k in constraints.target_node_keys if k in graph}

    if not start_keys or not target_set:
        return PathSearchOutput(
            paths=[],
            candidates_evaluated=0,
            is_truncated=False,
            truncation_reason=None,
            duration_ms=round((time.perf_counter() - t0) * 1000.0, 2),
        )

    dist_to_target, hops_to_target = _compute_target_lower_bounds(graph, target_set, constraints)

    candidates: list[tuple[float, list[str], list[GraphEdge]]] = []
    candidates_evaluated = 0
    is_truncated = False
    candidate_search_complete = True
    truncation_reason: str | None = None
    seen_edge_sequences: set[tuple[str, ...]] = set()

    if constraints.algorithm == AlgorithmType.BFS:
        queue: deque[tuple[str, list[str], list[GraphEdge]]] = deque()
        for sk in start_keys:
            start_node: GraphNode = graph.nodes[sk]["node"]
            if _node_allowed(start_node, constraints) and sk in hops_to_target:
                queue.append((sk, [sk], []))

        while queue:
            if time.perf_counter() > deadline:
                is_truncated = True
                candidate_search_complete = False
                truncation_reason = "timeout_exceeded"
                break
            if candidates_evaluated >= constraints.max_candidates:
                is_truncated = True
                candidate_search_complete = False
                truncation_reason = "max_candidates_reached"
                break

            curr_key, path_keys, edge_seq = queue.popleft()
            if curr_key in target_set and len(edge_seq) > 0:
                seq_sig = tuple(e.edge_id for e in edge_seq)
                if seq_sig not in seen_edge_sequences:
                    seen_edge_sequences.add(seq_sig)
                    total_cost = sum(edge_traversal_cost(e) for e in edge_seq)
                    candidates.append((total_cost, path_keys, edge_seq))
                    candidates_evaluated += 1
                continue

            if len(edge_seq) >= constraints.max_hops:
                continue

            neighbors = sorted(graph.out_edges(curr_key, keys=True, data=True), key=lambda x: (x[1], x[2]))
            for _, nxt_key, _, data in neighbors:
                if nxt_key in path_keys:
                    continue
                rem_hops = hops_to_target.get(nxt_key)
                if rem_hops is None or (len(edge_seq) + 1 + rem_hops) > constraints.max_hops:
                    continue
                edge_obj: GraphEdge = data["edge"]
                nxt_node: GraphNode = graph.nodes[nxt_key]["node"]
                if not _edge_allowed(edge_obj, constraints, graph.nodes[curr_key]["node"], nxt_node):
                    continue
                if not _node_allowed(nxt_node, constraints):
                    continue
                queue.append((nxt_key, [*path_keys, nxt_key], [*edge_seq, edge_obj]))
    else:
        # Deterministic goal-directed A* best-first simple-path enumeration (exact admissible lower bound)
        heap: list[tuple[float, float, int, tuple[str, ...], list[str], list[GraphEdge]]] = []
        for sk in start_keys:
            start_node = graph.nodes[sk]["node"]
            if _node_allowed(start_node, constraints) and sk in dist_to_target:
                rem_h = hops_to_target.get(sk, 0)
                if rem_h <= constraints.max_hops:
                    f_init = round(float(dist_to_target[sk]), 6)
                    heapq.heappush(heap, (f_init, 0.0, 0, (sk,), [sk], []))

        while heap:
            if time.perf_counter() > deadline:
                is_truncated = True
                truncation_reason = "timeout_exceeded"
                break
            if candidates_evaluated >= constraints.max_candidates:
                is_truncated = True
                truncation_reason = "max_candidates_reached"
                break

            _, cost, hop_len, key_tie, path_keys, edge_seq = heapq.heappop(heap)
            curr_key = path_keys[-1]

            if curr_key in target_set and hop_len > 0:
                seq_sig = tuple(e.edge_id for e in edge_seq)
                if seq_sig not in seen_edge_sequences:
                    seen_edge_sequences.add(seq_sig)
                    candidates.append((cost, path_keys, edge_seq))
                    candidates_evaluated += 1
                continue

            if hop_len >= constraints.max_hops:
                continue

            neighbors = sorted(graph.out_edges(curr_key, keys=True, data=True), key=lambda x: (x[1], x[2]))
            for _, nxt_key, edge_id, data in neighbors:
                if nxt_key in path_keys:
                    continue
                rem_cost = dist_to_target.get(nxt_key)
                rem_hops = hops_to_target.get(nxt_key)
                if rem_cost is None or rem_hops is None:
                    continue
                if (hop_len + 1 + rem_hops) > constraints.max_hops:
                    continue
                edge_obj = data["edge"]
                nxt_node = graph.nodes[nxt_key]["node"]
                if not _edge_allowed(edge_obj, constraints, graph.nodes[curr_key]["node"], nxt_node):
                    continue
                if not _node_allowed(nxt_node, constraints):
                    continue
                new_cost = round(cost + float(data["weight"]), 6)
                f_score = round(new_cost + float(rem_cost), 6)
                new_tie = (*key_tie, nxt_key, edge_id)
                heapq.heappush(
                    heap,
                    (f_score, new_cost, hop_len + 1, new_tie, [*path_keys, nxt_key], [*edge_seq, edge_obj]),
                )

    algo_params = {
        "algorithm": constraints.algorithm.value,
        "max_hops": constraints.max_hops,
        "max_candidates": constraints.max_candidates,
        "min_confidence": constraints.min_confidence,
        "top_k": constraints.top_k,
        "include_inferred": constraints.include_inferred,
        "candidate_search_complete": candidate_search_complete,
        "top_k_is_global": candidate_search_complete,
        "ranking_scope": (
            "global_candidate_universe"
            if candidate_search_complete
            else "evaluated_candidate_pool"
        ),
        "allow_unknown_preconditions": constraints.allow_unknown_preconditions,
        "allowed_edge_types": [e.value for e in constraints.allowed_edge_types]
        if constraints.allowed_edge_types is not None
        else None,
    }

    scored_results: list[AttackPathResult] = []
    for _, path_keys, edge_seq in candidates:
        path_nodes = [graph.nodes[k]["node"] for k in path_keys]
        start_n = path_nodes[0]
        target_n = path_nodes[-1]
        step_datas: list[PathStepData] = []
        for idx, edge_obj in enumerate(edge_seq, start=1):
            src_n = path_nodes[idx - 1]
            tgt_n = path_nodes[idx]
            step_data = build_step_explanation(
                step_order=idx,
                edge=edge_obj,
                src_node=src_n,
                tgt_node=tgt_n,
            )
            step_data.precondition_outcomes = evaluate_edge_preconditions(edge_obj, src_n, tgt_n)
            for outcome in step_data.precondition_outcomes:
                step_data.preconditions.append(
                    f"{outcome['kind']}: {outcome['status']} — {outcome['reason']}"
                )
                if outcome["status"] == "unknown":
                    step_data.assumptions.append(
                        f"Executable precondition '{outcome['kind']}' is unknown; this transition is conditional."
                    )
            if step_data.precondition_outcomes:
                step_data.assumptions.append(
                    f"Executable transition preconditions are {precondition_summary(step_data.precondition_outcomes)}."
                )
            step_datas.append(step_data)

        breakdown = score_attack_path(
            start_node=start_n,
            target_node=target_n,
            steps=step_datas,
            path_nodes=path_nodes,
        )
        assumptions, narrative, trace = build_path_explanation(
            start_node=start_n,
            target_node=target_n,
            steps=step_datas,
            breakdown=breakdown,
            algorithm=constraints.algorithm.value,
            algorithm_params=algo_params,
            edges=edge_seq,
            path_nodes=path_nodes,
        )
        det_hash = _compute_determinism_hash(
            start_n.key,
            target_n.key,
            [e.edge_id for e in edge_seq],
            constraints.algorithm.value,
            SCORING_VERSION,
            constraints.allow_unknown_preconditions,
        )
        scored_results.append(
            AttackPathResult(
                title=f"{start_n.label} -> {target_n.label} ({len(step_datas)} hops)",
                start_node_kind=start_n.node_kind.value,
                start_node_id=start_n.node_id,
                start_node_label=start_n.label,
                target_node_kind=target_n.node_kind.value,
                target_node_id=target_n.node_id,
                target_node_label=target_n.label,
                algorithm=constraints.algorithm.value,
                algorithm_params=algo_params,
                scoring_version=SCORING_VERSION,
                priority_score=breakdown.priority_score,
                impact_weight=breakdown.impact_weight,
                exposure_factor=breakdown.exposure_factor,
                privilege_factor=breakdown.privilege_factor,
                evidence_confidence=breakdown.evidence_confidence,
                missing_data_penalty=breakdown.missing_data_penalty,
                hop_count=len(step_datas),
                is_truncated=is_truncated,
                assumptions=assumptions,
                explanation_narrative=narrative,
                explanation_trace=trace,
                determinism_hash=det_hash,
                steps=step_datas,
            )
        )

    # Deterministic top-K ordering: highest priority score, shortest hop count, determinism_hash
    scored_results.sort(key=lambda r: (-r.priority_score, r.hop_count, r.determinism_hash))
    if len(scored_results) > constraints.top_k:
        is_truncated = True
        truncation_reason = truncation_reason or "top_k_limit"
        scored_results = scored_results[: constraints.top_k]
        for res in scored_results:
            res.is_truncated = True

    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    return PathSearchOutput(
        paths=scored_results,
        candidates_evaluated=candidates_evaluated,
        is_truncated=is_truncated,
        truncation_reason=truncation_reason,
        duration_ms=elapsed_ms,
        candidate_search_complete=candidate_search_complete,
        top_k_is_global=candidate_search_complete,
        ranking_scope=(
            "global_candidate_universe"
            if candidate_search_complete
            else "evaluated_candidate_pool"
        ),
    )
