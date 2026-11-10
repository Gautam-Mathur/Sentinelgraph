# Research implementation corrections — 10 November 2026

This note records three analytical-integrity corrections made against the main baseline `ff24df635d76c7ec8c5a3849bbddee86b1ddb526`.

The changes are proposed on branch `fix/research-data-test-flaws-2026-11`; they are not a claim that the branch has been merged or passed CI.

## 1. Candidate budget versus final priority order

The path enumerator explores candidates in traversal-cost order (goal-directed best-first ordering for the `dijkstra` option; queue order for BFS) and then sorts evaluated paths by `priority_score`. A hard candidate cap or timeout means the final top-K is only top-K within the explored pool.

The branch adds three explicit fields:
- `candidate_search_complete`
- `top_k_is_global`
- `ranking_scope`, set to `global_candidate_universe` only after candidate enumeration completes, otherwise `evaluated_candidate_pool`.

The fields are included in `PathSearchOutput` and in every returned path's `algorithm_params`. A response clipped by `top_k` can still be globally ranked when the underlying candidate search completed. A response stopped by `max_candidates` or timeout cannot claim global ranking.

The independent synthetic benchmark uses 100 trials × 300 candidate paths:
- budget 25: mean global top-5 recall 82.6%; global best path missed in 2% of trials;
- budget 50: mean global top-5 recall 94.6%;
- budgets 100 and 200: mean recall 100% in this synthetic dataset, but search completeness remains 0% because 100 or 200 of 300 candidates were explored;
- budget 400: all 300 synthetic candidates are explored, so search completeness is 100%.

The observed 100% recall at 100/200 is not a universal guarantee. The important result is that the default cap of 200 is still a truncated search and therefore cannot be labelled as global top-K.

## 2. CVE patch semantics

The old research edge-case fixture incorrectly described confidence multiplied by 0.25 and retained only if the transformed confidence exceeded 0.20 as current application behaviour.

The current `PATCH_VULNERABILITY` transform already records CVE state as `patched`, preserves evidence confidence, and updates the affected node/edge state. The vulnerability precondition evaluator then treats a patched CVE prerequisite as false. The remaining baseline flaw was that `build_networkx_graph` still inserted edges with explicitly false preconditions into its active graph, which allowed them to contribute to graph diagnostics even though path search blocked them.

The branch now checks preconditions during graph construction:
- false preconditions: edge excluded from the active graph;
- unknown preconditions: edge retained as a conditional hypothesis;
- graph-build diagnostics record `blocked_precondition_edge_count`.

Evidence confidence is not modified by patching. The legacy 0.90 → 0.225 example remains in `implementation_edge_cases.csv` only as a superseded audit counterexample.

## 3. Parallel relationship centrality

The baseline calculated edge betweenness on a collapsed simple `DiGraph`, then copied the endpoint-pair value to every edge ID sharing that pair.

The branch calculates weighted edge betweenness directly on the keyed `MultiDiGraph` and maps results by `(source, target, edge_key)`. Relationships with different traversal weights can receive different values. Equal-cost parallel relationships may still tie, as expected.

Node betweenness and strongly connected component analysis remain on the simple endpoint projection. The existing scale prototype therefore remains a historical baseline and is not a benchmark of the new multigraph edge-centrality calculation.

## Regression coverage

New/updated unit tests:
- `test_parallel_relationship_centrality_is_keyed_and_weight_aware`
- `test_explicitly_false_cve_precondition_is_excluded_from_active_graph`
- candidate-cap assertions for incomplete versus complete candidate enumeration and global top-K scope;
- CVE patch simulation asserts evidence confidence is preserved and patched edges are absent from the compiled active graph.

## Validation boundary

These are source-level corrections and tests. The independent CSVs are synthetic research artifacts and do not execute the product. Do not claim the correction branch is CI-verified until the branch's GitHub Actions run passes. The branch needs review and merge before these changes become the `main` implementation.
