# Research implementation corrections — 11 November 2026

This note records implementation and research corrections made against the main baseline `ff24df635d76c7ec8c5a3849bbddee86b1ddb526`.

The changes are on branch `fix/research-data-test-flaws-2026-11` in [pull request #4](https://github.com/Gautam-Mathur/Sentinelgraph/pull/4). At this research cut, the branch head is `d3543cc06d5bf36e02c07c23e666f101465fc04e`; it is **open and unmerged**.

## 1. Candidate traversal cost versus priority-score ranking

The enumerator explores candidates in traversal-cost order (goal-directed best-first for the `dijkstra` option and queue order for BFS), then ranks evaluated paths by `priority_score`. A cap or timeout therefore creates a ranking over the evaluated candidate pool only.

The engine exposes:
- `candidate_search_complete`
- `top_k_is_global`
- `ranking_scope`: `global_candidate_universe` only after exhaustive candidate enumeration; otherwise `evaluated_candidate_pool`.

These values are included in `PathSearchOutput`, per-path `algorithm_params`, and the path-generation API response. The response also includes the configured `max_candidates` and `top_k`. The Attack Paths page now has a candidate-budget input and explicitly warns when the ranking is pool-local. It describes a `top_k` response clip separately from an incomplete candidate search.

### Candidate-budget evidence (independent synthetic dataset)

The benchmark contains 100 trials per cap and 300 generated candidates per trial:

| Candidate cap | Mean global top-5 recall | Global #1 missed | Candidate search complete | Global top-K claim allowed |
|---:|---:|---:|---:|---:|
| 25 | 82.6% | 2.0% | 0% | 0% |
| 50 | 94.6% | 0.0% | 0% | 0% |
| 100 | 100.0% | 0.0% | 0% | 0% |
| 200 | 100.0% | 0.0% | 0% | 0% |
| 400 | 100.0% | 0.0% | 100% | 100% |

The 100% top-5 recall at caps 100 and 200 is only an observation about this particular synthetic dataset. Those runs still evaluate fewer than all 300 candidates. It is not a completeness guarantee. The default candidate cap of 200 must not be labelled as globally exhaustive.

**Claim boundary:** even when `candidate_search_complete=true`, “global” means global only within the configured graph snapshot, scope, edge filters, hop limit, evidence policy and search budget. It is not a claim about unmodelled or out-of-scope paths.

## 2. CVE patch semantics

The old `implementation_edge_cases.csv` fixture showed confidence multiplied by 0.25 and an edge retained when the transformed confidence met a 0.20 threshold. That fixture is now explicitly labelled **superseded fixture-only counterexample**, not the product's current patch semantics.

The product `PATCH_VULNERABILITY` transform:
- sets the relevant CVE state to `patched` on the scoped endpoint and linked relationship records;
- preserves the edge's evidence confidence (e.g. 0.90 remains 0.90);
- updates the scoped open-finding count where supported.

The vulnerability precondition evaluator treats the patched CVE prerequisite as false. The remaining active-graph flaw was that the graph compiler could still insert a relationship whose prerequisite was explicitly false. Graph construction now excludes those edges and increments `blocked_precondition_edge_count`. Unknown prerequisites remain conditional rather than being silently treated as false.

## 3. Parallel relationship centrality

The prior edge-centrality method collapsed a `MultiDiGraph` to a simple `DiGraph`, then copied one endpoint-pair score to all relationships sharing that pair.

The corrected method calculates weighted edge betweenness on the keyed `MultiDiGraph` and records scores using `(source, target, edge_key)`. Node betweenness and SCC calculations remain on the simple endpoint projection. Equal-cost parallel edges may still tie, as expected.

A separate NetworkX 3.6.1 synthetic prototype (seed 20261111) contains 100 multigraph trials and 1,546 edge rows. It includes 282 parallel endpoint-pair instances, of which 279 produced differentiated keyed weighted scores. This is an algorithmic prototype only—not execution of the product source and not an application performance benchmark. The earlier scale study remains a historical baseline and was not re-run as product benchmarking after the centrality change.

## Regression tests and API coverage

Added or extended coverage:
- `test_parallel_relationship_centrality_is_keyed_and_weight_aware`
- `test_explicitly_false_cve_precondition_is_excluded_from_active_graph`
- candidate-budget tests for incomplete candidate enumeration and the ranking-scope flags;
- `test_top_k_response_truncation_does_not_mark_candidate_search_incomplete`;
- CVE patch simulation checks for preserved confidence and active-graph exclusion;
- integration assertions for API-level `candidate_search_complete`, `top_k_is_global`, `ranking_scope` and `blocked_precondition_edge_count`.

Remediation metrics now separate:
- `path_search_complete` / `candidate_search_truncated`: did candidate enumeration finish?
- `path_results_truncated`: was the response clipped to top-K after search?

This prevents a complete enumeration followed by a top-K display cut from being reported as incomplete.

## CI validation on the current branch head

GitHub Actions run [#27](https://github.com/Gautam-Mathur/Sentinelgraph/actions/runs/42935930958) for branch head `d3543cc06d5bf36e02c07c23e666f101465fc04e` completed successfully:
- backend: **76 passed, 1 warning**; Ruff checks passed;
- frontend: typecheck, lint and build succeeded;
- Compose: `docker compose config -q` succeeded.

The single backend warning is a Starlette deprecation warning about using httpx with `starlette.testclient`; it did not fail the suite. These changes are CI-validated on the pull request branch, but remain unmerged and are not yet part of `main`.

## Data-pack companion

The companion research pack includes the row-level CSVs `candidate_budget_trials.csv`, `implementation_edge_cases.csv`, `parallel_edge_centrality_trials.csv`, and `parallel_edge_centrality_trial_summary.csv`, along with correction metadata and updated hashes. Workbook tabs mirror the raw tables. All synthetic multigraph/candidate-budget results are clearly labelled as independent synthetic prototypes.
