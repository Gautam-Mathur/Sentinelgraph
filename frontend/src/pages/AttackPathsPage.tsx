import React, { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../app/AuthContext";
import { CriticalityBadge, ErrorBanner } from "../components/Badges";
import { apiRequest } from "../lib/api";
import type { AssessmentItem, AttackPathItem, JobItem } from "../types/api";

export const AttackPathsPage: React.FC = () => {
  const { hasRole } = useAuth();
  const canGenerate = hasRole("tenant_admin", "assessor", "analyst");

  const [assessments, setAssessments] = useState<AssessmentItem[]>([]);
  const [selectedAssessmentId, setSelectedAssessmentId] = useState("");
  const [paths, setPaths] = useState<AttackPathItem[]>([]);
  const [algorithm, setAlgorithm] = useState<"dijkstra" | "bfs">("dijkstra");
  const [maxHops, setMaxHops] = useState("6");
  const [minConfidence, setMinConfidence] = useState("0.2");
  const [topK, setTopK] = useState("10");
  const [maxCandidates, setMaxCandidates] = useState("200");
  const [includeInferred, setIncludeInferred] = useState(true);
  const [excludedEnvs, setExcludedEnvs] = useState("");
  const [startKeys, setStartKeys] = useState("");
  const [targetKeys, setTargetKeys] = useState("");
  const [genNotice, setGenNotice] = useState<string>("");
  const [searchScope, setSearchScope] = useState<{
    candidateSearchComplete: boolean | null;
    topKIsGlobal: boolean | null;
    rankingScope: string | null;
    resultsTruncated: boolean;
    truncationReason: string | null;
  }>({
    candidateSearchComplete: null,
    topKIsGlobal: null,
    rankingScope: null,
    resultsTruncated: false,
    truncationReason: null,
  });
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const loadPaths = useCallback(async (assessmentId?: string) => {
    try {
      const qs = assessmentId ? `?assessment_id=${assessmentId}` : "";
      const res = await apiRequest<{ items: AttackPathItem[] }>(`/paths${qs}`);
      setPaths(res.items);
      const scopedPath = res.items.find(
        (p) => typeof p.algorithm_params?.candidate_search_complete === "boolean"
      );
      if (scopedPath) {
        setSearchScope({
          candidateSearchComplete: Boolean(scopedPath.algorithm_params.candidate_search_complete),
          topKIsGlobal: Boolean(scopedPath.algorithm_params.top_k_is_global),
          rankingScope: String(scopedPath.algorithm_params.ranking_scope || "unknown"),
          resultsTruncated: scopedPath.is_truncated &&
            Boolean(scopedPath.algorithm_params.candidate_search_complete),
          truncationReason: scopedPath.is_truncated ? "stored_result" : null,
        });
      } else if (res.items.length === 0) {
        setSearchScope({
          candidateSearchComplete: null,
          topKIsGlobal: null,
          rankingScope: null,
          resultsTruncated: false,
          truncationReason: null,
        });
      }
    } catch (err) {
      setError(err);
    }
  }, []);

  useEffect(() => {
    apiRequest<{ items: AssessmentItem[] }>("/assessments")
      .then((res) => {
        setAssessments(res.items);
        const firstId = res.items[0]?.id || "";
        setSelectedAssessmentId(firstId);
        return loadPaths(firstId || undefined);
      })
      .catch(setError);
  }, [loadPaths]);

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAssessmentId) return;
    setError(null);
    setBusy(true);
    try {
      const res = await apiRequest<{
        paths_count: number;
        is_truncated: boolean;
        candidate_search_complete: boolean;
        top_k_is_global: boolean;
        ranking_scope: string;
        truncation_reason: string | null;
        candidates_evaluated: number;
        duration_ms: number;
      }>("/paths/generate", {
        method: "POST",
        body: {
          assessment_id: selectedAssessmentId,
          algorithm,
          max_hops: Number(maxHops),
          min_confidence: Number(minConfidence),
          top_k: Number(topK),
          max_candidates: Number(maxCandidates),
          include_inferred: includeInferred,
          excluded_environments: excludedEnvs
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean),
          start_node_keys: startKeys
            ? startKeys
                .split(",")
                .map((s) => s.trim())
                .filter(Boolean)
            : null,
          target_node_keys: targetKeys
            ? targetKeys
                .split(",")
                .map((s) => s.trim())
                .filter(Boolean)
            : null,
        },
      });
      setSearchScope({
        candidateSearchComplete: res.candidate_search_complete,
        topKIsGlobal: res.top_k_is_global,
        rankingScope: res.ranking_scope,
        resultsTruncated: res.is_truncated && res.candidate_search_complete,
        truncationReason: res.truncation_reason,
      });
      setGenNotice(
        `Generated ${res.paths_count} path(s) from ${res.candidates_evaluated} evaluated candidate(s) in ${res.duration_ms} ms.`
      );
      await loadPaths(selectedAssessmentId);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  const handleQueuePathJob = async () => {
    if (!selectedAssessmentId) return;
    setError(null);
    setBusy(true);
    try {
      const job = await apiRequest<JobItem>("/jobs", {
        method: "POST",
        body: {
          job_type: "generate_paths",
          payload: {
            assessment_id: selectedAssessmentId,
            algorithm,
            max_hops: Number(maxHops),
            max_candidates: Number(maxCandidates),
            min_confidence: Number(minConfidence),
            top_k: Number(topK),
          },
        },
      });
      setGenNotice(`Queued worker path job (${job.id.slice(0, 8)}): status=${job.status}.`);
      await loadPaths(selectedAssessmentId);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Attack Paths &amp; Constraint Query</h1>
          <p className="page-subtitle">
            Deterministic bounded traversal across authorised evidence edges. All results represent
            plausible exposure chains, not confirmed breaches.
          </p>
        </div>
      </div>

      <ErrorBanner error={error} onDismiss={() => setError(null)} />
      {genNotice && (
        <div className="alert alert-success" role="status">
          <strong>✓ {genNotice}</strong>{" "}
          <Link to="/jobs" style={{ fontWeight: 600 }}>
            Open Jobs Queue →
          </Link>
        </div>
      )}

      {searchScope.candidateSearchComplete === false && (
        <div className="alert alert-warning" role="status">
          <strong>⚠ Candidate search is incomplete.</strong>
          <span>
            The engine stopped at a candidate or time budget. These paths are ranked only within
            the evaluated candidate pool ({searchScope.rankingScope || "evaluated_candidate_pool"});
            the displayed top-K is not guaranteed to be the global highest-priority set.
            {searchScope.truncationReason ? ` Stop reason: ${searchScope.truncationReason}.` : ""}
            Narrow the graph scope or raise the candidate budget before treating this list as complete.
          </span>
        </div>
      )}
      {searchScope.candidateSearchComplete === true &&
        searchScope.resultsTruncated && (
          <div className="alert alert-info" role="status">
            <strong>Top-K display limit applied after candidate enumeration.</strong>
            <span>
              All eligible candidates within the configured graph, filters, hop limit and evidence
              policy were evaluated. The displayed top-K is globally ranked within that modelled
              candidate universe, not beyond the configured model scope.
            </span>
          </div>
        )}
      {searchScope.candidateSearchComplete === null && paths.some((p) => p.is_truncated) && (
        <div className="alert alert-warning" role="status">
          <strong>Legacy result has truncation metadata but no candidate-scope flag.</strong>
          <span>Global ranking completeness cannot be established for this stored result.</span>
        </div>
      )}

      <section className="card">
        <h2 className="card-title">Constraint Builder</h2>
        <form onSubmit={handleGenerate} className="form-stack">
          <div className="grid-2">
            <div className="field">
              <label htmlFor="path-assess">Target Assessment</label>
              <select
                id="path-assess"
                value={selectedAssessmentId}
                onChange={(e) => {
                  setSelectedAssessmentId(e.target.value);
                  loadPaths(e.target.value);
                }}
              >
                {assessments.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name} ({a.status})
                  </option>
                ))}
              </select>
            </div>
            <div className="field">
              <label htmlFor="path-algo">Traversal Algorithm</label>
              <select
                id="path-algo"
                value={algorithm}
                onChange={(e) => setAlgorithm(e.target.value as "dijkstra" | "bfs")}
              >
                <option value="dijkstra">Weighted Dijkstra Shortest Risk Path</option>
                <option value="bfs">Unweighted Shortest Hop BFS</option>
              </select>
            </div>
          </div>

          <div className="grid-2">
            <div className="field">
              <label htmlFor="path-hops">Max Hops (1–12)</label>
              <input
                id="path-hops"
                type="number"
                min={1}
                max={12}
                value={maxHops}
                onChange={(e) => setMaxHops(e.target.value)}
              />
            </div>
            <div className="field">
              <label htmlFor="path-conf">Min Edge Confidence (0.05–1.0)</label>
              <input
                id="path-conf"
                type="number"
                step="0.05"
                min="0.05"
                max="1.0"
                value={minConfidence}
                onChange={(e) => setMinConfidence(e.target.value)}
              />
            </div>
          </div>

          <div className="grid-2">
            <div className="field">
              <label htmlFor="path-candidates">Candidate Enumeration Budget (1-2000)</label>
              <input
                id="path-candidates"
                type="number"
                min={1}
                max={2000}
                step={1}
                value={maxCandidates}
                onChange={(e) => setMaxCandidates(e.target.value)}
              />
              <small className="muted">
                A higher cap may improve coverage but does not guarantee completeness if the time limit is reached.
              </small>
            </div>
            <div className="field">
              <label htmlFor="path-topk">Top-K Ranked Paths</label>
              <input
                id="path-topk"
                type="number"
                min={1}
                max={50}
                value={topK}
                onChange={(e) => setTopK(e.target.value)}
              />
            </div>
            <div className="field">
              <label htmlFor="path-exenv">Excluded Environments (comma-separated)</label>
              <input
                id="path-exenv"
                value={excludedEnvs}
                onChange={(e) => setExcludedEnvs(e.target.value)}
                placeholder="e.g. dev, sandbox"
              />
            </div>
          </div>

          <div className="grid-2">
            <div className="field">
              <label htmlFor="path-starts">Start Node Keys Override (optional)</label>
              <input
                id="path-starts"
                value={startKeys}
                onChange={(e) => setStartKeys(e.target.value)}
                placeholder="leave blank for all external entry nodes"
              />
            </div>
            <div className="field">
              <label htmlFor="path-targets">Target Node Keys Override (optional)</label>
              <input
                id="path-targets"
                value={targetKeys}
                onChange={(e) => setTargetKeys(e.target.value)}
                placeholder="leave blank for critical / crown jewel nodes"
              />
            </div>
          </div>

          <div className="checkbox-row">
            <input
              id="path-inferred"
              type="checkbox"
              checked={includeInferred}
              onChange={(e) => setIncludeInferred(e.target.checked)}
            />
            <label htmlFor="path-inferred">
              Include inferred_relationship edges (tracked separately in evidence confidence)
            </label>
          </div>

          {canGenerate && (
            <div className="btn-row">
              <button type="submit" className="btn btn-primary" disabled={busy}>
                {busy ? "Computing Paths..." : "Generate Candidate Paths"}
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                disabled={busy || !selectedAssessmentId}
                onClick={handleQueuePathJob}
              >
                Queue Async Path Job
              </button>
            </div>
          )}
        </form>
      </section>

      <section className="card">
        <div className="table-region" tabIndex={0} role="region" aria-label="Ranked attack paths">
          <table className="data-table">
            <caption>Ranked Attack Paths ({paths.length})</caption>
            <thead>
              <tr>
                <th scope="col">Path Title</th>
                <th scope="col">Priority Score (Not Probability)</th>
                <th scope="col">Hops</th>
                <th scope="col">Evidence Conf.</th>
                <th scope="col">Algorithm</th>
                <th scope="col">Explainability</th>
              </tr>
            </thead>
            <tbody>
              {paths.map((p) => {
                const capChain = Array.isArray(p.explanation_trace?.capability_chain)
                  ? (p.explanation_trace.capability_chain as Array<{ stage_name?: string }>)
                  : [];
                const stages = capChain.map((c) => c.stage_name).filter(Boolean);
                const reg = Array.isArray(p.explanation_trace?.assumptions_register)
                  ? (p.explanation_trace.assumptions_register as Array<{ category?: string }>).filter(
                      (a) => a.category !== "plausibility_invariant"
                    )
                  : [];
                const assumptionCount = reg.length > 0 ? reg.length : p.assumptions.length;
                return (
                  <tr key={p.id}>
                    <th scope="row" data-label="Path Title">
                      <div>{p.title}</div>
                      {stages.length > 0 && (
                        <div style={{ fontSize: "0.78rem", color: "var(--text-secondary)", fontWeight: 500 }}>
                          {stages.join(" → ")}
                        </div>
                      )}
                      <div style={{ marginBlockStart: "0.2rem", display: "flex", flexWrap: "wrap", gap: "0.35rem", alignItems: "center" }}>
                        <span className="mono">hash: {p.determinism_hash.slice(0, 14)}...</span>
                        {assumptionCount > 0 && (
                          <span className="badge badge-neutral">
                            {assumptionCount} assumption(s)
                          </span>
                        )}
                      </div>
                    </th>
                    <td data-label="Priority Score">
                      <CriticalityBadge
                        level={p.priority_score >= 70 ? "critical" : p.priority_score >= 45 ? "high" : "medium"}
                      />{" "}
                      <strong>{p.priority_score} / 100</strong>
                    </td>
                    <td data-label="Hops">{p.hop_count}</td>
                    <td data-label="Evidence Conf.">{Math.round(p.evidence_confidence * 100)}%</td>
                    <td data-label="Algorithm" className="mono">
                      {p.algorithm} ({p.scoring_version})
                    </td>
                    <td data-label="Explainability">
                      <Link to={`/paths/${p.id}`} className="btn btn-primary btn-sm">
                        Inspect Reasoning
                      </Link>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};
