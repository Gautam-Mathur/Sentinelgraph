import React, { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useAuth } from "../app/AuthContext";
import { CriticalityBadge, ErrorBanner, ProvenanceBadge } from "../components/Badges";
import { CytoscapeGraph } from "../components/CytoscapeGraph";
import { ModalDialog } from "../components/ModalDialog";
import { Tabs } from "../components/Tabs";
import { apiRequest } from "../lib/api";
import type {
  AttackPathItem,
  CutSetRecommendation,
  EdgeBlastRadius,
  GraphEdge,
  PathIntelligenceResponse,
  RemediationItem,
} from "../types/api";

interface ChallengeTarget {
  relationshipId: string;
  relationType: string;
  fromLabel: string;
  toLabel: string;
}

export const PathDetailPage: React.FC = () => {
  const { pathId } = useParams<{ pathId: string }>();
  const { hasRole } = useAuth();
  const canEdit = hasRole("tenant_admin", "assessor", "analyst");
  const canAuthor = hasRole("tenant_admin", "assessor");
  const canSimulate = hasRole("tenant_admin", "assessor", "analyst", "remediation_owner");

  const [pathData, setPathData] = useState<AttackPathItem | null>(null);
  const [intel, setIntel] = useState<PathIntelligenceResponse | null>(null);
  const [activeTab, setActiveTab] = useState<string>("why");
  const [selectedCut, setSelectedCut] = useState<CutSetRecommendation | null>(null);
  const [simResult, setSimResult] = useState<RemediationItem | null>(null);
  const [simBusyId, setSimBusyId] = useState<string | null>(null);
  const [rebuildBusy, setRebuildBusy] = useState(false);

  const [showJsonTrace, setShowJsonTrace] = useState(false);
  const [suppressTarget, setSuppressTarget] = useState<ChallengeTarget | null>(null);
  const [reason, setReason] = useState("");
  const [statusMsg, setStatusMsg] = useState("");
  const [error, setError] = useState<unknown>(null);

  const loadDetail = useCallback(async () => {
    if (!pathId) return;
    try {
      const [detailRes, intelRes] = await Promise.all([
        apiRequest<AttackPathItem>(`/paths/${pathId}`),
        apiRequest<PathIntelligenceResponse>(`/paths/${pathId}/intelligence`),
      ]);
      setPathData(detailRes);
      setIntel(intelRes);
    } catch (err) {
      setError(err);
    }
  }, [pathId]);

  useEffect(() => {
    loadDetail();
  }, [loadDetail]);

  const handleChallengeEdge = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!suppressTarget) return;
    setError(null);
    try {
      await apiRequest(`/relationships/${suppressTarget.relationshipId}/suppress`, {
        method: "POST",
        body: { suppressed: true, reason: reason.trim() },
      });
      setSuppressTarget(null);
      setReason("");
      setStatusMsg(
        "Relationship marked suppressed (raw provenance preserved). Rebuild assessment graph and regenerate paths to confirm elimination."
      );
      await loadDetail();
    } catch (err) {
      setError(err);
    }
  };

  const handleRebuildAndRegen = async () => {
    if (!pathData) return;
    setError(null);
    setRebuildBusy(true);
    try {
      await apiRequest(`/assessments/${pathData.assessment_id}/build-graph`, { method: "POST" });
      await apiRequest("/paths/generate", {
        method: "POST",
        body: {
          assessment_id: pathData.assessment_id,
          algorithm: pathData.algorithm === "bfs" ? "bfs" : "dijkstra",
          max_hops: Number(pathData.algorithm_params?.max_hops ?? 6),
          min_confidence: Number(pathData.algorithm_params?.min_confidence ?? 0.2),
          include_inferred: Boolean(pathData.algorithm_params?.include_inferred ?? true),
        },
      });
      setStatusMsg(
        "Rebuilt assessment graph and regenerated candidate paths. Visit All Paths to inspect updated routes."
      );
      await loadDetail();
    } catch (err) {
      setError(err);
    } finally {
      setRebuildBusy(false);
    }
  };

  const handleSimulateRecommendation = async (rec: CutSetRecommendation) => {
    if (!pathData || !canSimulate) return;
    setError(null);
    setSimBusyId(rec.id);
    setSelectedCut(rec);
    try {
      const sim = await apiRequest<RemediationItem>("/remediations/simulate", {
        method: "POST",
        body: {
          assessment_id: pathData.assessment_id,
          name: `Fix for ${pathData.title}: ${rec.label}`.slice(0, 180),
          description: rec.rationale,
          transforms: rec.transforms,
        },
      });
      setSimResult(sim);
      setStatusMsg(
        `Simulated "${rec.label}": baseline ${sim.baseline_metrics.total_paths} -> ${sim.modelled_metrics.total_paths} enumerated candidates (-${sim.delta_summary.paths_eliminated}). ${sim.modelled_metrics.reachable_unbounded === true ? "A possible residual route remains." : sim.modelled_metrics.reachability_verification_complete === true ? "No possible route remains in the sandbox model." : "Reachability is unknown."}`
      );
    } catch (err) {
      setError(err);
    } finally {
      setSimBusyId(null);
    }
  };

  const handleSimulateEdgeCut = async (edge: GraphEdge, blast?: EdgeBlastRadius) => {
    if (!pathData || !canSimulate) return;
    const tx = blast?.recommended_transform ?? {
      transform_type: "remove_relationship",
      relationship_id: edge.edge_id,
      notes: `Cut edge from path debugger: ${edge.relation_type}`,
    };
    const tempRec: CutSetRecommendation = {
      id: edge.edge_id,
      label: blast?.action_label || `Break ${edge.relation_type}`,
      cut_size: 1,
      effort_score: 1,
      baseline_paths: blast?.total_paths ?? 1,
      paths_broken: blast?.paths_traversed_count ?? 1,
      residual_paths: blast?.residual_paths_if_cut ?? 0,
      reachable_unbounded: blast?.residual_reachable,
      reachability_verification_complete: blast?.reachability_verification_complete,
      verification_status: blast?.reachability_verification_complete
        ? blast?.residual_reachable ? "PARTIAL_CUT" : "MODEL_VERIFIED_CUT"
        : "INDETERMINATE",
      minimum_cut_proven: false,
      coverage_pct: blast?.path_coverage_pct ?? 100,
      critical_assets_unlinked:
        blast?.residual_reachable === false && blast?.reachability_verification_complete === true ? 1 : 0,
      highest_score_reduction: 0,
      edge_ids: [edge.edge_id],
      steps_summary: [edge.relation_type],
      transforms: [tx],
      rationale: `Single-edge intervention (${edge.source} -> ${edge.target}) triggered from subgraph inspector.`,
    };
    await handleSimulateRecommendation(tempRec);
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">{pathData ? pathData.title : "Attack Path Explainability"}</h1>
          <p className="page-subtitle">
            Causal capability chain, bypass-aware assumption sensitivity, verified cut-set
            remediation, and auditable provenance trace.
          </p>
        </div>
        <div className="btn-row">
          <Link to="/paths" className="btn btn-secondary">
            ← All Paths
          </Link>
          <Link to="/remediations" className="btn btn-primary">
            Simulate Remediation
          </Link>
        </div>
      </div>

      <ErrorBanner error={error} onDismiss={() => setError(null)} />
      {statusMsg && (
        <div className="alert alert-success" role="status">
          <strong>✓ {statusMsg}</strong>
        </div>
      )}

      {pathData && (
        <>
          <div className="alert alert-info" role="note">
            <strong>Scoring Model {pathData.scoring_version} — Priority Ranking Disclaimer</strong>
            <span>
              Priority Score <strong>{pathData.priority_score} / 100</strong> is a deterministic
              normalised remediation triage score, <strong>NOT a statistical probability</strong>{" "}
              of breach. Plausible path only — does not constitute confirmed exploitation.
            </span>
          </div>

          {intel?.stale_path_notice && (
            <div className="alert alert-warning" role="status">
              <strong>Cached Path Diverges From Live Graph Evidence</strong>
              <span>{intel.stale_path_notice}</span>
              {canAuthor && (
                <div style={{ marginBlockStart: "0.4rem" }}>
                  <button
                    type="button"
                    className="btn btn-primary btn-sm"
                    disabled={rebuildBusy}
                    onClick={handleRebuildAndRegen}
                  >
                    {rebuildBusy ? "Rebuilding & Refreshing..." : "Rebuild Graph & Refresh Paths"}
                  </button>
                </div>
              )}
            </div>
          )}

          <div className="kpi-grid">
            <div className="card">
              <div className="kpi-label">Priority Score</div>
              <div className="kpi-value">{pathData.priority_score}</div>
              <CriticalityBadge level={pathData.priority_score >= 70 ? "critical" : "high"} />
            </div>
            <div className="card">
              <div className="kpi-label">Impact Weight</div>
              <div className="kpi-value">{pathData.impact_weight}</div>
              <span className="kpi-hint">Target: {pathData.target_node_label}</span>
            </div>
            <div className="card">
              <div className="kpi-label">Exposure Factor</div>
              <div className="kpi-value">{pathData.exposure_factor}</div>
              <span className="kpi-hint">Entry: {pathData.start_node_label}</span>
            </div>
            <div className="card">
              <div className="kpi-label">Privilege Factor</div>
              <div className="kpi-value">{pathData.privilege_factor}</div>
            </div>
            <div className="card">
              <div className="kpi-label">Evidence Confidence</div>
              <div className="kpi-value">{Math.round(pathData.evidence_confidence * 100)}%</div>
            </div>
            <div className="card">
              <div className="kpi-label">Missing Data Penalty</div>
              <div className="kpi-value">{pathData.missing_data_penalty}</div>
            </div>
          </div>

          {intel && (
            <>
              <section className="card">
                <h2 className="card-title">
                  Focused Attack Subgraph &amp; Parallel Bypass Topology
                </h2>
                <CytoscapeGraph
                  nodes={intel.subgraph.nodes}
                  edges={intel.subgraph.edges}
                  highlightedPathNodeKeys={intel.subgraph.highlighted_node_keys}
                  highlightedPathEdgeIds={intel.subgraph.highlighted_edge_ids}
                  cutEdgeIds={selectedCut?.edge_ids || []}
                  edgeBlastRadius={intel.edge_blast_radius}
                  activeOverlayTitle={`${pathData.start_node_label} → ${pathData.target_node_label}`}
                  activeCutTitle={selectedCut?.label}
                  onClearOverlay={selectedCut ? () => setSelectedCut(null) : undefined}
                  onSimulateEdgeCut={canSimulate ? handleSimulateEdgeCut : undefined}
                  canvasHeight={380}
                />

                {simResult && (
                  <div
                    className="alert alert-success"
                    role="status"
                    style={{ marginBlockStart: "1rem", marginBlockEnd: 0 }}
                  >
                    <strong>
                      Modelled Post-Remediation ({simResult.name}): Baseline{" "}
                      {simResult.baseline_metrics.total_paths} → Modelled{" "}
                      {simResult.modelled_metrics.total_paths} paths (-
                      {simResult.delta_summary.paths_eliminated} eliminated, peak score -
                      {simResult.delta_summary.highest_score_reduction})
                    </strong>
                    <span>
                      {simResult.delta_summary.disclaimer}{" "}
                      <Link to="/remediations" style={{ fontWeight: 700 }}>
                        Inspect Scenario History →
                      </Link>
                    </span>
                  </div>
                )}
              </section>

              <section className="card">
                <h2 className="card-title">Graph Engine Causal Debugger</h2>
                <Tabs
                  label="Causal Path Intelligence Pillars"
                  activeId={activeTab}
                  onChange={setActiveTab}
                  items={[
                    {
                      id: "why",
                      label: "Why This Path Exists",
                      content: (
                        <div className="form-stack">
                          <div className="alert alert-info" role="note" style={{ marginBlockEnd: 0 }}>
                            <strong>Causal Mechanism</strong>
                            <span>{intel.why_exists.summary}</span>
                          </div>

                          <div className="intel-summary-grid">
                            <div className="intel-metric-tile">
                              <div className="intel-metric-label">Same Entry→Target Candidates</div>
                              <div className="intel-metric-val">
                                {intel.why_exists.structural_context.same_pair_total_paths}
                              </div>
                            </div>
                            <div className="intel-metric-tile">
                              <div className="intel-metric-label">Parallel Bypass Candidates</div>
                              <div className="intel-metric-val">
                                {intel.why_exists.structural_context.parallel_bypass_paths_count}
                              </div>
                            </div>
                            <div className="intel-metric-tile">
                              <div className="intel-metric-label">Bridge Chokepoint Steps</div>
                              <div className="intel-metric-val">
                                {intel.why_exists.structural_context.chokepoint_step_orders.length > 0
                                  ? intel.why_exists.structural_context.chokepoint_step_orders
                                      .map((s) => `Step ${s}`)
                                      .join(", ")
                                  : "None (Bypassed)"}
                              </div>
                            </div>
                            <div className="intel-metric-tile">
                              <div className="intel-metric-label">Assessment Path Candidates</div>
                              <div className="intel-metric-val">
                                {intel.why_exists.structural_context.total_assessment_paths}
                              </div>
                            </div>
                          </div>

                          <p className="muted" style={{ fontSize: "0.83rem", margin: 0 }}>
                            Candidate counts are bounded enumerations. Pairwise chokepoint flags use independent BFS reachability checks.
                            Pair search complete: {intel.why_exists.structural_context.same_pair_path_search_complete ? "Yes" : "No"} ·
                            Reachable route remains: {intel.why_exists.structural_context.same_pair_reachable ? "Yes" : "No"}
                          </p>

                          <div className="chain-timeline">
                            {intel.why_exists.capability_chain.map((cap) => (
                              <article
                                key={cap.step_order}
                                className={`chain-step-card ${
                                  cap.is_pair_bridge_chokepoint ? "is-chokepoint" : ""
                                }`}
                              >
                                <div
                                  style={{
                                    display: "flex",
                                    flexWrap: "wrap",
                                    justifyContent: "space-between",
                                    gap: "0.5rem",
                                    marginBlockEnd: "0.35rem",
                                  }}
                                >
                                  <div>
                                    <strong>
                                      Step {cap.step_order}: {cap.stage_name}
                                    </strong>
                                    <div className="mono">
                                      {cap.source_label} --[{cap.relation_type}]--&gt;{" "}
                                      {cap.target_label}
                                    </div>
                                  </div>
                                  <div className="btn-row">
                                    {cap.is_pair_bridge_chokepoint ? (
                                      <span className="badge badge-critical">
                                        ★ Pair Bridge Chokepoint
                                      </span>
                                    ) : (
                                      <span className="badge badge-medium">
                                        {cap.same_pair_bypasses_if_removed} Bypass Route(s) Exist
                                      </span>
                                    )}
                                    <span className="badge badge-neutral">
                                      Betweenness {cap.edge_betweenness}
                                    </span>
                                    <ProvenanceBadge factKind={cap.fact_kind} />
                                  </div>
                                </div>
                                <p style={{ margin: "0 0 0.4rem" }}>{cap.mechanism}</p>
                                {cap.preconditions_met && cap.preconditions_met.length > 0 && (
                                  <div style={{ fontSize: "0.84rem", color: "var(--text-secondary)" }}>
                                    <strong>Verified Attributes:</strong>{" "}
                                    {cap.preconditions_met.join(" • ")}
                                  </div>
                                )}
                              </article>
                            ))}
                          </div>
                        </div>
                      ),
                    },
                    {
                      id: "assumptions",
                      label: `Assumptions & Sensitivity (${intel.assumptions_register.length})`,
                      content: (
                        <div className="form-stack">
                          <div>
                            <h3 style={{ margin: "0 0 0.5rem", fontSize: "1rem" }}>
                              Typed Assumptions Register
                            </h3>
                            <div className="form-stack">
                              {intel.assumptions_register.map((asm) => {
                                const matchingStep = (pathData.steps || []).find(
                                  (s) => s.relationship_id === asm.relationship_id
                                );
                                return (
                                  <article key={asm.assumption_id} className="selectable-intel-row">
                                    <div style={{ minInlineSize: 0, flex: "1 1 22rem" }}>
                                      <div>
                                        <CriticalityBadge level={asm.fragility} />{" "}
                                        <strong>{asm.statement}</strong>{" "}
                                        <span className="badge badge-neutral">{asm.category}</span>
                                      </div>
                                      {asm.if_falsified && (
                                        <div style={{ marginBlockStart: "0.3rem", fontSize: "0.86rem" }}>
                                          <strong>If Falsified:</strong> {asm.if_falsified}
                                        </div>
                                      )}
                                      <div
                                        style={{
                                          marginBlockStart: "0.2rem",
                                          fontSize: "0.84rem",
                                          color: "var(--text-secondary)",
                                        }}
                                      >
                                        <strong>Verify:</strong> {asm.verification_action}
                                      </div>
                                    </div>
                                    {canEdit && asm.can_challenge_edge && asm.relationship_id && (
                                      <button
                                        type="button"
                                        className="btn btn-secondary btn-sm"
                                        aria-label={`Challenge edge for assumption: ${asm.statement}`}
                                        onClick={() => {
                                          setSuppressTarget({
                                            relationshipId: asm.relationship_id!,
                                            relationType: matchingStep?.relation_type || "EDGE",
                                            fromLabel:
                                              matchingStep?.from_node_label || "source",
                                            toLabel: matchingStep?.to_node_label || "target",
                                          });
                                          setReason("");
                                        }}
                                      >
                                        Challenge Edge
                                      </button>
                                    )}
                                  </article>
                                );
                              })}
                            </div>
                          </div>

                          <div
                            className="table-region"
                            tabIndex={0}
                            role="region"
                            aria-label="Per-step counterfactual sensitivity"
                          >
                            <table className="data-table">
                              <caption>Per-Step Removal Counterfactuals (Bypass Analysis)</caption>
                              <thead>
                                <tr>
                                  <th scope="col">Step Transition</th>
                                  <th scope="col">Same-Pair Bypass Candidates / Reachability</th>
                                  <th scope="col">Assessment Path Candidates / Reachability</th>
                                  <th scope="col">Bypass Routes If Cut</th>
                                </tr>
                              </thead>
                              <tbody>
                                {intel.per_step_sensitivity.map((ps) => (
                                  <tr key={`${ps.step_order}-${ps.relationship_id}`}>
                                    <th scope="row" data-label="Step Transition">
                                      Step {ps.step_order}: {ps.transition}
                                    </th>
                                    <td data-label="Same-Pair Bypasses">
                                      {ps.is_pair_bridge_chokepoint ? (
                                        <span className="badge badge-critical">0 (Chokepoint)</span>
                                      ) : (
                                        <span className="badge badge-medium">
                                          {ps.same_pair_bypasses_remaining} candidate(s); route remains: {ps.same_pair_reachable ? "Yes" : ps.same_pair_reachability_verification_complete ? "No" : "Unknown"}
                                        </span>
                                      )}
                                    </td>
                                    <td data-label="Assessment Paths Remaining">
                                      {ps.assessment_paths_remaining} candidate(s) remaining (-
                                      {ps.assessment_paths_broken} traversed by this edge); possible route: {ps.assessment_reachable_remaining ? "Yes" : ps.assessment_reachability_verification_complete ? "No" : "Unknown"}
                                    </td>
                                    <td data-label="Bypass Routes If Cut" className="mono">
                                      {ps.bypass_routes_preview.length > 0
                                        ? ps.bypass_routes_preview.join(" | ")
                                        : ps.same_pair_reachable
                                          ? "No enumerated preview; a possible route remains"
                                          : ps.same_pair_reachability_verification_complete
                                            ? "BFS found no possible same-pair route"
                                            : "No route preview; reachability unknown"}
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>

                          <div
                            className="table-region"
                            tabIndex={0}
                            role="region"
                            aria-label="Assessment assumption sensitivity"
                          >
                            <table className="data-table">
                              <caption>Global What-If Sensitivity Scenarios</caption>
                              <thead>
                                <tr>
                                  <th scope="col">Scenario</th>
                                  <th scope="col">Remaining Paths</th>
                                  <th scope="col">Score Delta</th>
                                  <th scope="col">Verdict</th>
                                </tr>
                              </thead>
                              <tbody>
                                {intel.assessment_sensitivity.map((sc) => (
                                  <tr key={sc.scenario_id}>
                                    <th scope="row" data-label="Scenario">
                                      {sc.label}
                                    </th>
                                    <td data-label="Remaining Paths">
                                      {sc.remaining_paths} / {sc.baseline_paths}
                                    </td>
                                    <td data-label="Score Delta">-{sc.score_reduction}</td>
                                    <td data-label="Verdict">{sc.verdict}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      ),
                    },
                    {
                      id: "breaks",
                      label: `Which Fix Breaks It (${intel.recommended_remediations.length})`,
                      content: (
                        <div className="form-stack">
                          {intel.recommended_remediations.map((rec) => {
                            const isPreview = selectedCut?.id === rec.id;
                            return (
                              <article
                                key={rec.id}
                                className={`selectable-intel-row ${isPreview ? "is-cut-active" : ""}`}
                              >
                                <div style={{ minInlineSize: 0, flex: "1 1 22rem" }}>
                                  <div>
                                    <strong>{rec.label}</strong>{" "}
                                    {rec.eliminates_all_bypasses ? (
                                      <span className="badge badge-success">
                                        Eliminates Bypasses
                                      </span>
                                    ) : (
                                      <span className="badge badge-medium">
                                        Leaves{" "}
                                        {rec.same_pair_bypasses_remaining ?? rec.residual_paths}{" "}
                                        Bypass Route(s)
                                      </span>
                                    )}{" "}
                                    <span className="badge badge-neutral">
                                      Cut Size: {rec.cut_size}
                                    </span>{" "}
                                    <span className="badge badge-info">
                                      Assessment Coverage: {rec.paths_broken}/{rec.baseline_paths} (
                                      {rec.coverage_pct}%)
                                    </span>
                                  </div>
                                  <p
                                    style={{
                                      margin: "0.3rem 0",
                                      fontSize: "0.86rem",
                                      color: "var(--text-secondary)",
                                    }}
                                  >
                                    {rec.rationale}
                                  </p>
                                  <ul style={{ margin: 0, paddingInlineStart: "1.2rem", fontSize: "0.84rem" }}>
                                    {rec.steps_summary.map((s, idx) => (
                                      <li key={idx}>{s}</li>
                                    ))}
                                  </ul>
                                </div>
                                <div className="btn-row">
                                  <button
                                    type="button"
                                    className="btn btn-secondary btn-sm"
                                    aria-pressed={isPreview}
                                    aria-label={`Preview ${rec.label} on graph`}
                                    onClick={() => setSelectedCut(isPreview ? null : rec)}
                                  >
                                    {isPreview ? "✓ Cut Highlighted" : "Preview Cut on Graph"}
                                  </button>
                                  {canSimulate && (
                                    <button
                                      type="button"
                                      className="btn btn-primary btn-sm"
                                      disabled={simBusyId === rec.id}
                                      aria-label={`Simulate ${rec.label} in sandbox`}
                                      onClick={() => handleSimulateRecommendation(rec)}
                                    >
                                      {simBusyId === rec.id
                                        ? "Simulating..."
                                        : "Simulate Fix in Sandbox"}
                                    </button>
                                  )}
                                </div>
                              </article>
                            );
                          })}
                        </div>
                      ),
                    },
                  ]}
                />
              </section>
            </>
          )}

          <section className="card">
            <h2 className="card-title">Step-by-Step Transition Chain ({pathData.hop_count} Hops)</h2>
            <div className="form-stack">
              {(pathData.steps || []).map((st) => (
                <article
                  key={st.id}
                  style={{
                    border: "1px solid var(--border-subtle)",
                    borderRadius: "0.5rem",
                    padding: "1rem",
                    background: "var(--bg-subtle)",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      flexWrap: "wrap",
                      justifyContent: "space-between",
                      gap: "0.5rem",
                      marginBlockEnd: "0.5rem",
                    }}
                  >
                    <div>
                      <strong>
                        Step {st.step_order}: {st.from_node_label} → {st.to_node_label}
                      </strong>
                      <div className="mono">{st.relation_type}</div>
                    </div>
                    <div className="btn-row">
                      <ProvenanceBadge factKind={st.fact_kind} />
                      <span className="badge badge-info">
                        Confidence: {Math.round(st.confidence * 100)}%
                      </span>
                      {canEdit && (
                        <button
                          type="button"
                          className="btn btn-secondary btn-sm"
                          onClick={() => {
                            setSuppressTarget({
                              relationshipId: st.relationship_id,
                              relationType: st.relation_type,
                              fromLabel: st.from_node_label,
                              toLabel: st.to_node_label,
                            });
                            setReason("");
                          }}
                        >
                          Challenge / Suppress Edge
                        </button>
                      )}
                    </div>
                  </div>
                  <p style={{ margin: "0 0 0.45rem" }}>{st.narrative}</p>
                  <div>
                    <strong>Preconditions:</strong>
                    <ul style={{ margin: "0.2rem 0 0.45rem", paddingInlineStart: "1.25rem" }}>
                      {st.preconditions.map((pre, idx) => (
                        <li key={idx}>{pre}</li>
                      ))}
                    </ul>
                  </div>
                  {st.assumptions.length > 0 && (
                    <div>
                      <strong>Assumptions &amp; Caveats:</strong>
                      <ul style={{ margin: "0.2rem 0 0.45rem", paddingInlineStart: "1.25rem" }}>
                        {st.assumptions.map((asmp, idx) => (
                          <li key={idx}>{asmp}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  <details>
                    <summary style={{ cursor: "pointer", fontWeight: 600 }}>
                      Evidence References ({st.evidence_refs.length})
                    </summary>
                    <pre className="mono" style={{ overflowX: "auto" }}>
                      {JSON.stringify(st.evidence_refs, null, 2)}
                    </pre>
                  </details>
                </article>
              ))}
            </div>
          </section>

          <section className="card">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <h2 className="card-title" style={{ margin: 0 }}>
                Narrative Summary &amp; Deterministic JSON Trace
              </h2>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                aria-expanded={showJsonTrace}
                onClick={() => setShowJsonTrace((s) => !s)}
              >
                {showJsonTrace ? "Show Plain-English Narrative" : "Show Structured JSON Trace"}
              </button>
            </div>
            {showJsonTrace ? (
              <pre
                className="mono"
                style={{
                  background: "var(--bg-subtle)",
                  padding: "0.85rem",
                  borderRadius: "0.375rem",
                  overflowX: "auto",
                  marginBlockStart: "0.75rem",
                }}
              >
                {JSON.stringify(pathData.explanation_trace, null, 2)}
              </pre>
            ) : (
              <pre
                style={{
                  whiteSpace: "pre-wrap",
                  fontFamily: "var(--font-sans)",
                  background: "var(--bg-subtle)",
                  padding: "0.85rem",
                  borderRadius: "0.375rem",
                  marginBlockStart: "0.75rem",
                }}
              >
                {pathData.explanation_narrative}
              </pre>
            )}
          </section>
        </>
      )}

      <ModalDialog
        open={Boolean(suppressTarget)}
        title="Challenge & Suppress Path Edge"
        onClose={() => setSuppressTarget(null)}
      >
        <form onSubmit={handleChallengeEdge} className="form-stack">
          <p style={{ margin: 0 }}>
            Edge: <code className="mono">{suppressTarget?.relationType}</code> from{" "}
            <strong>{suppressTarget?.fromLabel}</strong> to{" "}
            <strong>{suppressTarget?.toLabel}</strong>.
          </p>
          <div className="field">
            <label htmlFor="challenge-reason">Analytical Justification</label>
            <textarea
              id="challenge-reason"
              required
              minLength={3}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="e.g. Compensating firewall ACL drops lateral flow"
            />
          </div>
          <div className="btn-row">
            <button type="submit" className="btn btn-danger">
              Suppress Edge
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => setSuppressTarget(null)}
            >
              Cancel
            </button>
          </div>
        </form>
      </ModalDialog>
    </div>
  );
};
