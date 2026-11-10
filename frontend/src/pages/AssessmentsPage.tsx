import React, { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../app/AuthContext";
import { CriticalityBadge, ErrorBanner, StatusBadge } from "../components/Badges";
import { CytoscapeGraph } from "../components/CytoscapeGraph";
import { ModalDialog } from "../components/ModalDialog";
import { Tabs } from "../components/Tabs";
import { apiRequest } from "../lib/api";
import type {
  AssessmentGraphPayload,
  AssessmentIntelligenceResponse,
  AssessmentItem,
  CutSetRecommendation,
  EdgeBlastRadius,
  GraphEdge,
  JobItem,
  PathOverlayEntry,
  RemediationItem,
} from "../types/api";

export const AssessmentsPage: React.FC = () => {
  const { hasRole } = useAuth();
  const canAuthor = hasRole("tenant_admin", "assessor");
  const canSimulate = hasRole("tenant_admin", "assessor", "analyst", "remediation_owner");

  const [assessments, setAssessments] = useState<AssessmentItem[]>([]);
  const [selectedId, setSelectedId] = useState<string>("");
  const [graphData, setGraphData] = useState<AssessmentGraphPayload | null>(null);
  const [intel, setIntel] = useState<AssessmentIntelligenceResponse | null>(null);
  const [intelTab, setIntelTab] = useState<string>("paths");

  const [highlightedPath, setHighlightedPath] = useState<PathOverlayEntry | null>(null);
  const [highlightedCycleNodes, setHighlightedCycleNodes] = useState<string[]>([]);
  const [highlightedCycleLabel, setHighlightedCycleLabel] = useState<string>("");
  const [previewCut, setPreviewCut] = useState<CutSetRecommendation | null>(null);
  const [simResult, setSimResult] = useState<RemediationItem | null>(null);
  const [simBusyId, setSimBusyId] = useState<string | null>(null);

  const [statusMsg, setStatusMsg] = useState<string>("");
  const [error, setError] = useState<unknown>(null);

  const [createOpen, setCreateOpen] = useState(false);
  const [name, setName] = useState("");
  const [desc, setDesc] = useState("");
  const [cidrs, setCidrs] = useState("10.10.0.0/16, lab.sentinelgraph.invalid");
  const [isSynthetic, setIsSynthetic] = useState(true);

  const loadAssessments = useCallback(async () => {
    try {
      const res = await apiRequest<{ items: AssessmentItem[] }>("/assessments");
      setAssessments(res.items);
      if (res.items.length > 0 && !selectedId) {
        setSelectedId(res.items[0].id);
      }
    } catch (err) {
      setError(err);
    }
  }, [selectedId]);

  const loadGraphAndIntel = useCallback(async (assessmentId: string) => {
    if (!assessmentId) return;
    try {
      const [graphRes, intelRes] = await Promise.all([
        apiRequest<AssessmentGraphPayload>(`/assessments/${assessmentId}/graph`),
        apiRequest<AssessmentIntelligenceResponse>(`/assessments/${assessmentId}/intelligence`),
      ]);
      setGraphData(graphRes);
      setIntel(intelRes);
      setHighlightedPath(intelRes.paths_overlay[0] ?? null);
      setHighlightedCycleNodes([]);
      setHighlightedCycleLabel("");
      setPreviewCut(null);
      setSimResult(null);
    } catch (err) {
      setError(err);
    }
  }, []);

  useEffect(() => {
    loadAssessments();
  }, [loadAssessments]);

  useEffect(() => {
    if (!selectedId) return;
    loadGraphAndIntel(selectedId);
  }, [loadGraphAndIntel, selectedId]);

  const activeAssessment = assessments.find((a) => a.id === selectedId) || null;

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    const now = new Date();
    const end = new Date(now.getTime() + 14 * 86400 * 1000);
    try {
      const created = await apiRequest<AssessmentItem>("/assessments", {
        method: "POST",
        body: {
          name: name.trim(),
          description: desc.trim(),
          approved_scope_cidrs: cidrs
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean),
          time_window_start: now.toISOString(),
          time_window_end: end.toISOString(),
          is_synthetic: isSynthetic,
        },
      });
      setCreateOpen(false);
      setName("");
      setDesc("");
      setSelectedId(created.id);
      setStatusMsg(`Created assessment "${created.name}" (draft scope).`);
      await loadAssessments();
    } catch (err) {
      setError(err);
    }
  };

  const handleApproveScope = async (id: string) => {
    setError(null);
    try {
      await apiRequest(`/assessments/${id}/approve-scope`, { method: "POST" });
      setStatusMsg("Assessment scope approved.");
      await loadAssessments();
    } catch (err) {
      setError(err);
    }
  };

  const handleBuildGraph = async (id: string) => {
    setError(null);
    try {
      await apiRequest(`/assessments/${id}/build-graph`, { method: "POST" });
      await loadGraphAndIntel(id);
      setStatusMsg("Built deterministic NetworkX MultiDiGraph and refreshed graph intelligence.");
      await loadAssessments();
    } catch (err) {
      setError(err);
    }
  };

  const handleQueueGraphJob = async (id: string) => {
    setError(null);
    try {
      const job = await apiRequest<JobItem>("/jobs", {
        method: "POST",
        body: { job_type: "build_graph", payload: { assessment_id: id } },
      });
      setStatusMsg(`Queued worker job build_graph (${job.id.slice(0, 8)}): status=${job.status}.`);
      await loadAssessments();
    } catch (err) {
      setError(err);
    }
  };

  const handleSimulateCutSet = async (cut: CutSetRecommendation) => {
    if (!selectedId) return;
    setError(null);
    setSimBusyId(cut.id);
    setPreviewCut(cut);
    try {
      const sim = await apiRequest<RemediationItem>("/remediations/simulate", {
        method: "POST",
        body: {
          assessment_id: selectedId,
          name: `Cut-Set: ${cut.label}`,
          description: cut.rationale,
          transforms: cut.transforms,
        },
      });
      setSimResult(sim);
      setStatusMsg(
        `Simulated "${cut.label}": eliminated ${sim.delta_summary.paths_eliminated} of ${sim.baseline_metrics.total_paths} path(s).`
      );
    } catch (err) {
      setError(err);
    } finally {
      setSimBusyId(null);
    }
  };

  const handleSimulateSingleEdge = async (edge: GraphEdge, blast?: EdgeBlastRadius) => {
    if (!selectedId || !canSimulate) return;
    const tx = blast?.recommended_transform ?? {
      transform_type: "remove_relationship",
      relationship_id: edge.edge_id,
      notes: `Edge cut from Graph Explorer: ${edge.relation_type}`,
    };
    setError(null);
    setSimBusyId(edge.edge_id);
    try {
      const sim = await apiRequest<RemediationItem>("/remediations/simulate", {
        method: "POST",
        body: {
          assessment_id: selectedId,
          name: blast?.action_label || `Break ${edge.relation_type} edge`,
          description: `Interactive graph edge cut (${edge.source} -> ${edge.target})`,
          transforms: [tx],
        },
      });
      setSimResult(sim);
      setPreviewCut({
        id: edge.edge_id,
        label: blast?.action_label || edge.relation_type,
        cut_size: 1,
        effort_score: 1,
        baseline_paths: sim.baseline_metrics.total_paths,
        paths_broken: sim.delta_summary.paths_eliminated,
        residual_paths: sim.modelled_metrics.total_paths,
        coverage_pct: 100,
        critical_assets_unlinked: sim.delta_summary.critical_assets_unlinked,
        highest_score_reduction: sim.delta_summary.highest_score_reduction,
        edge_ids: [edge.edge_id],
        steps_summary: [edge.relation_type],
        transforms: [tx],
        rationale: "Single edge sandbox cut triggered from graph inspector.",
      });
      setStatusMsg(
        `Edge sandbox cut: eliminated ${sim.delta_summary.paths_eliminated} path(s), ${sim.modelled_metrics.total_paths} residual path(s) remain.`
      );
    } catch (err) {
      setError(err);
    } finally {
      setSimBusyId(null);
    }
  };

  const activeNodeKeys = highlightedPath
    ? highlightedPath.node_keys
    : highlightedCycleNodes;
  const activeEdgeIds = highlightedPath ? highlightedPath.edge_ids : [];
  const activeOverlayTitle = highlightedPath
    ? `${highlightedPath.title} (Score ${highlightedPath.priority_score})`
    : highlightedCycleLabel || undefined;

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Authorised Assessments &amp; Graph Intelligence Center</h1>
          <p className="page-subtitle">
            Scope governance, interactive NetworkX attack graph causality, minimum remediation
            cut-sets, and counterfactual assumption sensitivity.
          </p>
        </div>
        {canAuthor && (
          <button type="button" className="btn btn-primary" onClick={() => setCreateOpen(true)}>
            + New Assessment
          </button>
        )}
      </div>

      <ErrorBanner error={error} onDismiss={() => setError(null)} />
      {statusMsg && (
        <div className="alert alert-success" role="status">
          <strong>✓ {statusMsg}</strong>{" "}
          <Link to="/jobs" style={{ fontWeight: 600 }}>
            View Background Jobs →
          </Link>
        </div>
      )}

      <div className="table-region" tabIndex={0} role="region" aria-label="Assessments list">
        <table className="data-table">
          <caption>Assessments ({assessments.length})</caption>
          <thead>
            <tr>
              <th scope="col">Name</th>
              <th scope="col">Status</th>
              <th scope="col">Approved Scope</th>
              <th scope="col">Graph Stats</th>
              <th scope="col">Actions</th>
            </tr>
          </thead>
          <tbody>
            {assessments.map((a) => (
              <tr key={a.id}>
                <th scope="row" data-label="Name">
                  <div>{a.name}</div>
                  {a.is_synthetic && <span className="badge badge-medium">Synthetic Lab</span>}
                </th>
                <td data-label="Status">
                  <StatusBadge status={a.status} />
                </td>
                <td data-label="Approved Scope" className="mono">
                  {a.approved_scope_cidrs.join(", ")}
                </td>
                <td data-label="Graph Stats">
                  v{a.graph_version} — {a.graph_stats?.node_count ?? 0} nodes /{" "}
                  {a.graph_stats?.edge_count ?? 0} edges
                </td>
                <td data-label="Actions">
                  <div className="btn-row">
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={() => setSelectedId(a.id)}
                    >
                      {a.id === selectedId ? "Selected" : "Inspect"}
                    </button>
                    {canAuthor && a.status === "draft" && (
                      <button
                        type="button"
                        className="btn btn-primary btn-sm"
                        onClick={() => handleApproveScope(a.id)}
                      >
                        Approve Scope
                      </button>
                    )}
                    {canAuthor && a.status !== "draft" && (
                      <>
                        <button
                          type="button"
                          className="btn btn-primary btn-sm"
                          onClick={() => handleBuildGraph(a.id)}
                        >
                          Rebuild Graph
                        </button>
                        <button
                          type="button"
                          className="btn btn-secondary btn-sm"
                          onClick={() => handleQueueGraphJob(a.id)}
                        >
                          Queue Worker Job
                        </button>
                      </>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {activeAssessment && graphData && (
        <section className="card" style={{ marginBlockStart: "1.25rem" }}>
          <h2 className="card-title">
            Attack Graph: {activeAssessment.name} (Version {activeAssessment.graph_version})
          </h2>

          {intel && (
            <div className="intel-summary-grid" aria-label="Graph intelligence summary">
              <div className="intel-metric-tile">
                <div className="intel-metric-label">Reachable Attack Paths</div>
                <div className="intel-metric-val">{intel.summary.total_active_paths}</div>
              </div>
              <div className="intel-metric-tile">
                <div className="intel-metric-label">Minimum Cut-Set Size</div>
                <div className="intel-metric-val">
                  {intel.summary.min_cut_size !== null ? `${intel.summary.min_cut_size} edge(s)` : "None"}
                </div>
              </div>
              <div className="intel-metric-tile">
                <div className="intel-metric-label">1-Edge Chokepoints</div>
                <div className="intel-metric-val">{intel.summary.single_point_chokepoints_count}</div>
              </div>
              <div className="intel-metric-tile">
                <div className="intel-metric-label">Inferred-Dependent Paths</div>
                <div className="intel-metric-val">
                  {intel.summary.inferred_dependent_paths} / {intel.summary.total_active_paths}
                </div>
              </div>
              <div className="intel-metric-tile">
                <div className="intel-metric-label">Uncorroborated ACL Edges</div>
                <div className="intel-metric-val">{intel.summary.uncorroborated_acl_edges}</div>
              </div>
            </div>
          )}

          <div className="grid-2" style={{ marginBlockEnd: "1rem" }}>
            <div className="card" style={{ margin: 0 }}>
              <h3 style={{ marginTop: 0, fontSize: "0.95rem" }}>
                Top Bridge Nodes (Betweenness Centrality)
              </h3>
              {(graphData.stats?.top_bridge_nodes || []).length === 0 ? (
                <p style={{ color: "var(--text-muted)", margin: 0 }}>No bridge nodes computed.</p>
              ) : (
                <ul style={{ margin: 0, paddingInlineStart: "1.25rem" }}>
                  {(graphData.stats?.top_bridge_nodes || []).map((b) => (
                    <li key={b.node_key}>
                      <strong>{b.label}</strong> ({b.node_kind}) — centrality{" "}
                      <code className="mono">{b.betweenness_centrality}</code>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div className="card" style={{ margin: 0 }}>
              <h3 style={{ marginTop: 0, fontSize: "0.95rem" }}>
                Strongly Connected Privilege Cycles (SCC)
              </h3>
              <p style={{ margin: "0 0 0.5rem" }}>
                Cycle count: <strong>{graphData.stats?.scc_cycle_count ?? 0}</strong> | Suppressed
                edges excluded: <strong>{graphData.stats?.suppressed_edge_count ?? 0}</strong> |
                Expired edges excluded: <strong>{graphData.stats?.expired_edge_count ?? 0}</strong>
              </p>
              {(graphData.stats?.scc_cycles || []).length > 0 && (
                <div className="btn-row">
                  {(graphData.stats?.scc_cycles || []).slice(0, 3).map((cycle, idx) => (
                    <button
                      key={idx}
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={() => {
                        setHighlightedPath(null);
                        setHighlightedCycleNodes(cycle);
                        setHighlightedCycleLabel(`SCC Privilege Cycle #${idx + 1} (${cycle.length} nodes)`);
                      }}
                    >
                      Focus SCC Cycle #{idx + 1} ({cycle.length} nodes)
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>

          <CytoscapeGraph
            nodes={graphData.nodes}
            edges={graphData.edges}
            highlightedPathNodeKeys={activeNodeKeys}
            highlightedPathEdgeIds={activeEdgeIds}
            cutEdgeIds={previewCut?.edge_ids || []}
            edgeBlastRadius={intel?.edge_blast_radius || {}}
            activeOverlayTitle={activeOverlayTitle}
            activeCutTitle={previewCut?.label}
            onClearOverlay={() => {
              setHighlightedPath(null);
              setHighlightedCycleNodes([]);
              setHighlightedCycleLabel("");
              setPreviewCut(null);
            }}
            onSimulateEdgeCut={canSimulate ? handleSimulateSingleEdge : undefined}
          />

          {simResult && (
            <div className="alert alert-success" role="status" style={{ marginBlockStart: "1rem" }}>
              <strong>
                Sandbox Result — {simResult.name}: Baseline {simResult.baseline_metrics.total_paths}{" "}
                paths → Modelled {simResult.modelled_metrics.total_paths} paths (-
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

          {intel && (
            <div className="card" style={{ marginBlockStart: "1rem" }}>
              <h3 className="card-title">
                Graph Intelligence: Why Paths Exist, Assumptions &amp; Minimum Cut-Sets
              </h3>
              <Tabs
                label="Graph Intelligence Perspectives"
                activeId={intelTab}
                onChange={setIntelTab}
                items={[
                  {
                    id: "paths",
                    label: `Why Paths Exist (${intel.paths_overlay.length})`,
                    content:
                      intel.paths_overlay.length === 0 ? (
                        <p style={{ color: "var(--text-secondary)", margin: 0 }}>
                          No candidate attack paths discovered between entry points and crown jewels
                          under current constraints.
                        </p>
                      ) : (
                        <div className="form-stack">
                          {intel.paths_overlay.map((p, idx) => {
                            const isSelected = highlightedPath?.determinism_hash === p.determinism_hash;
                            return (
                              <div
                                key={p.determinism_hash}
                                className={`selectable-intel-row ${isSelected ? "is-active" : ""}`}
                              >
                                <div style={{ minInlineSize: 0, flex: "1 1 20rem" }}>
                                  <div>
                                    <strong>
                                      #{idx + 1} {p.title}
                                    </strong>{" "}
                                    <CriticalityBadge
                                      level={
                                        p.priority_score >= 70
                                          ? "critical"
                                          : p.priority_score >= 45
                                            ? "high"
                                            : "medium"
                                      }
                                    />{" "}
                                    <span className="badge badge-info">
                                      Score {p.priority_score} / 100
                                    </span>{" "}
                                    <span className="badge badge-neutral">{p.hop_count} hops</span>{" "}
                                    {p.has_inferred && (
                                      <span className="badge badge-medium">Uses Inferred Edge</span>
                                    )}
                                  </div>
                                  {p.capability_stages.length > 0 && (
                                    <div
                                      style={{
                                        fontSize: "0.84rem",
                                        color: "var(--text-secondary)",
                                        marginBlockStart: "0.25rem",
                                      }}
                                    >
                                      <strong>Causal Chain:</strong> {p.capability_stages.join(" → ")}
                                    </div>
                                  )}
                                </div>
                                <div className="btn-row">
                                  <button
                                    type="button"
                                    className="btn btn-secondary btn-sm"
                                    aria-pressed={isSelected}
                                    aria-label={`Highlight ${p.title} on graph`}
                                    onClick={() => {
                                      setHighlightedCycleNodes([]);
                                      setHighlightedCycleLabel("");
                                      setHighlightedPath(isSelected ? null : p);
                                    }}
                                  >
                                    {isSelected ? "✓ Focused on Graph" : "Focus on Graph"}
                                  </button>
                                  {p.path_id && (
                                    <Link
                                      to={`/paths/${p.path_id}`}
                                      className="btn btn-primary btn-sm"
                                      aria-label={`Explain causality and assumptions for ${p.title}`}
                                    >
                                      Explain Path →
                                    </Link>
                                  )}
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      ),
                  },
                  {
                    id: "cuts",
                    label: `Minimum Cut-Sets (${intel.cut_sets.length})`,
                    content:
                      intel.cut_sets.length === 0 ? (
                        <p style={{ color: "var(--text-secondary)", margin: 0 }}>
                          No cut-sets required — zero active attack paths remain.
                        </p>
                      ) : (
                        <div className="form-stack">
                          {intel.cut_sets.map((cs) => {
                            const isPreviewed = previewCut?.id === cs.id;
                            return (
                              <div
                                key={cs.id}
                                className={`selectable-intel-row ${isPreviewed ? "is-cut-active" : ""}`}
                              >
                                <div style={{ minInlineSize: 0, flex: "1 1 22rem" }}>
                                  <div>
                                    <strong>{cs.label}</strong>{" "}
                                    <span
                                      className={`badge ${
                                        cs.residual_paths === 0 ? "badge-success" : "badge-medium"
                                      }`}
                                    >
                                      {cs.paths_broken}/{cs.baseline_paths} paths broken ({cs.coverage_pct}
                                      %)
                                    </span>{" "}
                                    <span className="badge badge-neutral">
                                      Cut Size: {cs.cut_size}
                                    </span>{" "}
                                    <span className="badge badge-neutral">
                                      Effort: {cs.effort_score}
                                    </span>
                                  </div>
                                  <p
                                    style={{
                                      margin: "0.3rem 0",
                                      fontSize: "0.86rem",
                                      color: "var(--text-secondary)",
                                    }}
                                  >
                                    {cs.rationale}
                                  </p>
                                  <ul style={{ margin: 0, paddingInlineStart: "1.2rem", fontSize: "0.84rem" }}>
                                    {cs.steps_summary.map((line, i) => (
                                      <li key={i}>{line}</li>
                                    ))}
                                  </ul>
                                </div>
                                <div className="btn-row">
                                  <button
                                    type="button"
                                    className="btn btn-secondary btn-sm"
                                    aria-pressed={isPreviewed}
                                    aria-label={`Preview ${cs.label} cut edges on graph`}
                                    onClick={() => setPreviewCut(isPreviewed ? null : cs)}
                                  >
                                    {isPreviewed ? "✓ Cut Highlighted" : "Preview Cut on Graph"}
                                  </button>
                                  {canSimulate && (
                                    <button
                                      type="button"
                                      className="btn btn-primary btn-sm"
                                      disabled={simBusyId === cs.id}
                                      aria-label={`Simulate ${cs.label} in sandbox`}
                                      onClick={() => handleSimulateCutSet(cs)}
                                    >
                                      {simBusyId === cs.id
                                        ? "Simulating..."
                                        : "Simulate Cut-Set in Sandbox"}
                                    </button>
                                  )}
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      ),
                  },
                  {
                    id: "sensitivity",
                    label: `Assumption Sensitivity (${intel.sensitivity_analysis.length})`,
                    content: (
                      <div className="form-stack">
                        <div className="table-region" tabIndex={0} role="region" aria-label="Counterfactual sensitivity matrix">
                          <table className="data-table">
                            <caption>Counterfactual Assumption Stress Tests</caption>
                            <thead>
                              <tr>
                                <th scope="col">What-If Assumption Test</th>
                                <th scope="col">Remaining Paths</th>
                                <th scope="col">Eliminated</th>
                                <th scope="col">Peak Score Delta</th>
                                <th scope="col">Engine Verdict</th>
                              </tr>
                            </thead>
                            <tbody>
                              {intel.sensitivity_analysis.map((sc) => (
                                <tr key={sc.scenario_id}>
                                  <th scope="row" data-label="What-If Assumption Test">
                                    <div>{sc.label}</div>
                                    <div style={{ fontWeight: 400, fontSize: "0.8rem", color: "var(--text-secondary)" }}>
                                      {sc.assumption_tested}
                                    </div>
                                  </th>
                                  <td data-label="Remaining Paths">
                                    <strong>{sc.remaining_paths}</strong> / {sc.baseline_paths}
                                  </td>
                                  <td data-label="Eliminated">-{sc.paths_eliminated}</td>
                                  <td data-label="Peak Score Delta">
                                    {sc.highest_score_remaining} (-{sc.score_reduction})
                                  </td>
                                  <td data-label="Engine Verdict">{sc.verdict}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>

                        {intel.assumptions_summary.length > 0 && (
                          <div>
                            <h4 style={{ margin: "0 0 0.5rem" }}>
                              Top Structural Assumptions Across Active Paths
                            </h4>
                            <div className="form-stack">
                              {intel.assumptions_summary.slice(0, 6).map((asm, i) => (
                                <div key={`${asm.assumption_id}-${i}`} className="selectable-intel-row">
                                  <div style={{ minInlineSize: 0 }}>
                                    <div>
                                      <CriticalityBadge level={asm.fragility} />{" "}
                                      <strong>{asm.statement}</strong>{" "}
                                      {typeof asm.affected_paths_count === "number" && (
                                        <span className="badge badge-neutral">
                                          Affects {asm.affected_paths_count} path(s)
                                        </span>
                                      )}
                                    </div>
                                    <div style={{ fontSize: "0.84rem", color: "var(--text-secondary)", marginBlockStart: "0.2rem" }}>
                                      <strong>Verification:</strong> {asm.verification_action}
                                    </div>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    ),
                  },
                ]}
              />
            </div>
          )}
        </section>
      )}

      <ModalDialog
        open={createOpen}
        title="Create Authorised Assessment"
        onClose={() => setCreateOpen(false)}
      >
        <form onSubmit={handleCreate} className="form-stack">
          <div className="field">
            <label htmlFor="ass-name">Assessment Name</label>
            <input
              id="ass-name"
              required
              minLength={2}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Post-Remediation Re-Verification"
            />
          </div>
          <div className="field">
            <label htmlFor="ass-desc">Description</label>
            <textarea
              id="ass-desc"
              value={desc}
              onChange={(e) => setDesc(e.target.value)}
            />
          </div>
          <div className="field">
            <label htmlFor="ass-scope">Approved Scope CIDRs / Domains (comma-separated)</label>
            <input
              id="ass-scope"
              required
              value={cidrs}
              onChange={(e) => setCidrs(e.target.value)}
            />
          </div>
          <div className="checkbox-row">
            <input
              id="ass-synth"
              type="checkbox"
              checked={isSynthetic}
              onChange={(e) => setIsSynthetic(e.target.checked)}
            />
            <label htmlFor="ass-synth">Mark as Synthetic / Demo Assessment</label>
          </div>
          <div className="btn-row">
            <button type="submit" className="btn btn-primary">
              Create Assessment
            </button>
            <button type="button" className="btn btn-secondary" onClick={() => setCreateOpen(false)}>
              Cancel
            </button>
          </div>
        </form>
      </ModalDialog>
    </div>
  );
};
