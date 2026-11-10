import React, { useCallback, useEffect, useState } from "react";
import { useAuth } from "../app/AuthContext";
import { ErrorBanner, StatusBadge } from "../components/Badges";
import { apiRequest } from "../lib/api";
import type {
  AssessmentIntelligenceResponse,
  AssessmentItem,
  CutSetRecommendation,
  RelationshipItem,
  RemediationItem,
} from "../types/api";

export const RemediationPage: React.FC = () => {
  const { hasRole } = useAuth();
  const canSimulate = hasRole("tenant_admin", "assessor", "analyst", "remediation_owner");

  const [assessments, setAssessments] = useState<AssessmentItem[]>([]);
  const [relationships, setRelationships] = useState<RelationshipItem[]>([]);
  const [remediations, setRemediations] = useState<RemediationItem[]>([]);
  const [intel, setIntel] = useState<AssessmentIntelligenceResponse | null>(null);
  const [assessmentId, setAssessmentId] = useState("");
  const [planName, setPlanName] = useState("Remove standing DB admin path");
  const [transformType, setTransformType] = useState("remove_relationship");
  const [selectedRelId, setSelectedRelId] = useState("");
  const [targetCve, setTargetCve] = useState("CVE-2024-10979");
  const [newConf, setNewConf] = useState("0.25");
  const [notes, setNotes] = useState("Isolated sandbox remediation test");
  const [validateLaterId, setValidateLaterId] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  const loadAll = useCallback(async () => {
    try {
      const [assRes, relRes, remRes] = await Promise.all([
        apiRequest<{ items: AssessmentItem[] }>("/assessments"),
        apiRequest<{ items: RelationshipItem[] }>("/relationships?include_suppressed=false&limit=200"),
        apiRequest<{ items: RemediationItem[] }>("/remediations"),
      ]);
      setAssessments(assRes.items);
      setRelationships(relRes.items);
      setRemediations(remRes.items);
      if (!assessmentId && assRes.items[0]) {
        setAssessmentId(assRes.items[0].id);
        setValidateLaterId(assRes.items[0].id);
      }
      if (!selectedRelId && relRes.items[0]) {
        setSelectedRelId(relRes.items[0].id);
      }
    } catch (err) {
      setError(err);
    }
  }, [assessmentId, selectedRelId]);

  useEffect(() => {
    loadAll();
  }, [loadAll]);

  useEffect(() => {
    if (!assessmentId) return;
    apiRequest<AssessmentIntelligenceResponse>(`/assessments/${assessmentId}/intelligence`)
      .then(setIntel)
      .catch(() => setIntel(null));
  }, [assessmentId]);

  const handleSimulateCutSet = async (cut: CutSetRecommendation) => {
    if (!assessmentId) return;
    setError(null);
    setBusy(true);
    try {
      const sim = await apiRequest<RemediationItem>("/remediations/simulate", {
        method: "POST",
        body: {
          assessment_id: assessmentId,
          name: `Cut-Set: ${cut.label}`,
          description: cut.rationale,
          transforms: cut.transforms,
        },
      });
      setNotice(
        `Simulated "${sim.name}": eliminated ${sim.delta_summary.paths_eliminated} paths (score delta -${sim.delta_summary.highest_score_reduction}).`
      );
      await loadAll();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  const handleSimulate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!assessmentId) return;
    setError(null);
    setBusy(true);
    try {
      const transform: Record<string, unknown> = {
        transform_type: transformType,
        notes: notes.trim(),
      };
      if (
        transformType === "remove_relationship" ||
        transformType === "downgrade_relationship" ||
        transformType === "disable_role" ||
        transformType === "segment_network" ||
        transformType === "rotate_service_identity"
      ) {
        transform.relationship_id = selectedRelId || null;
      }
      if (transformType === "downgrade_relationship") {
        transform.new_confidence = Number(newConf);
      }
      if (transformType === "patch_vulnerability") {
        transform.cve_id = targetCve.trim();
      }

      const sim = await apiRequest<RemediationItem>("/remediations/simulate", {
        method: "POST",
        body: {
          assessment_id: assessmentId,
          name: planName.trim(),
          description: "Interactive sandbox remediation comparison",
          transforms: [transform],
        },
      });
      setNotice(
        `Simulated "${sim.name}": eliminated ${sim.delta_summary.paths_eliminated} paths (score delta -${sim.delta_summary.highest_score_reduction}).`
      );
      await loadAll();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  const handleValidate = async (remId: string) => {
    if (!validateLaterId) return;
    setError(null);
    try {
      const res = await apiRequest<RemediationItem>(`/remediations/${remId}/validate`, {
        method: "POST",
        body: { later_assessment_id: validateLaterId },
      });
      setNotice(
        `Validation against assessment recorded (${res.validation_result ? "completed" : "done"}).`
      );
      await loadAll();
    } catch (err) {
      setError(err);
    }
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Remediation Planner &amp; Sandbox Simulator</h1>
          <p className="page-subtitle">
            Simulate control changes on an isolated copy of the graph before production rollout,
            then validate against later evidence imports.
          </p>
        </div>
      </div>

      <ErrorBanner error={error} onDismiss={() => setError(null)} />
      {notice && (
        <div className="alert alert-success" role="status">
          <strong>✓ {notice}</strong>
        </div>
      )}

      <div className="alert alert-warning" role="note">
        <strong>Modelled Impact Disclaimer</strong>
        <span>
          Every remediation scenario executes against a deep copy of the baseline graph and leaves
          live ingested evidence untouched. Modelled impact does not prove remediation on live
          systems until re-validated against a later assessment.
        </span>
      </div>

      {intel && intel.cut_sets.length > 0 && (
        <section className="card">
          <h2 className="card-title">
            Graph-Solved Minimum Cut-Sets ({intel.cut_sets.length} Recommended Strategies)
          </h2>
          <p style={{ margin: "0 0 0.75rem", color: "var(--text-secondary)", fontSize: "0.9rem" }}>
            Automatically solved hitting-sets for <strong>{intel.assessment_name}</strong> ranked by
            complete path elimination, cut size, and engineering effort.
          </p>
          <div className="form-stack">
            {intel.cut_sets.map((cut) => (
              <article key={cut.id} className="selectable-intel-row">
                <div style={{ minInlineSize: 0, flex: "1 1 22rem" }}>
                  <div>
                    <strong>{cut.label}</strong>{" "}
                    <span
                      className={`badge ${
                        cut.residual_paths === 0 ? "badge-success" : "badge-medium"
                      }`}
                    >
                      Eliminates {cut.paths_broken}/{cut.baseline_paths} paths ({cut.coverage_pct}%)
                    </span>{" "}
                    <span className="badge badge-neutral">{cut.cut_size} transform(s)</span>
                  </div>
                  <p style={{ margin: "0.25rem 0", fontSize: "0.86rem", color: "var(--text-secondary)" }}>
                    {cut.rationale}
                  </p>
                  <ul style={{ margin: 0, paddingInlineStart: "1.2rem", fontSize: "0.84rem" }}>
                    {cut.steps_summary.map((s, idx) => (
                      <li key={idx}>{s}</li>
                    ))}
                  </ul>
                </div>
                {canSimulate && (
                  <button
                    type="button"
                    className="btn btn-primary btn-sm"
                    disabled={busy}
                    aria-label={`Simulate cut-set ${cut.label}`}
                    onClick={() => handleSimulateCutSet(cut)}
                  >
                    Simulate Cut-Set Plan
                  </button>
                )}
              </article>
            ))}
          </div>
        </section>
      )}

      {canSimulate && (
        <section className="card">
          <h2 className="card-title">Build Remediation Transform Scenario</h2>
          <form onSubmit={handleSimulate} className="form-stack">
            <div className="grid-2">
              <div className="field">
                <label htmlFor="rem-assess">Baseline Assessment</label>
                <select
                  id="rem-assess"
                  value={assessmentId}
                  onChange={(e) => setAssessmentId(e.target.value)}
                >
                  {assessments.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.name}
                    </option>
                  ))}
                </select>
              </div>
              <div className="field">
                <label htmlFor="rem-name">Scenario Name</label>
                <input
                  id="rem-name"
                  required
                  value={planName}
                  onChange={(e) => setPlanName(e.target.value)}
                />
              </div>
            </div>

            <div className="grid-2">
              <div className="field">
                <label htmlFor="rem-ttype">Graph Transform Operation</label>
                <select
                  id="rem-ttype"
                  value={transformType}
                  onChange={(e) => setTransformType(e.target.value)}
                >
                  <option value="remove_relationship">Remove Relationship Edge</option>
                  <option value="downgrade_relationship">Downgrade Edge Confidence</option>
                  <option value="disable_role">Disable Privileged Role / Group Edge</option>
                  <option value="segment_network">Segment Network Reachability Edge</option>
                  <option value="rotate_service_identity">Rotate Service Identity Edge</option>
                  <option value="patch_vulnerability">Patch CVE Observation</option>
                </select>
              </div>

              {transformType === "patch_vulnerability" ? (
                <div className="field">
                  <label htmlFor="rem-cve">CVE ID to Mark Patched</label>
                  <input
                    id="rem-cve"
                    value={targetCve}
                    onChange={(e) => setTargetCve(e.target.value)}
                  />
                </div>
              ) : (
                <div className="field">
                  <label htmlFor="rem-rel">Target Relationship Edge</label>
                  <select
                    id="rem-rel"
                    value={selectedRelId}
                    onChange={(e) => setSelectedRelId(e.target.value)}
                  >
                    {relationships.map((r) => (
                      <option key={r.id} value={r.id}>
                        {r.source_label} --[{r.relation_type}]--&gt; {r.target_label}
                      </option>
                    ))}
                  </select>
                </div>
              )}
            </div>

            {transformType === "downgrade_relationship" && (
              <div className="field" style={{ maxWidth: "16rem" }}>
                <label htmlFor="rem-conf">New Modelled Confidence (0.05 – 1.0)</label>
                <input
                  id="rem-conf"
                  type="number"
                  step="0.05"
                  min="0.05"
                  max="1"
                  value={newConf}
                  onChange={(e) => setNewConf(e.target.value)}
                />
              </div>
            )}

            <div className="field">
              <label htmlFor="rem-notes">Control Notes</label>
              <input id="rem-notes" value={notes} onChange={(e) => setNotes(e.target.value)} />
            </div>

            <div>
              <button type="submit" className="btn btn-primary" disabled={busy}>
                {busy ? "Running Sandbox Simulation..." : "Run Before / After Simulation"}
              </button>
            </div>
          </form>
        </section>
      )}

      <section className="card">
        <h2 className="card-title">Simulated Scenarios ({remediations.length})</h2>
        <div className="form-stack">
          {remediations.map((rem) => (
            <article
              key={rem.id}
              style={{
                border: "1px solid var(--border-subtle)",
                borderRadius: "0.5rem",
                padding: "1rem",
              }}
            >
              <div
                style={{
                  display: "flex",
                  flexWrap: "wrap",
                  justifyContent: "space-between",
                  gap: "0.5rem",
                }}
              >
                <div>
                  <strong>{rem.name}</strong>
                  <div style={{ fontSize: "0.85rem", color: "var(--text-secondary)" }}>
                    {rem.description}
                  </div>
                </div>
                <div className="btn-row">
                  <StatusBadge status={rem.status} />
                  {rem.is_modelled_only && (
                    <span className="badge badge-medium">Modelled Only (Unverified)</span>
                  )}
                </div>
              </div>

              <div className="grid-2" style={{ marginBlockStart: "0.75rem" }}>
                <div
                  style={{
                    background: "var(--bg-subtle)",
                    padding: "0.75rem",
                    borderRadius: "0.375rem",
                  }}
                >
                  <strong>Baseline Graph</strong>
                  <div>Total Paths: {rem.baseline_metrics.total_paths}</div>
                  <div>Highest Priority Score: {rem.baseline_metrics.highest_path_score}</div>
                  <div>
                    Reachable Critical Assets: {rem.baseline_metrics.reachable_critical_assets}
                  </div>
                </div>
                <div
                  style={{
                    background: "#f0fdf4",
                    padding: "0.75rem",
                    borderRadius: "0.375rem",
                    border: "1px solid #86efac",
                  }}
                >
                  <strong>Modelled Post-Remediation</strong>
                  <div>
                    Total Paths: {rem.modelled_metrics.total_paths} (
                    <strong>-{rem.delta_summary.paths_eliminated} eliminated</strong>)
                  </div>
                  <div>
                    Highest Score: {rem.modelled_metrics.highest_path_score} (
                    <strong>-{rem.delta_summary.highest_score_reduction}</strong>)
                  </div>
                  <div>
                    Critical Assets Unlinked: <strong>{rem.delta_summary.critical_assets_unlinked}</strong>
                  </div>
                </div>
              </div>

              {canSimulate && (
                <div
                  style={{
                    display: "flex",
                    flexWrap: "wrap",
                    alignItems: "center",
                    gap: "0.6rem",
                    marginBlockStart: "0.75rem",
                  }}
                >
                  <label htmlFor={`val-${rem.id}`} style={{ fontWeight: 600, fontSize: "0.85rem" }}>
                    Validate against later assessment:
                  </label>
                  <select
                    id={`val-${rem.id}`}
                    value={validateLaterId}
                    onChange={(e) => setValidateLaterId(e.target.value)}
                    style={{ minHeight: "38px" }}
                  >
                    {assessments.map((a) => (
                      <option key={a.id} value={a.id}>
                        {a.name}
                      </option>
                    ))}
                  </select>
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    onClick={() => handleValidate(rem.id)}
                  >
                    Compare &amp; Validate
                  </button>
                </div>
              )}

              {rem.validation_result && (
                <pre
                  className="mono"
                  style={{
                    marginBlockStart: "0.6rem",
                    padding: "0.65rem",
                    background: "var(--bg-subtle)",
                    borderRadius: "0.375rem",
                    overflowX: "auto",
                  }}
                >
                  {JSON.stringify(rem.validation_result, null, 2)}
                </pre>
              )}
            </article>
          ))}
        </div>
      </section>
    </div>
  );
};
