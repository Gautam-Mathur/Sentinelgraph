import React, { useCallback, useEffect, useState } from "react";
import { useAuth } from "../app/AuthContext";
import { ErrorBanner, StatusBadge } from "../components/Badges";
import { apiRequest } from "../lib/api";
import type { AssessmentItem, BackgroundJobType, JobItem } from "../types/api";

export const JobsPage: React.FC = () => {
  const { hasRole } = useAuth();
  const canEnqueue = hasRole("tenant_admin", "assessor", "analyst", "remediation_owner");
  const canCancel = hasRole("tenant_admin", "assessor");

  const [jobs, setJobs] = useState<JobItem[]>([]);
  const [assessments, setAssessments] = useState<AssessmentItem[]>([]);
  const [jobType, setJobType] = useState<BackgroundJobType>("build_graph");
  const [assessmentId, setAssessmentId] = useState("");
  const [reportTitle, setReportTitle] = useState("Scheduled Worker Assessment Report");
  const [dryRunRetention, setDryRunRetention] = useState(true);
  const [idempotencyKey, setIdempotencyKey] = useState("");
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const loadJobs = useCallback(async () => {
    try {
      const [jobsRes, assRes] = await Promise.all([
        apiRequest<{ items: JobItem[] }>("/jobs"),
        apiRequest<{ items: AssessmentItem[] }>("/assessments"),
      ]);
      setJobs(jobsRes.items);
      setAssessments(assRes.items);
      if (!assessmentId && assRes.items[0]) {
        setAssessmentId(assRes.items[0].id);
      }
    } catch (err) {
      setError(err);
    }
  }, [assessmentId]);

  useEffect(() => {
    loadJobs();
  }, [loadJobs]);

  const hasActiveJobs = jobs.some((j) => j.status === "queued" || j.status === "running");

  useEffect(() => {
    if (!autoRefresh || !hasActiveJobs) return;
    const timer = setInterval(() => {
      loadJobs();
    }, 3000);
    return () => clearInterval(timer);
  }, [autoRefresh, hasActiveJobs, loadJobs]);

  const handleEnqueue = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      let payload: Record<string, unknown>;
      if (jobType === "enforce_retention") {
        payload = { dry_run: dryRunRetention };
      } else if (jobType === "generate_report") {
        payload = {
          assessment_id: assessmentId,
          title: reportTitle.trim() || null,
        };
      } else if (jobType === "generate_paths") {
        payload = {
          assessment_id: assessmentId,
          algorithm: "dijkstra",
          max_hops: 6,
          max_candidates: 200,
          min_confidence: 0.2,
          top_k: 10,
        };
      } else {
        payload = { assessment_id: assessmentId };
      }

      const created = await apiRequest<JobItem>("/jobs", {
        method: "POST",
        body: { job_type: jobType, payload },
        headers: idempotencyKey.trim()
          ? { "Idempotency-Key": idempotencyKey.trim() }
          : undefined,
      });
      setNotice(`Background job "${created.job_type}" (${created.id.slice(0, 8)}) -> ${created.status}.`);
      setIdempotencyKey("");
      await loadJobs();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  const handleCancel = async (jobId: string) => {
    setError(null);
    try {
      const updated = await apiRequest<JobItem>(`/jobs/${jobId}/cancel`, { method: "POST" });
      setNotice(`Job ${jobId.slice(0, 8)} marked ${updated.status}.`);
      await loadJobs();
    } catch (err) {
      setError(err);
    }
  };

  const activeCount = jobs.filter((j) => j.status === "queued" || j.status === "running").length;
  const succeededCount = jobs.filter((j) => j.status === "succeeded").length;
  const failedCount = jobs.filter((j) => j.status === "failed" || j.status === "dead_letter").length;

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Background Worker Jobs &amp; Queue Status</h1>
          <p className="page-subtitle">
            Monitor RQ asynchronous graph builds, attack-path computations, report generation, and
            scheduled retention enforcement with deterministic retry and cancellation state.
          </p>
        </div>
        <div className="btn-row">
          <div className="checkbox-row" style={{ minHeight: "36px" }}>
            <input
              id="jobs-autorefresh"
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
            />
            <label htmlFor="jobs-autorefresh">Auto-poll active jobs (3s)</label>
          </div>
          <button type="button" className="btn btn-secondary" onClick={loadJobs}>
            ↻ Refresh Queue
          </button>
        </div>
      </div>

      <ErrorBanner error={error} onDismiss={() => setError(null)} />
      {notice && (
        <div className="alert alert-success" role="status">
          <strong>✓ {notice}</strong>
        </div>
      )}

      <div className="kpi-grid">
        <div className="kpi-card">
          <span className="kpi-label">Recent Jobs</span>
          <span className="kpi-value">{jobs.length}</span>
          <span className="kpi-hint">Last 50 in tenant</span>
        </div>
        <div className="kpi-card">
          <span className="kpi-label">Active (Queued / Running)</span>
          <span className="kpi-value">{activeCount}</span>
          <span className="kpi-hint">{hasActiveJobs ? "Polling active" : "Queue idle"}</span>
        </div>
        <div className="kpi-card">
          <span className="kpi-label">Succeeded</span>
          <span className="kpi-value">{succeededCount}</span>
          <span className="kpi-hint">Completed cleanly</span>
        </div>
        <div className="kpi-card">
          <span className="kpi-label">Failed / Dead-Letter</span>
          <span className="kpi-value">{failedCount}</span>
          <span className="kpi-hint">Inspect error message below</span>
        </div>
      </div>

      {canEnqueue && (
        <section className="card">
          <h2 className="card-title">Enqueue Typed Worker Job</h2>
          <form onSubmit={handleEnqueue} className="form-stack">
            <div className="grid-2">
              <div className="field">
                <label htmlFor="job-type">Job Type (Whitelisted)</label>
                <select
                  id="job-type"
                  name="job_type"
                  value={jobType}
                  onChange={(e) => setJobType(e.target.value as BackgroundJobType)}
                >
                  <option value="build_graph">build_graph — Compile Assessment Graph</option>
                  <option value="generate_paths">generate_paths — Compute Attack Paths</option>
                  <option value="generate_report">generate_report — Render Evidence Report</option>
                  {hasRole("tenant_admin") && (
                    <option value="enforce_retention">enforce_retention — Execute Retention Schedule</option>
                  )}
                </select>
              </div>

              {jobType !== "enforce_retention" ? (
                <div className="field">
                  <label htmlFor="job-assess">Target Assessment</label>
                  <select
                    id="job-assess"
                    name="assessment_id"
                    value={assessmentId}
                    onChange={(e) => setAssessmentId(e.target.value)}
                  >
                    {assessments.map((a) => (
                      <option key={a.id} value={a.id}>
                        {a.name} ({a.status})
                      </option>
                    ))}
                  </select>
                </div>
              ) : (
                <div className="field">
                  <div className="checkbox-row" style={{ marginTop: "1.6rem" }}>
                    <input
                      id="job-ret-dryrun"
                      type="checkbox"
                      checked={dryRunRetention}
                      onChange={(e) => setDryRunRetention(e.target.checked)}
                    />
                    <label htmlFor="job-ret-dryrun">
                      Dry Run only (count expired records without deleting)
                    </label>
                  </div>
                </div>
              )}
            </div>

            {jobType === "generate_report" && (
              <div className="field">
                <label htmlFor="job-rep-title">Report Title</label>
                <input
                  id="job-rep-title"
                  value={reportTitle}
                  onChange={(e) => setReportTitle(e.target.value)}
                />
              </div>
            )}

            <div className="field">
              <label htmlFor="job-idem">Idempotency Key (optional)</label>
              <input
                id="job-idem"
                value={idempotencyKey}
                onChange={(e) => setIdempotencyKey(e.target.value)}
                placeholder="e.g. nightly-graph-build-2026-11-10"
                autoCorrect="off"
                autoCapitalize="none"
                spellCheck={false}
              />
            </div>

            <div>
              <button
                type="submit"
                className="btn btn-primary"
                disabled={busy || (jobType !== "enforce_retention" && !assessmentId)}
              >
                {busy ? "Enqueuing..." : "Enqueue Worker Job"}
              </button>
            </div>
          </form>
        </section>
      )}

      <section className="card">
        <div className="table-region" tabIndex={0} role="region" aria-label="Background jobs queue">
          <table className="data-table">
            <caption>Background Jobs ({jobs.length})</caption>
            <thead>
              <tr>
                <th scope="col">Job Type / ID</th>
                <th scope="col">Status</th>
                <th scope="col">Progress</th>
                <th scope="col">Attempts</th>
                <th scope="col">Result / Error</th>
                <th scope="col">Actions</th>
              </tr>
            </thead>
            <tbody>
              {jobs.length === 0 ? (
                <tr>
                  <td colSpan={6} style={{ color: "var(--text-muted)" }}>
                    No background jobs queued for this tenant yet.
                  </td>
                </tr>
              ) : (
                jobs.map((j) => {
                  const isIndeterminate =
                    j.status === "queued" || (j.status === "running" && j.progress === 0);
                  const progValue = j.status === "succeeded" ? 100 : j.progress;
                  return (
                    <tr key={j.id}>
                      <th scope="row" data-label="Job Type / ID">
                        <div className="mono">{j.job_type}</div>
                        <div className="mono" style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                          {j.id}
                        </div>
                      </th>
                      <td data-label="Status">
                        <StatusBadge status={j.status} />
                        <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                          {new Date(j.created_at).toLocaleString()}
                        </div>
                      </td>
                      <td data-label="Progress">
                        <div className="job-progress-cell">
                          <progress
                            max={100}
                            {...(isIndeterminate ? {} : { value: progValue })}
                            aria-label={`Progress for ${j.job_type} job ${j.id.slice(0, 8)}`}
                          />
                          <span className="mono">{isIndeterminate ? "..." : `${progValue}%`}</span>
                        </div>
                      </td>
                      <td data-label="Attempts" className="mono">
                        {j.attempts} / {j.max_attempts}
                      </td>
                      <td data-label="Result / Error">
                        {j.error_message ? (
                          <div style={{ color: "var(--danger)", fontSize: "0.82rem" }}>
                            {j.error_message}
                          </div>
                        ) : j.result ? (
                          <pre className="mono" style={{ margin: 0, whiteSpace: "pre-wrap", fontSize: "0.75rem" }}>
                            {JSON.stringify(j.result)}
                          </pre>
                        ) : (
                          <span style={{ color: "var(--text-muted)", fontSize: "0.82rem" }}>Pending</span>
                        )}
                      </td>
                      <td data-label="Actions">
                        {canCancel && (j.status === "queued" || j.status === "running") ? (
                          <button
                            type="button"
                            className="btn btn-danger btn-sm"
                            aria-label={`Cancel job ${j.job_type} ${j.id.slice(0, 8)}`}
                            onClick={() => handleCancel(j.id)}
                          >
                            Cancel
                          </button>
                        ) : (
                          <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>—</span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};
