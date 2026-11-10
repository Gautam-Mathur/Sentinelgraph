import React, { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../app/AuthContext";
import { ErrorBanner } from "../components/Badges";
import { apiDownloadBlob, apiRequest } from "../lib/api";
import type { AssessmentItem, JobItem, RemediationItem, ReportItem } from "../types/api";

export const ReportsPage: React.FC = () => {
  const { hasRole } = useAuth();
  const canGenerate = hasRole("tenant_admin", "assessor", "analyst", "remediation_owner");

  const [assessments, setAssessments] = useState<AssessmentItem[]>([]);
  const [remediations, setRemediations] = useState<RemediationItem[]>([]);
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [selectedReport, setSelectedReport] = useState<ReportItem | null>(null);
  const [assessmentId, setAssessmentId] = useState("");
  const [remediationId, setRemediationId] = useState("");
  const [title, setTitle] = useState("Enterprise Attack-Path Assessment Report");
  const [notice, setNotice] = useState("");
  const [error, setError] = useState<unknown>(null);

  const loadAll = useCallback(async () => {
    try {
      const [assRes, remRes, repRes] = await Promise.all([
        apiRequest<{ items: AssessmentItem[] }>("/assessments"),
        apiRequest<{ items: RemediationItem[] }>("/remediations"),
        apiRequest<{ items: ReportItem[] }>("/reports"),
      ]);
      setAssessments(assRes.items);
      setRemediations(remRes.items);
      setReports(repRes.items);
      if (!assessmentId && assRes.items[0]) {
        setAssessmentId(assRes.items[0].id);
      }
      if (repRes.items[0] && !selectedReport) {
        const detail = await apiRequest<ReportItem>(`/reports/${repRes.items[0].id}`);
        setSelectedReport(detail);
      }
    } catch (err) {
      setError(err);
    }
  }, [assessmentId, selectedReport]);

  useEffect(() => {
    loadAll();
  }, [loadAll]);

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!assessmentId) return;
    setError(null);
    try {
      const created = await apiRequest<ReportItem>("/reports", {
        method: "POST",
        body: {
          assessment_id: assessmentId,
          title: title.trim() || null,
          remediation_action_id: remediationId || null,
          report_format: "html",
        },
      });
      setSelectedReport(created);
      await loadAll();
    } catch (err) {
      setError(err);
    }
  };

  const handleQueueReportJob = async () => {
    if (!assessmentId) return;
    setError(null);
    try {
      const job = await apiRequest<JobItem>("/jobs", {
        method: "POST",
        body: {
          job_type: "generate_report",
          payload: {
            assessment_id: assessmentId,
            title: title.trim() || null,
            remediation_action_id: remediationId || null,
          },
        },
      });
      setNotice(`Queued async report job (${job.id.slice(0, 8)}): status=${job.status}.`);
      await loadAll();
    } catch (err) {
      setError(err);
    }
  };

  const handleInspectReport = async (id: string) => {
    setError(null);
    try {
      const detail = await apiRequest<ReportItem>(`/reports/${id}`);
      setSelectedReport(detail);
    } catch (err) {
      setError(err);
    }
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Evidence Reports &amp; Multi-Format Exports</h1>
          <p className="page-subtitle">
            Auto-escaped Jinja2 HTML, structured JSON, formula-neutralised CSV, and SARIF v2.1.0
            exports preserving methodology caveats, scoring versions, and synthetic watermarks.
          </p>
        </div>
      </div>

      <ErrorBanner error={error} onDismiss={() => setError(null)} />
      {notice && (
        <div className="alert alert-success" role="status">
          <strong>✓ {notice}</strong>{" "}
          <Link to="/jobs" style={{ fontWeight: 600 }}>
            View Background Jobs →
          </Link>
        </div>
      )}

      {canGenerate && (
        <section className="card">
          <h2 className="card-title">Generate New HTML Report</h2>
          <form onSubmit={handleGenerate} className="form-stack">
            <div className="grid-2">
              <div className="field">
                <label htmlFor="rep-assess">Assessment</label>
                <select
                  id="rep-assess"
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
                <label htmlFor="rep-rem">Include Remediation Plan (optional)</label>
                <select
                  id="rep-rem"
                  value={remediationId}
                  onChange={(e) => setRemediationId(e.target.value)}
                >
                  <option value="">None</option>
                  {remediations.map((r) => (
                    <option key={r.id} value={r.id}>
                      {r.name}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            <div className="field">
              <label htmlFor="rep-title">Report Title</label>
              <input
                id="rep-title"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
              />
            </div>
            <div className="btn-row">
              <button type="submit" className="btn btn-primary">
                Generate HTML Report
              </button>
              <button type="button" className="btn btn-secondary" onClick={handleQueueReportJob}>
                Queue Async Report Job
              </button>
            </div>
          </form>
        </section>
      )}

      <section className="card">
        <div className="table-region" tabIndex={0} role="region" aria-label="Generated reports">
          <table className="data-table">
            <caption>Generated Reports ({reports.length})</caption>
            <thead>
              <tr>
                <th scope="col">Title</th>
                <th scope="col">Watermark</th>
                <th scope="col">Scoring Version</th>
                <th scope="col">Actions</th>
              </tr>
            </thead>
            <tbody>
              {reports.map((rep) => (
                <tr key={rep.id}>
                  <th scope="row" data-label="Title">
                    {rep.title}
                  </th>
                  <td data-label="Watermark">
                    {rep.is_synthetic_watermarked ? (
                      <span className="badge badge-medium">⚠ Synthetic Watermarked</span>
                    ) : (
                      <span className="badge badge-neutral">Production</span>
                    )}
                  </td>
                  <td data-label="Scoring Version" className="mono">
                    {rep.scoring_version}
                  </td>
                  <td data-label="Actions">
                    <div className="btn-row">
                      <button
                        type="button"
                        className="btn btn-secondary btn-sm"
                        onClick={() => handleInspectReport(rep.id)}
                      >
                        Preview Sandboxed
                      </button>
                      <button
                        type="button"
                        className="btn btn-primary btn-sm"
                        onClick={() =>
                          apiDownloadBlob(
                            `/reports/${rep.id}/download?format=html`,
                            `sentinelgraph-report-${rep.id}.html`
                          ).catch(setError)
                        }
                      >
                        Download HTML
                      </button>
                      <button
                        type="button"
                        className="btn btn-secondary btn-sm"
                        onClick={() =>
                          apiDownloadBlob(
                            `/reports/${rep.id}/download?format=json`,
                            `sentinelgraph-report-${rep.id}.json`
                          ).catch(setError)
                        }
                      >
                        JSON
                      </button>
                      <button
                        type="button"
                        className="btn btn-secondary btn-sm"
                        onClick={() =>
                          apiDownloadBlob(
                            `/reports/${rep.id}/download?format=csv`,
                            `sentinelgraph-report-${rep.id}.csv`
                          ).catch(setError)
                        }
                      >
                        CSV
                      </button>
                      <button
                        type="button"
                        className="btn btn-secondary btn-sm"
                        onClick={() =>
                          apiDownloadBlob(
                            `/reports/${rep.id}/download?format=sarif`,
                            `sentinelgraph-report-${rep.id}.sarif.json`
                          ).catch(setError)
                        }
                      >
                        SARIF
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {selectedReport?.html_content && (
        <section className="card">
          <h2 className="card-title">Sandboxed Report Preview: {selectedReport.title}</h2>
          <iframe
            className="report-frame"
            sandbox=""
            title={`Sandboxed preview of ${selectedReport.title}`}
            srcDoc={selectedReport.html_content}
          />
        </section>
      )}
    </div>
  );
};
