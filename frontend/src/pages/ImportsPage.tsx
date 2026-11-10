import React, { useCallback, useEffect, useState } from "react";
import { useAuth } from "../app/AuthContext";
import { ErrorBanner, StatusBadge } from "../components/Badges";
import { ModalDialog } from "../components/ModalDialog";
import { apiRequest } from "../lib/api";
import type { AssessmentItem, ImportItem } from "../types/api";

export const ImportsPage: React.FC = () => {
  const { hasRole } = useAuth();
  const canStage = hasRole("tenant_admin", "assessor", "analyst");
  const canApprove = hasRole("tenant_admin", "assessor");

  const [assessments, setAssessments] = useState<AssessmentItem[]>([]);
  const [imports, setImports] = useState<ImportItem[]>([]);
  const [assessmentId, setAssessmentId] = useState("");
  const [sourceFormat, setSourceFormat] = useState("nmap_xml");
  const [file, setFile] = useState<File | null>(null);
  const [idempotencyKey, setIdempotencyKey] = useState("");
  const [rejectTarget, setRejectTarget] = useState<ImportItem | null>(null);
  const [rejectReason, setRejectReason] = useState("");
  const [notice, setNotice] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const loadAll = useCallback(async () => {
    try {
      const [assRes, impRes] = await Promise.all([
        apiRequest<{ items: AssessmentItem[] }>("/assessments"),
        apiRequest<{ items: ImportItem[] }>("/imports"),
      ]);
      setAssessments(assRes.items);
      setImports(impRes.items);
      if (!assessmentId && assRes.items[0]) {
        setAssessmentId(assRes.items[0].id);
      }
    } catch (err) {
      setError(err);
    }
  }, [assessmentId]);

  useEffect(() => {
    loadAll();
  }, [loadAll]);

  const handleUploadStage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!assessmentId || !file) return;
    setError(null);
    setBusy(true);
    try {
      const fd = new FormData();
      fd.append("assessment_id", assessmentId);
      fd.append("source_format", sourceFormat);
      fd.append("file", file);

      const staged = await apiRequest<ImportItem>("/imports", {
        method: "POST",
        body: fd,
        headers: idempotencyKey.trim()
          ? { "Idempotency-Key": idempotencyKey.trim() }
          : undefined,
      });
      setNotice(
        `Staged "${staged.filename}" (${staged.parser_version}). Inspect preview warnings before approving & committing.`
      );
      setFile(null);
      await loadAll();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  const handleApprove = async (impId: string) => {
    setError(null);
    try {
      await apiRequest(`/imports/${impId}/approve`, { method: "POST" });
      setNotice("Staged import approved for commit.");
      await loadAll();
    } catch (err) {
      setError(err);
    }
  };

  const handleCommit = async (impId: string) => {
    setError(null);
    try {
      await apiRequest(`/imports/${impId}/commit`, { method: "POST" });
      setNotice("Import committed into normalised tenant inventory & observations.");
      await loadAll();
    } catch (err) {
      setError(err);
    }
  };

  const handleReject = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!rejectTarget) return;
    setError(null);
    try {
      await apiRequest(`/imports/${rejectTarget.id}/reject`, {
        method: "POST",
        body: { reason: rejectReason.trim() },
      });
      setRejectTarget(null);
      setRejectReason("");
      setNotice("Staged import rejected.");
      await loadAll();
    } catch (err) {
      setError(err);
    }
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Evidence Ingestion &amp; Staged Imports</h1>
          <p className="page-subtitle">
            Strict staged workflow: Upload &amp; Parse Preview → Scope/Schema Validation →
            Assessor Approval → Idempotent Atomic Commit. Live Nmap execution is prohibited in MVP.
          </p>
        </div>
      </div>

      <ErrorBanner error={error} onDismiss={() => setError(null)} />
      {notice && (
        <div className="alert alert-success" role="status">
          <strong>✓ {notice}</strong>
        </div>
      )}

      {canStage && (
        <section className="card">
          <h2 className="card-title">Stage Authorised Evidence File</h2>
          <form onSubmit={handleUploadStage} className="form-stack">
            <div className="grid-2">
              <div className="field">
                <label htmlFor="imp-assess">Approved Assessment</label>
                <select
                  id="imp-assess"
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

              <div className="field">
                <label htmlFor="imp-fmt">Parser Adapter Format</label>
                <select
                  id="imp-fmt"
                  value={sourceFormat}
                  onChange={(e) => setSourceFormat(e.target.value)}
                >
                  <option value="nmap_xml">Nmap XML Export (defusedxml hardened)</option>
                  <option value="nessus_xml">Tenable Nessus (.nessus XML)</option>
                  <option value="sarif_json">SARIF v2.1.0 / Trivy Vulnerability JSON</option>
                  <option value="bloodhound_json">BloodHound / SharpHound Directory JSON</option>
                  <option value="aws_iam_export_json">
                    Offline AWS IAM / Security Group Snapshot JSON
                  </option>
                  <option value="network_topology_json">
                    Network Topology / Firewall Rules JSON
                  </option>
                  <option value="network_topology_csv">Network Topology / ACL CSV</option>
                  <option value="identity_json">Identity &amp; Group Export JSON</option>
                  <option value="vulnerability_json">Vulnerability Findings JSON</option>
                  <option value="relationship_json">Validated Relationship Export JSON</option>
                </select>
              </div>
            </div>

            <div className="grid-2">
              <div className="field">
                <label htmlFor="imp-file">Evidence File (.xml, .nessus, .json, .sarif, or .csv)</label>
                <input
                  id="imp-file"
                  type="file"
                  required
                  accept=".xml,.nessus,.json,.sarif,.csv,application/xml,text/xml,application/json,text/csv"
                  onChange={(e) => setFile(e.target.files?.[0] || null)}
                />
              </div>

              <div className="field">
                <label htmlFor="imp-idem">Idempotency Key (optional)</label>
                <input
                  id="imp-idem"
                  value={idempotencyKey}
                  onChange={(e) => setIdempotencyKey(e.target.value)}
                  placeholder="e.g. sprint4-nmap-batch-1"
                />
              </div>
            </div>

            <div>
              <button type="submit" className="btn btn-primary" disabled={busy || !file}>
                {busy ? "Parsing & Staging..." : "Upload & Preview Stage"}
              </button>
            </div>
          </form>
        </section>
      )}

      <section className="card">
        <div className="table-region" tabIndex={0} role="region" aria-label="Staged and committed imports">
          <table className="data-table">
            <caption>Import Staging Queue &amp; History ({imports.length})</caption>
            <thead>
              <tr>
                <th scope="col">File / Format</th>
                <th scope="col">SHA-256 &amp; Size</th>
                <th scope="col">Preview Summary &amp; Scope Warnings</th>
                <th scope="col">Status</th>
                <th scope="col">Workflow Actions</th>
              </tr>
            </thead>
            <tbody>
              {imports.map((imp) => {
                const warnings = imp.preview_summary?.warnings || [];
                return (
                  <tr key={imp.id}>
                    <th scope="row" data-label="File / Format">
                      <div>{imp.filename}</div>
                      <div className="mono">
                        {imp.source_format} ({imp.parser_version})
                      </div>
                    </th>
                    <td data-label="SHA-256 & Size">
                      <div className="mono">{imp.file_sha256.slice(0, 16)}...</div>
                      <div>{imp.file_size_bytes} bytes</div>
                    </td>
                    <td data-label="Preview Summary">
                      <pre className="mono" style={{ margin: 0, whiteSpace: "pre-wrap" }}>
                        {JSON.stringify(imp.preview_summary, null, 2)}
                      </pre>
                      {warnings.length > 0 && (
                        <div className="badge badge-medium" style={{ marginTop: "0.3rem" }}>
                          ⚠ {warnings.length} scope/parser warning(s)
                        </div>
                      )}
                    </td>
                    <td data-label="Status">
                      <StatusBadge status={imp.status} />
                      {imp.error_detail && (
                        <div style={{ color: "var(--danger)", fontSize: "0.8rem" }}>
                          {typeof imp.error_detail === "string"
                            ? imp.error_detail
                            : JSON.stringify(imp.error_detail)}
                        </div>
                      )}
                    </td>
                    <td data-label="Workflow Actions">
                      <div className="btn-row">
                        {canApprove && (imp.status === "preview_ready" || imp.status === "staged") && (
                          <>
                            <button
                              type="button"
                              className="btn btn-primary btn-sm"
                              onClick={() => handleApprove(imp.id)}
                            >
                              Approve
                            </button>
                            <button
                              type="button"
                              className="btn btn-danger btn-sm"
                              onClick={() => setRejectTarget(imp)}
                            >
                              Reject
                            </button>
                          </>
                        )}
                        {canApprove && imp.status === "approved" && (
                          <button
                            type="button"
                            className="btn btn-primary btn-sm"
                            onClick={() => handleCommit(imp.id)}
                          >
                            Commit Atomically
                          </button>
                        )}
                        {imp.status === "committed" && (
                          <span className="badge badge-success">✓ Committed</span>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      <ModalDialog
        open={Boolean(rejectTarget)}
        title="Reject Staged Import"
        onClose={() => setRejectTarget(null)}
      >
        <form onSubmit={handleReject} className="form-stack">
          <p style={{ margin: 0 }}>Reject import "{rejectTarget?.filename}" cleanly.</p>
          <div className="field">
            <label htmlFor="rej-reason">Rejection Reason</label>
            <textarea
              id="rej-reason"
              required
              minLength={3}
              value={rejectReason}
              onChange={(e) => setRejectReason(e.target.value)}
            />
          </div>
          <div className="btn-row">
            <button type="submit" className="btn btn-danger">
              Reject Import
            </button>
            <button type="button" className="btn btn-secondary" onClick={() => setRejectTarget(null)}>
              Cancel
            </button>
          </div>
        </form>
      </ModalDialog>
    </div>
  );
};
