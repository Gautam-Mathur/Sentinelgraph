import React, { useCallback, useEffect, useState } from "react";
import { useAuth } from "../app/AuthContext";
import { CriticalityBadge, ErrorBanner, StatusBadge } from "../components/Badges";
import { ModalDialog } from "../components/ModalDialog";
import { apiRequest } from "../lib/api";
import type { FindingRecord } from "../types/api";

export const FindingsPage: React.FC = () => {
  const { hasRole } = useAuth();
  const canTriage = hasRole("tenant_admin", "assessor", "analyst", "remediation_owner");

  const [findings, setFindings] = useState<FindingRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [notice, setNotice] = useState("");
  const [error, setError] = useState<unknown>(null);

  const [triageTarget, setTriageTarget] = useState<FindingRecord | null>(null);
  const [triageStatus, setTriageStatus] = useState("open");
  const [triageNote, setTriageNote] = useState("");
  const [busy, setBusy] = useState(false);

  const loadFindings = useCallback(async () => {
    try {
      const qs = new URLSearchParams();
      if (search.trim()) qs.set("search", search.trim());
      if (severity) qs.set("severity", severity);
      if (statusFilter) qs.set("status", statusFilter);
      const res = await apiRequest<{ items: FindingRecord[]; total: number }>(
        `/findings?${qs.toString()}`
      );
      setFindings(res.items);
      setTotal(res.total);
    } catch (err) {
      setError(err);
    }
  }, [search, severity, statusFilter]);

  useEffect(() => {
    loadFindings();
  }, [loadFindings]);

  const handleFilterSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    await loadFindings();
  };

  const handleOpenTriage = (f: FindingRecord) => {
    setTriageTarget(f);
    setTriageStatus(f.status || "open");
    setTriageNote(f.triage_note || "");
  };

  const handleSaveTriage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!triageTarget) return;
    setError(null);
    setBusy(true);
    try {
      await apiRequest(`/findings/${triageTarget.id}`, {
        method: "PATCH",
        body: {
          status: triageStatus,
          triage_note: triageNote.trim(),
        },
      });
      setNotice(
        `Triaged ${triageTarget.cve_id || "finding"} on ${triageTarget.asset_display_name} -> ${triageStatus}.`
      );
      setTriageTarget(null);
      await loadFindings();
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
          <h1 className="page-title">Vulnerability Findings &amp; Analyst Triage</h1>
          <p className="page-subtitle">
            Search ingested CVE/package findings across Nmap, Nessus, Trivy SARIF, and vulnerability
            exports, and record analyst triage dispositions without altering raw evidence.
          </p>
        </div>
      </div>

      <ErrorBanner error={error} onDismiss={() => setError(null)} />
      {notice && (
        <div className="alert alert-success" role="status">
          <strong>✓ {notice}</strong>
        </div>
      )}

      <div className="alert alert-info" role="note">
        <strong>Evidence Boundary — Non-Exploitative Scanner Observations</strong>
        <span>
          All findings retain <code>exploitability_proven = false</code> unless corroborated by
          explicit authorised validation evidence. Triage status updates are hash-chained into the
          tenant audit log.
        </span>
      </div>

      <section className="card">
        <search>
          <form
            onSubmit={handleFilterSubmit}
            style={{
              display: "flex",
              flexWrap: "wrap",
              gap: "0.75rem",
              alignItems: "end",
            }}
          >
            <div className="field" style={{ flex: "1 1 16rem" }}>
              <label htmlFor="find-search">Search CVE, Component, Scanner, or Asset</label>
              <input
                id="find-search"
                name="search"
                type="search"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="e.g. CVE-2024 or openssl or web-dmz-01"
                autoCorrect="off"
                autoCapitalize="none"
                spellCheck={false}
              />
            </div>
            <div className="field" style={{ minWidth: "10rem" }}>
              <label htmlFor="find-sev">Severity</label>
              <select
                id="find-sev"
                name="severity"
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
              >
                <option value="">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </div>
            <div className="field" style={{ minWidth: "11rem" }}>
              <label htmlFor="find-status">Triage Status</label>
              <select
                id="find-status"
                name="status"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
              >
                <option value="">All Statuses</option>
                <option value="open">Open</option>
                <option value="mitigated">Mitigated</option>
                <option value="accepted_risk">Accepted Risk</option>
                <option value="false_positive">False Positive</option>
              </select>
            </div>
            <div className="btn-row">
              <button type="submit" className="btn btn-primary">
                Apply Filters
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => {
                  setSearch("");
                  setSeverity("");
                  setStatusFilter("");
                }}
              >
                Reset
              </button>
            </div>
          </form>
        </search>
      </section>

      <section className="card">
        <div className="table-region" tabIndex={0} role="region" aria-label="Vulnerability findings table">
          <table className="data-table">
            <caption>Vulnerability Findings ({total} matching in active tenant)</caption>
            <thead>
              <tr>
                <th scope="col">CVE &amp; Component</th>
                <th scope="col">Affected Asset</th>
                <th scope="col">Severity / CVSS</th>
                <th scope="col">Scanner</th>
                <th scope="col">Triage Status &amp; Note</th>
                <th scope="col">Exploitability</th>
                <th scope="col">Actions</th>
              </tr>
            </thead>
            <tbody>
              {findings.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ color: "var(--text-muted)" }}>
                    No matching vulnerability findings found.
                  </td>
                </tr>
              ) : (
                findings.map((f) => (
                  <tr key={f.id}>
                    <th scope="row" data-label="CVE & Component">
                      <div className="mono">{f.cve_id || "NO-CVE"}</div>
                      <div style={{ fontSize: "0.82rem", fontWeight: 400, color: "var(--text-secondary)" }}>
                        {f.affected_component || "unknown component"}
                      </div>
                    </th>
                    <td data-label="Affected Asset">
                      <div>{f.asset_display_name}</div>
                      {f.asset_canonical_key && (
                        <div className="mono" style={{ fontSize: "0.78rem", color: "var(--text-muted)" }}>
                          {f.asset_canonical_key}
                        </div>
                      )}
                    </td>
                    <td data-label="Severity / CVSS">
                      <div className="btn-row">
                        <CriticalityBadge level={f.severity} />
                        {f.cvss_score !== null && (
                          <span className="badge badge-neutral">CVSS {f.cvss_score}</span>
                        )}
                      </div>
                    </td>
                    <td data-label="Scanner">
                      <div>{f.scanner_name}</div>
                      <div style={{ fontSize: "0.78rem", color: "var(--text-muted)" }}>
                        {new Date(f.observed_at).toLocaleDateString()}
                      </div>
                    </td>
                    <td data-label="Triage Status">
                      <StatusBadge status={f.status} />
                      {f.triage_note && (
                        <div style={{ fontSize: "0.8rem", color: "var(--text-secondary)", marginTop: "0.25rem" }}>
                          {f.triage_note}
                        </div>
                      )}
                    </td>
                    <td data-label="Exploitability">
                      <span className="badge badge-medium">
                        {f.exploitability_proven ? "✓ Corroborated" : "○ Unproven"}
                      </span>
                    </td>
                    <td data-label="Actions">
                      {canTriage ? (
                        <button
                          type="button"
                          className="btn btn-secondary btn-sm"
                          aria-label={`Triage ${f.cve_id || "finding"} on ${f.asset_display_name}`}
                          onClick={() => handleOpenTriage(f)}
                        >
                          Triage
                        </button>
                      ) : (
                        <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>Read-only</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      <ModalDialog
        open={Boolean(triageTarget)}
        title={`Triage Finding: ${triageTarget?.cve_id || triageTarget?.affected_component || ""}`}
        onClose={() => setTriageTarget(null)}
      >
        <form onSubmit={handleSaveTriage} className="form-stack">
          <p style={{ margin: 0, color: "var(--text-secondary)", fontSize: "0.9rem" }}>
            Asset: <strong>{triageTarget?.asset_display_name}</strong> | Scanner:{" "}
            <code className="mono">{triageTarget?.scanner_name}</code>
          </p>

          <div className="field">
            <label htmlFor="triage-status">Disposition Status</label>
            <select
              id="triage-status"
              name="status"
              required
              value={triageStatus}
              onChange={(e) => setTriageStatus(e.target.value)}
            >
              <option value="open">Open</option>
              <option value="mitigated">Mitigated (Compensating Control / Patched)</option>
              <option value="accepted_risk">Accepted Risk (Governance Sign-Off)</option>
              <option value="false_positive">False Positive</option>
            </select>
          </div>

          <div className="field">
            <label htmlFor="triage-note">Analyst Justification / Triage Note</label>
            <span id="triage-note-hint" className="field-hint">
              Document compensating controls, ticket reference, or rationale (up to 2000 characters).
            </span>
            <textarea
              id="triage-note"
              name="triage_note"
              aria-describedby="triage-note-hint"
              maxLength={2000}
              value={triageNote}
              onChange={(e) => setTriageNote(e.target.value)}
              placeholder="e.g. Verified OpenSSL patched via hotfix CHG-4921; awaits next offline scan."
            />
          </div>

          <div className="btn-row">
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? "Saving Disposition..." : "Save Triage Decision"}
            </button>
            <button type="button" className="btn btn-secondary" onClick={() => setTriageTarget(null)}>
              Cancel
            </button>
          </div>
        </form>
      </ModalDialog>
    </div>
  );
};
