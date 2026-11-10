import React, { useCallback, useEffect, useState } from "react";
import { useAuth } from "../app/AuthContext";
import { ErrorBanner, StatusBadge } from "../components/Badges";
import { apiDownloadBlob, apiRequest } from "../lib/api";
import type { AuditEventItem } from "../types/api";

export const AuditLogPage: React.FC = () => {
  const { hasRole } = useAuth();
  const canExport = hasRole("tenant_admin", "auditor");

  const [events, setEvents] = useState<AuditEventItem[]>([]);
  const [total, setTotal] = useState(0);
  const [actionFilter, setActionFilter] = useState("");
  const [outcomeFilter, setOutcomeFilter] = useState("");
  const [error, setError] = useState<unknown>(null);

  const loadEvents = useCallback(async () => {
    try {
      const qs = new URLSearchParams({ limit: "100" });
      if (actionFilter.trim()) qs.set("action", actionFilter.trim());
      if (outcomeFilter) qs.set("outcome", outcomeFilter);
      const res = await apiRequest<{ items: AuditEventItem[]; total: number }>(
        `/audit?${qs.toString()}`
      );
      setEvents(res.items);
      setTotal(res.total);
    } catch (err) {
      setError(err);
    }
  }, [actionFilter, outcomeFilter]);

  useEffect(() => {
    loadEvents();
  }, [loadEvents]);

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Immutable Audit Log (Hash-Chained)</h1>
          <p className="page-subtitle">
            PostgreSQL trigger-enforced append-only log with SHA-256 tamper-evident hash chaining.
          </p>
        </div>
        {canExport && (
          <div className="btn-row">
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() =>
                apiDownloadBlob("/audit/export?format=json", "sentinelgraph-audit.json").catch(
                  setError
                )
              }
            >
              Export JSON
            </button>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() =>
                apiDownloadBlob("/audit/export?format=csv", "sentinelgraph-audit.csv").catch(
                  setError
                )
              }
            >
              Export CSV
            </button>
          </div>
        )}
      </div>

      <ErrorBanner error={error} onDismiss={() => setError(null)} />

      <div
        className="card"
        style={{ marginBlockEnd: "1rem", display: "flex", flexWrap: "wrap", gap: "0.75rem" }}
      >
        <div className="field" style={{ flex: "1 1 14rem" }}>
          <label htmlFor="audit-action">Exact Action Filter</label>
          <input
            id="audit-action"
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            placeholder="e.g. import.commit or auth.login"
          />
        </div>
        <div className="field" style={{ minWidth: "10rem" }}>
          <label htmlFor="audit-outcome">Outcome</label>
          <select
            id="audit-outcome"
            value={outcomeFilter}
            onChange={(e) => setOutcomeFilter(e.target.value)}
          >
            <option value="">All Outcomes</option>
            <option value="success">Success</option>
            <option value="denied">Denied</option>
          </select>
        </div>
      </div>

      <div className="table-region" tabIndex={0} role="region" aria-label="Audit events table">
        <table className="data-table">
          <caption>Audit Events ({total} recorded)</caption>
          <thead>
            <tr>
              <th scope="col">Timestamp</th>
              <th scope="col">Actor</th>
              <th scope="col">Action</th>
              <th scope="col">Target Object</th>
              <th scope="col">Outcome</th>
              <th scope="col">Event Hash Chain</th>
            </tr>
          </thead>
          <tbody>
            {events.map((ev) => (
              <tr key={ev.id}>
                <th scope="row" data-label="Timestamp" className="mono">
                  {ev.created_at}
                </th>
                <td data-label="Actor">{ev.actor_email || "system"}</td>
                <td data-label="Action" className="mono">
                  {ev.action}
                </td>
                <td data-label="Target Object" className="mono">
                  {ev.object_type}:{ev.object_id.slice(0, 12)}
                </td>
                <td data-label="Outcome">
                  <StatusBadge status={ev.outcome === "success" ? "committed" : "rejected"} />
                </td>
                <td data-label="Event Hash Chain" className="mono">
                  <div>hash: {ev.event_hash.slice(0, 16)}...</div>
                  <div>prev: {ev.prev_hash ? `${ev.prev_hash.slice(0, 16)}...` : "GENESIS"}</div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
