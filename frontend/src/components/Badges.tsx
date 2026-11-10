import React from "react";
import { ApiClientError } from "../lib/api";
import type { FactKind } from "../types/api";

export const CriticalityBadge: React.FC<{ level: string }> = ({ level }) => {
  const norm = level.toLowerCase();
  if (norm === "critical") {
    return <span className="badge badge-critical">▲ CRITICAL</span>;
  }
  if (norm === "high") {
    return <span className="badge badge-high">◆ HIGH</span>;
  }
  if (norm === "medium") {
    return <span className="badge badge-medium">● MEDIUM</span>;
  }
  return <span className="badge badge-low">○ {level.toUpperCase()}</span>;
};

export const ProvenanceBadge: React.FC<{ factKind: FactKind | string; suppressed?: boolean }> = ({
  factKind,
  suppressed = false,
}) => {
  if (suppressed) {
    return <span className="badge badge-danger badge-critical">⊘ SUPPRESSED</span>;
  }
  if (factKind === "observed_fact") {
    return <span className="badge badge-success">✓ Observed Fact</span>;
  }
  if (factKind === "inferred_relationship") {
    return <span className="badge badge-medium">~ Inferred Edge</span>;
  }
  return <span className="badge badge-info">✎ Analyst Assertion</span>;
};

export const StatusBadge: React.FC<{ status: string }> = ({ status }) => {
  const norm = status.toLowerCase();
  if (["committed", "approved", "graph_built", "succeeded", "simulated", "active"].includes(norm)) {
    return <span className="badge badge-success">● {status}</span>;
  }
  if (["rejected", "failed", "dead_letter", "cancelled"].includes(norm)) {
    return <span className="badge badge-critical">✕ {status}</span>;
  }
  if (["staged", "draft", "queued", "running", "partially_valid"].includes(norm)) {
    return <span className="badge badge-medium">◐ {status}</span>;
  }
  return <span className="badge badge-neutral">• {status}</span>;
};

export const ErrorBanner: React.FC<{ error: unknown; onDismiss?: () => void }> = ({
  error,
  onDismiss,
}) => {
  if (!error) return null;
  if (error instanceof ApiClientError) {
    return (
      <div className="alert alert-danger" role="alert">
        <div style={{ display: "flex", justifyContent: "space-between", gap: "0.75rem" }}>
          <strong>
            ⚠ Error [{error.code}] (HTTP {error.status}): {error.message}
          </strong>
          {onDismiss && (
            <button type="button" className="btn btn-secondary btn-sm" onClick={onDismiss}>
              Dismiss
            </button>
          )}
        </div>
        <div className="mono">request_id: {error.requestId}</div>
        {error.fieldErrors.length > 0 && (
          <ul style={{ margin: "0.25rem 0 0 1.25rem", padding: 0 }}>
            {error.fieldErrors.map((fe, idx) => (
              <li key={idx}>
                <code>{fe.field}</code>: {fe.message}
              </li>
            ))}
          </ul>
        )}
      </div>
    );
  }
  const msg = error instanceof Error ? error.message : String(error);
  return (
    <div className="alert alert-danger" role="alert">
      <strong>⚠ Error: {msg}</strong>
    </div>
  );
};
