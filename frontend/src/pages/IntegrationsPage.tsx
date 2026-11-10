import React, { useCallback, useEffect, useState } from "react";
import { useAuth } from "../app/AuthContext";
import { ErrorBanner } from "../components/Badges";
import { apiRequest } from "../lib/api";
import type { IntegrationsResponse } from "../types/api";

export const IntegrationsPage: React.FC = () => {
  const { hasRole } = useAuth();
  const isAdmin = hasRole("tenant_admin");

  const [data, setData] = useState<IntegrationsResponse | null>(null);
  const [name, setName] = useState("");
  const [sourceType, setSourceType] = useState("nmap_xml");
  const [secretToken, setSecretToken] = useState("");
  const [notice, setNotice] = useState("");
  const [error, setError] = useState<unknown>(null);

  const loadIntegrations = useCallback(async () => {
    try {
      const res = await apiRequest<IntegrationsResponse>("/integrations");
      setData(res);
    } catch (err) {
      setError(err);
    }
  }, []);

  useEffect(() => {
    loadIntegrations();
  }, [loadIntegrations]);

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      await apiRequest("/integrations", {
        method: "POST",
        body: {
          name: name.trim(),
          source_type: sourceType,
          secret_token: secretToken.trim() || null,
          config_metadata: { ingest_mode: "file_upload_only" },
        },
      });
      setName("");
      setSecretToken("");
      setNotice("Connector metadata saved (secrets encrypted at rest and write-only).");
      await loadIntegrations();
    } catch (err) {
      setError(err);
    }
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Connectors &amp; Integration Boundaries</h1>
          <p className="page-subtitle">
            MVP uses file-based offline ingestion (Nmap XML, Topology JSON, Identity JSON,
            Vulnerability JSON). Direct cloud connectors are scoped strictly to Phase 2.
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
        <strong>MVP Architecture Boundary — No Unapproved Active Scanning or Cloud Polling</strong>
        <span>
          Nmap XML files are parsed locally from customer-approved exports; SentinelGraph never runs{" "}
          <code>nmap</code> from the API/worker or polls external cloud APIs in MVP.
        </span>
      </div>

      {isAdmin && (
        <section className="card">
          <h2 className="card-title">Register MVP File Data Source</h2>
          <form onSubmit={handleRegister} className="form-stack">
            <div className="grid-2">
              <div className="field">
                <label htmlFor="int-name">Data Source Name</label>
                <input
                  id="int-name"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Corp Firewall Weekly Export"
                />
              </div>
              <div className="field">
                <label htmlFor="int-type">MVP Source Type</label>
                <select
                  id="int-type"
                  value={sourceType}
                  onChange={(e) => setSourceType(e.target.value)}
                >
                  <option value="nmap_xml">nmap_xml</option>
                  <option value="nessus_xml">nessus_xml</option>
                  <option value="sarif_json">sarif_json</option>
                  <option value="bloodhound_json">bloodhound_json</option>
                  <option value="aws_iam_export_json">aws_iam_export_json</option>
                  <option value="network_topology_json">network_topology_json</option>
                  <option value="network_topology_csv">network_topology_csv</option>
                  <option value="identity_json">identity_json</option>
                  <option value="vulnerability_json">vulnerability_json</option>
                  <option value="relationship_json">relationship_json</option>
                </select>
              </div>
            </div>
            <div className="field">
              <label htmlFor="int-sec">Optional Signature Verification Secret (encrypted via MultiFernet)</label>
              <input
                id="int-sec"
                type="password"
                value={secretToken}
                onChange={(e) => setSecretToken(e.target.value)}
                placeholder="Write-only; never returned after save"
              />
            </div>
            <div>
              <button type="submit" className="btn btn-primary">
                Save Connector Metadata
              </button>
            </div>
          </form>
        </section>
      )}

      {data && (
        <>
          <section className="card">
            <h2 className="card-title">Configured Tenant Sources ({data.configured_sources.length})</h2>
            {data.configured_sources.length === 0 ? (
              <p style={{ color: "var(--text-secondary)", margin: 0 }}>
                No custom sources registered yet (use Imports page for direct file uploads).
              </p>
            ) : (
              <ul>
                {data.configured_sources.map((src) => (
                  <li key={src.id}>
                    <strong>{src.name}</strong> (<code className="mono">{src.source_type}</code>) —{" "}
                    {src.has_secret_configured ? "Encrypted secret stored (masked)" : "No secret"}
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="card">
            <h2 className="card-title">Phase 2 Read-Only Cloud &amp; Directory Connectors (Disabled in MVP)</h2>
            <div className="grid-2">
              {data.phase2_roadmap_connectors.map((c) => (
                <article
                  key={c.source_type}
                  style={{
                    border: "1px solid var(--border-subtle)",
                    borderRadius: "0.5rem",
                    padding: "1rem",
                    background: "var(--bg-subtle)",
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", gap: "0.5rem" }}>
                    <strong>{c.display_name}</strong>
                    <span className="badge badge-neutral">⊘ {c.phase}</span>
                  </div>
                  <div style={{ fontSize: "0.85rem", marginBlockStart: "0.4rem" }}>
                    Auth Model: <strong>{c.required_auth_model}</strong>
                  </div>
                  <div style={{ fontSize: "0.85rem" }}>
                    Scopes: <code className="mono">{c.read_only_scopes.join(", ")}</code>
                  </div>
                  <div style={{ fontSize: "0.82rem", color: "var(--text-secondary)", marginTop: "0.3rem" }}>
                    {c.threat_notes}
                  </div>
                </article>
              ))}
            </div>
          </section>
        </>
      )}
    </div>
  );
};
