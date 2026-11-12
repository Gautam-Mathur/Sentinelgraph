import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ErrorBanner, ProvenanceBadge } from "../components/Badges";
import { apiRequest } from "../lib/api";
import type { AttackPathItem, DashboardOverview } from "../types/api";

export const OverviewPage: React.FC = () => {
  const [overview, setOverview] = useState<DashboardOverview | null>(null);
  const [paths, setPaths] = useState<AttackPathItem[]>([]);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    Promise.all([
      apiRequest<DashboardOverview>("/dashboard"),
      apiRequest<{ items: AttackPathItem[] }>("/paths?limit=5"),
    ])
      .then(([dash, pathRes]) => {
        setOverview(dash);
        setPaths(pathRes.items);
      })
      .catch(setError);
  }, []);

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Overview Dashboard</h1>
          <p className="page-subtitle">
            Tenant-scoped exposure posture, source coverage honesty, and prioritised attack paths.
          </p>
        </div>
        <div className="btn-row">
          <Link to="/imports" className="btn btn-primary">
            + Stage Evidence Import
          </Link>
          <Link to="/paths" className="btn btn-secondary">
            Explore Attack Paths
          </Link>
        </div>
      </div>

      <ErrorBanner error={error} />

      {overview && (
        <>
          <div className="kpi-grid">
            <Link to="/assets" className="kpi-card">
              <span className="kpi-label">Assets Observed</span>
              <span className="kpi-value">{overview.kpis.assets_observed}</span>
              <span className="kpi-hint">View inventory →</span>
            </Link>
            <Link to="/assets?criticality=critical" className="kpi-card">
              <span className="kpi-label">Critical Assets</span>
              <span className="kpi-value">{overview.kpis.critical_assets}</span>
              <span className="kpi-hint">Filter critical assets →</span>
            </Link>
            <Link to="/assets" className="kpi-card">
              <span className="kpi-label">Exposed Services</span>
              <span className="kpi-value">{overview.kpis.exposed_services}</span>
              <span className="kpi-hint">Inspect open ports →</span>
            </Link>
            <Link to="/paths" className="kpi-card">
              <span className="kpi-label">High-Confidence Paths</span>
              <span className="kpi-value">{overview.kpis.high_confidence_paths}</span>
              <span className="kpi-hint">Confidence ≥ 70% →</span>
            </Link>
            <Link to="/paths" className="kpi-card">
              <span className="kpi-label">Paths to Critical Assets</span>
              <span className="kpi-value">{overview.kpis.paths_to_critical_assets}</span>
              <span className="kpi-hint">Prioritise remediation →</span>
            </Link>
            <Link to="/relationships" className="kpi-card">
              <span className="kpi-label">Stale Observations</span>
              <span className="kpi-value">{overview.kpis.stale_observations}</span>
              <span className="kpi-hint">&gt; 30 days without refresh →</span>
            </Link>
            <Link to="/imports" className="kpi-card">
              <span className="kpi-label">Unreviewed Imports</span>
              <span className="kpi-value">{overview.kpis.unreviewed_imports}</span>
              <span className="kpi-hint">Review staging queue →</span>
            </Link>
          </div>

          <div
            className={`alert ${
              overview.freshness_and_coverage.missing_recommended_sources.length > 0
                ? "alert-warning"
                : "alert-info"
            }`}
            role="status"
          >
            <strong>
              Source Coverage &amp; Freshness ({overview.freshness_and_coverage.coverage_status})
            </strong>
            <span>{overview.freshness_and_coverage.completeness_notice}</span>
            <span>
              Latest committed observation:{" "}
              {overview.freshness_and_coverage.latest_observation_at || "None committed yet"} |
              Missing recommended sources:{" "}
              {overview.freshness_and_coverage.missing_recommended_sources.length > 0
                ? overview.freshness_and_coverage.missing_recommended_sources.join(", ")
                : "None (all core MVP telemetry formats observed)"}
            </span>
          </div>

          <section className="card">
            <h2 className="card-title">Top Prioritised Attack Paths (Plausible Chains Only)</h2>
            <p style={{ marginBlockStart: 0, color: "var(--text-secondary)", fontSize: "0.9rem" }}>
              Scores are weighted 0–100 structural remediation triage priorities under Scoring
              v2.0.0 — NOT statistical probabilities of compromise. Evidence confidence and
              missing-data penalties are reported separately.
            </p>

            {paths.length === 0 ? (
              <p>No paths generated yet. Build an assessment graph and generate candidate paths.</p>
            ) : (
              <div className="table-region" tabIndex={0} role="region" aria-label="Top attack paths">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th scope="col">Path Title</th>
                      <th scope="col">Priority Score</th>
                      <th scope="col">Evidence Conf.</th>
                      <th scope="col">Hops</th>
                      <th scope="col">Scoring Version</th>
                      <th scope="col">Inspect</th>
                    </tr>
                  </thead>
                  <tbody>
                    {paths.map((p) => (
                      <tr key={p.id}>
                        <th scope="row" data-label="Path Title">
                          {p.title}
                        </th>
                        <td data-label="Priority Score">
                          <span className="badge badge-critical">{p.priority_score} / 100</span>
                        </td>
                        <td data-label="Evidence Conf.">
                          {Math.round(p.evidence_confidence * 100)}%
                        </td>
                        <td data-label="Hops">{p.hop_count}</td>
                        <td data-label="Scoring Version" className="mono">
                          {p.scoring_version}
                        </td>
                        <td data-label="Inspect">
                          <Link to={`/paths/${p.id}`} className="btn btn-secondary btn-sm">
                            Explain Path
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <section className="card">
            <h2 className="card-title">Committed Telemetry Sources</h2>
            <div style={{ display: "flex", flexWrap: "wrap", gap: "0.6rem" }}>
              {overview.freshness_and_coverage.observed_source_formats.map((src) => (
                <div
                  key={src.source_format}
                  style={{
                    border: "1px solid var(--border-subtle)",
                    borderRadius: "0.375rem",
                    padding: "0.6rem 0.85rem",
                    background: "var(--bg-subtle)",
                  }}
                >
                  <div className="mono" style={{ fontWeight: 700 }}>
                    {src.source_format}
                  </div>
                  <div style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
                    Last committed: {src.last_committed_at || "N/A"}
                  </div>
                  <ProvenanceBadge factKind="observed_fact" />
                </div>
              ))}
            </div>
          </section>
        </>
      )}
    </div>
  );
};
