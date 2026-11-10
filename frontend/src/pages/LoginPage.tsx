import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../app/AuthContext";
import { ErrorBanner } from "../components/Badges";
import { apiRequest } from "../lib/api";
import type { OidcConfigResponse, OidcLoginStartResponse } from "../types/api";

const DEMO_ACCOUNTS = [
  { email: "admin@acme.local", role: "tenant_admin", label: "Acme Tenant Admin" },
  { email: "assessor@acme.local", role: "assessor", label: "Acme Lead Assessor" },
  { email: "analyst@acme.local", role: "analyst", label: "Acme Security Analyst" },
  { email: "remediation@acme.local", role: "remediation_owner", label: "Acme Remediation Owner" },
  { email: "auditor@acme.local", role: "auditor", label: "Acme Auditor" },
  { email: "viewer@acme.local", role: "read_only", label: "Acme Read-Only Viewer" },
  { email: "admin@beta.local", role: "tenant_admin (beta-isolated)", label: "Beta Isolated Admin" },
];

export const LoginPage: React.FC = () => {
  const { login, isAuthenticated } = useAuth();
  const navigate = useNavigate();

  const [email, setEmail] = useState("admin@acme.local");
  const [password, setPassword] = useState("");
  const [tenantSlug, setTenantSlug] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [oidcConfig, setOidcConfig] = useState<OidcConfigResponse | null>(null);

  useEffect(() => {
    if (isAuthenticated) {
      navigate("/overview", { replace: true });
    }
  }, [isAuthenticated, navigate]);

  useEffect(() => {
    apiRequest<OidcConfigResponse>("/auth/oidc/config")
      .then(setOidcConfig)
      .catch(() => setOidcConfig(null));
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(email.trim(), password, tenantSlug.trim() || undefined);
      navigate("/overview", { replace: true });
    } catch (err) {
      setError(err);
    } finally {
      setSubmitting(false);
    }
  };

  const handleDemoFill = async (demoEmail: string) => {
    setEmail(demoEmail);
    setPassword("SentinelDemo!2026");
    setError(null);
    setSubmitting(true);
    try {
      await login(demoEmail, "SentinelDemo!2026");
      navigate("/overview", { replace: true });
    } catch (err) {
      setError(err);
    } finally {
      setSubmitting(false);
    }
  };

  const handleOidcRedirect = async () => {
    setError(null);
    setSubmitting(true);
    try {
      const slug = tenantSlug.trim();
      if (slug) {
        sessionStorage.setItem("sentinelgraph.oidc_tenant_slug", slug);
      } else {
        sessionStorage.removeItem("sentinelgraph.oidc_tenant_slug");
      }
      const qs = slug ? `?tenant_slug=${encodeURIComponent(slug)}` : "";
      const res = await apiRequest<OidcLoginStartResponse>(`/auth/oidc/login${qs}`);
      window.location.assign(res.authorization_url);
    } catch (err) {
      setError(err);
      setSubmitting(false);
    }
  };

  return (
    <main className="login-shell" id="main-content" tabIndex={-1}>
      <div className="login-card">
        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginBlockEnd: "1rem" }}>
          <span className="brand-mark" aria-hidden="true">
            SG
          </span>
          <div>
            <h1 style={{ margin: 0, fontSize: "1.45rem" }}>SentinelGraph Sign In</h1>
            <p style={{ margin: 0, color: "var(--text-secondary)", fontSize: "0.9rem" }}>
              Authorised Enterprise Attack-Path Intelligence Engine
            </p>
          </div>
        </div>

        <div className="alert alert-info">
          <strong>Safety &amp; Authorisation Boundary</strong>
          <span>
            SentinelGraph analyses customer-provided authorised telemetry only. No autonomous
            exploitation or unapproved network scanning is performed.
          </span>
        </div>

        <ErrorBanner error={error} onDismiss={() => setError(null)} />

        <form onSubmit={handleSubmit} className="form-stack">
          <div className="field">
            <label htmlFor="login-email">
              Work Email <span aria-hidden="true">*</span>
            </label>
            <span id="login-email-hint" className="field-hint">
              Format: analyst@organisation.example
            </span>
            <input
              id="login-email"
              name="email"
              type="email"
              required
              autoComplete="username"
              autoCorrect="off"
              autoCapitalize="none"
              spellCheck={false}
              aria-describedby="login-email-hint"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
            <div className="field-error-msg">
              <span role="img" aria-label="Error">✕</span> Enter a valid work email address.
            </div>
          </div>

          <div className="field">
            <label htmlFor="login-password">
              Password <span aria-hidden="true">*</span>
            </label>
            <div style={{ display: "flex", gap: "0.5rem" }}>
              <input
                id="login-password"
                name="password"
                type={showPassword ? "text" : "password"}
                required
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                style={{ flex: 1 }}
              />
              <button
                type="button"
                className="btn btn-secondary"
                aria-pressed={showPassword}
                onClick={() => setShowPassword((s) => !s)}
              >
                {showPassword ? "Hide" : "Show"}
              </button>
            </div>
          </div>

          <div className="field">
            <label htmlFor="login-tenant">Tenant Slug (optional)</label>
            <input
              id="login-tenant"
              name="tenant_slug"
              type="text"
              placeholder="e.g. acme-demo"
              autoCorrect="off"
              autoCapitalize="none"
              spellCheck={false}
              value={tenantSlug}
              onChange={(e) => setTenantSlug(e.target.value)}
            />
          </div>

          <button type="submit" className="btn btn-primary" disabled={submitting}>
            {submitting ? "Signing in..." : "Sign In"}
          </button>
        </form>

        {oidcConfig && (
          <section style={{ marginBlockStart: "1.25rem", borderBlockStart: "1px solid var(--border-subtle)", paddingBlockStart: "1rem" }}>
            <div style={{ fontSize: "0.85rem", color: "var(--text-secondary)", marginBlockEnd: "0.6rem" }}>
              <strong>Enterprise SSO (OIDC + PKCE):</strong>{" "}
              {oidcConfig.oidc_enabled
                ? `Configured (${oidcConfig.issuer_url})`
                : "Available when OIDC_ISSUER_URL is configured (not configured in local dev)"}
            </div>

            {oidcConfig.oidc_enabled && (
              <div style={{ marginBlockEnd: "0.9rem" }}>
                <button
                  type="button"
                  className="btn btn-secondary"
                  disabled={submitting}
                  onClick={handleOidcRedirect}
                >
                  Sign In with Enterprise SSO (OIDC)
                </button>
              </div>
            )}

            {!oidcConfig.local_dev_auth_enabled && (
              <div className="alert alert-warning" role="note">
                <strong>Local password login disabled in production mode</strong>
                <span>Use Enterprise SSO (OIDC) to authenticate into your tenant.</span>
              </div>
            )}

            {oidcConfig.local_dev_auth_enabled && (
              <div>
                <h2 style={{ fontSize: "0.95rem", margin: "0 0 0.5rem" }}>
                  Local Development Demo Accounts (Synthetic Data Only)
                </h2>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.45rem" }}>
                  {DEMO_ACCOUNTS.map((acc) => (
                    <button
                      key={acc.email}
                      type="button"
                      className="btn btn-secondary btn-sm"
                      style={{ justifyContent: "flex-start", textAlign: "start" }}
                      disabled={submitting}
                      onClick={() => handleDemoFill(acc.email)}
                    >
                      <span>
                        <strong>{acc.role}</strong>
                        <br />
                        <span className="mono">{acc.email}</span>
                      </span>
                    </button>
                  ))}
                </div>
              </div>
            )}
          </section>
        )}
      </div>
    </main>
  );
};
