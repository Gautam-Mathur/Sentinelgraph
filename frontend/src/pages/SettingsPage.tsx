import React, { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../app/AuthContext";
import { ErrorBanner, StatusBadge } from "../components/Badges";
import { apiRequest } from "../lib/api";
import type { JobItem, MemberItem, RetentionResponse, RoleName, WebhookItem } from "../types/api";

const ALL_ROLES: RoleName[] = [
  "tenant_admin",
  "assessor",
  "analyst",
  "remediation_owner",
  "auditor",
  "read_only",
];

const WEBHOOK_EVENTS = [
  { id: "attack_path.high_risk", label: "High-risk attack paths generated" },
  { id: "finding.critical", label: "Critical vulnerability finding ingested" },
  { id: "import.committed", label: "Staged import committed" },
  { id: "test.ping", label: "Manual test ping" },
];

export const SettingsPage: React.FC = () => {
  const { activeTenant, user, hasRole, refreshMe, switchTenant } = useAuth();
  const isAdmin = hasRole("tenant_admin");

  const [members, setMembers] = useState<MemberItem[]>([]);
  const [retention, setRetention] = useState<RetentionResponse | null>(null);
  const [webhooks, setWebhooks] = useState<WebhookItem[]>([]);

  const [newTenantName, setNewTenantName] = useState("");
  const [newTenantSlug, setNewTenantSlug] = useState("");
  const [dataClass, setDataClass] = useState("imports");
  const [retentionDays, setRetentionDays] = useState("90");
  const [enforceDryRun, setEnforceDryRun] = useState(true);
  const [enforceResult, setEnforceResult] = useState<Record<string, unknown> | null>(null);
  const [exportBundle, setExportBundle] = useState<Record<string, unknown> | null>(null);

  // Member invite form
  const [invEmail, setInvEmail] = useState("");
  const [invName, setInvName] = useState("");
  const [invRole, setInvRole] = useState<RoleName>("analyst");
  const [invProvider, setInvProvider] = useState<"oidc" | "local">("oidc");
  const [invPassword, setInvPassword] = useState("");

  // Password rotation form
  const [curPwd, setCurPwd] = useState("");
  const [newPwd, setNewPwd] = useState("");
  const [confirmPwd, setConfirmPwd] = useState("");
  const [pwdMismatchErr, setPwdMismatchErr] = useState("");

  // Webhook creation form
  const [whName, setWhName] = useState("");
  const [whUrl, setWhUrl] = useState("");
  const [whMinScore, setWhMinScore] = useState("70");
  const [whSecret, setWhSecret] = useState("");
  const [whEvents, setWhEvents] = useState<string[]>(["attack_path.high_risk"]);

  const [notice, setNotice] = useState("");
  const [error, setError] = useState<unknown>(null);

  const loadGovernance = useCallback(async () => {
    try {
      const retRes = await apiRequest<RetentionResponse>("/retention");
      setRetention(retRes);
      if (isAdmin) {
        const [memRes, whRes] = await Promise.all([
          apiRequest<{ items: MemberItem[] }>("/tenants/members"),
          apiRequest<{ items: WebhookItem[] }>("/webhooks"),
        ]);
        setMembers(memRes.items);
        setWebhooks(whRes.items);
      }
    } catch (err) {
      setError(err);
    }
  }, [isAdmin]);

  useEffect(() => {
    loadGovernance();
  }, [loadGovernance]);

  const handleCreateTenant = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      const created = await apiRequest<{ id: string; slug: string; name: string }>("/tenants", {
        method: "POST",
        body: {
          name: newTenantName.trim(),
          slug: newTenantSlug.trim().toLowerCase(),
          is_demo: false,
        },
      });
      await switchTenant(created.id);
      await refreshMe();
      setNewTenantName("");
      setNewTenantSlug("");
      setNotice(`Created and switched to tenant "${created.name}".`);
    } catch (err) {
      setError(err);
    }
  };

  const handleInviteMember = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      const created = await apiRequest<MemberItem>("/tenants/members", {
        method: "POST",
        body: {
          email: invEmail.trim().toLowerCase(),
          display_name: invName.trim(),
          role: invRole,
          auth_provider: invProvider,
          password: invProvider === "local" ? invPassword : null,
        },
      });
      setInvEmail("");
      setInvName("");
      setInvPassword("");
      setNotice(`Provisioned tenant member ${created.email} with role ${created.role}.`);
      await loadGovernance();
    } catch (err) {
      setError(err);
    }
  };

  const handleRoleChange = async (membershipId: string, newRole: RoleName) => {
    setError(null);
    try {
      await apiRequest(`/tenants/members/${membershipId}`, {
        method: "PATCH",
        body: { role: newRole },
      });
      setNotice(`Updated member role to ${newRole} and recorded audit event.`);
      await loadGovernance();
    } catch (err) {
      setError(err);
    }
  };

  const handleToggleMemberStatus = async (m: MemberItem) => {
    setError(null);
    const nextStatus = m.status === "active" ? "suspended" : "active";
    try {
      await apiRequest(`/tenants/members/${m.membership_id}`, {
        method: "PATCH",
        body: { status: nextStatus },
      });
      setNotice(`Member ${m.email} status updated to ${nextStatus}.`);
      await loadGovernance();
    } catch (err) {
      setError(err);
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setPwdMismatchErr("");
    if (newPwd !== confirmPwd) {
      setPwdMismatchErr("New password and confirmation do not match.");
      return;
    }
    try {
      await apiRequest("/auth/change-password", {
        method: "POST",
        body: { current_password: curPwd, new_password: newPwd },
      });
      setCurPwd("");
      setNewPwd("");
      setConfirmPwd("");
      setNotice("Password rotated successfully.");
    } catch (err) {
      setError(err);
    }
  };

  const handleUpsertRetention = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      await apiRequest("/retention/policies", {
        method: "PUT",
        body: {
          data_class: dataClass,
          retention_days: Number(retentionDays),
          lawful_basis: "authorised_security_assessment",
        },
      });
      setNotice(`Retention policy saved for ${dataClass}.`);
      await loadGovernance();
    } catch (err) {
      setError(err);
    }
  };

  const handleExportBundle = async () => {
    setError(null);
    try {
      const bundle = await apiRequest<Record<string, unknown>>("/retention/export", {
        method: "POST",
      });
      setExportBundle(bundle);
      setNotice("Generated tenant data export summary.");
    } catch (err) {
      setError(err);
    }
  };

  const handleDeletionRequest = async () => {
    setError(null);
    try {
      await apiRequest("/retention/delete", {
        method: "POST",
        body: { data_class: dataClass },
      });
      setNotice(`Executed deletion request for data class "${dataClass}".`);
      await loadGovernance();
    } catch (err) {
      setError(err);
    }
  };

  const handleEnforceRetention = async () => {
    setError(null);
    try {
      const res = await apiRequest<Record<string, unknown>>("/retention/enforce", {
        method: "POST",
        body: { dry_run: enforceDryRun },
      });
      setEnforceResult(res);
      setNotice(
        enforceDryRun
          ? "Completed retention enforcement dry-run."
          : "Executed retention enforcement across configured policies."
      );
      await loadGovernance();
    } catch (err) {
      setError(err);
    }
  };

  const handleQueueRetentionJob = async () => {
    setError(null);
    try {
      const job = await apiRequest<JobItem>("/jobs", {
        method: "POST",
        body: { job_type: "enforce_retention", payload: { dry_run: enforceDryRun } },
      });
      setNotice(`Queued worker job enforce_retention (${job.id.slice(0, 8)}): ${job.status}.`);
    } catch (err) {
      setError(err);
    }
  };

  const toggleWebhookEvent = (evId: string) => {
    setWhEvents((prev) =>
      prev.includes(evId) ? prev.filter((item) => item !== evId) : [...prev, evId]
    );
  };

  const handleCreateWebhook = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      await apiRequest("/webhooks", {
        method: "POST",
        body: {
          name: whName.trim(),
          target_url: whUrl.trim(),
          event_types: whEvents.length > 0 ? whEvents : ["attack_path.high_risk"],
          min_priority_score: Number(whMinScore),
          signing_secret: whSecret.trim() || null,
          enabled: true,
        },
      });
      setWhName("");
      setWhUrl("");
      setWhSecret("");
      setNotice("Created outbound HMAC-signed webhook subscription.");
      await loadGovernance();
    } catch (err) {
      setError(err);
    }
  };

  const handleTestWebhook = async (webhookId: string) => {
    setError(null);
    try {
      const res = await apiRequest<{ delivered: boolean; status_code: number | null; error: string | null }>(
        `/webhooks/${webhookId}/test`,
        { method: "POST" }
      );
      setNotice(
        res.delivered
          ? `Webhook test ping delivered (HTTP ${res.status_code}).`
          : `Webhook test ping failed (${res.error || `HTTP ${res.status_code}`}).`
      );
      await loadGovernance();
    } catch (err) {
      setError(err);
    }
  };

  const handleDeleteWebhook = async (webhookId: string) => {
    setError(null);
    try {
      await apiRequest(`/webhooks/${webhookId}`, { method: "DELETE" });
      setNotice("Deleted webhook subscription.");
      await loadGovernance();
    } catch (err) {
      setError(err);
    }
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Settings, Tenant Isolation &amp; Privacy Governance</h1>
          <p className="page-subtitle">
            Manage isolated organisation tenants, member onboarding, RBAC lifecycle, retention
            enforcement, password security, and signed webhook notifications.
          </p>
        </div>
      </div>

      <ErrorBanner error={error} onDismiss={() => setError(null)} />
      {notice && (
        <div className="alert alert-success" role="status">
          <strong>✓ {notice}</strong>{" "}
          <Link to="/jobs" style={{ fontWeight: 600 }}>
            Jobs Queue →
          </Link>
        </div>
      )}

      <div className="grid-2">
        <section className="card">
          <h2 className="card-title">Create Isolated Tenant</h2>
          <form onSubmit={handleCreateTenant} className="form-stack">
            <div className="field">
              <label htmlFor="ten-name">Organisation Name</label>
              <input
                id="ten-name"
                required
                minLength={2}
                value={newTenantName}
                onChange={(e) => setNewTenantName(e.target.value)}
                placeholder="e.g. Gamma Security Division"
              />
            </div>
            <div className="field">
              <label htmlFor="ten-slug">Slug (lowercase alphanumeric / hyphen)</label>
              <input
                id="ten-slug"
                required
                minLength={3}
                value={newTenantSlug}
                onChange={(e) => setNewTenantSlug(e.target.value)}
                placeholder="e.g. gamma-sec"
                autoCorrect="off"
                autoCapitalize="none"
                spellCheck={false}
              />
            </div>
            <button type="submit" className="btn btn-primary">
              Create &amp; Switch Tenant
            </button>
          </form>
        </section>

        <section className="card">
          <h2 className="card-title">Data Retention &amp; GDPR Governance</h2>
          {isAdmin ? (
            <form onSubmit={handleUpsertRetention} className="form-stack">
              <div className="grid-2">
                <div className="field">
                  <label htmlFor="ret-class">Data Class</label>
                  <select
                    id="ret-class"
                    value={dataClass}
                    onChange={(e) => setDataClass(e.target.value)}
                  >
                    <option value="imports">imports</option>
                    <option value="observations">observations</option>
                    <option value="reports">reports</option>
                    <option value="identities">identities</option>
                    <option value="assessments">assessments</option>
                  </select>
                </div>
                <div className="field">
                  <label htmlFor="ret-days">Retention Days (7–3650)</label>
                  <input
                    id="ret-days"
                    type="number"
                    min={7}
                    max={3650}
                    value={retentionDays}
                    onChange={(e) => setRetentionDays(e.target.value)}
                  />
                </div>
              </div>
              <div className="checkbox-row">
                <input
                  id="ret-dryrun"
                  type="checkbox"
                  checked={enforceDryRun}
                  onChange={(e) => setEnforceDryRun(e.target.checked)}
                />
                <label htmlFor="ret-dryrun">
                  Dry run when enforcing retention schedules
                </label>
              </div>
              <div className="btn-row">
                <button type="submit" className="btn btn-primary">
                  Save Policy
                </button>
                <button type="button" className="btn btn-secondary" onClick={handleExportBundle}>
                  Export Tenant Bundle
                </button>
                <button type="button" className="btn btn-secondary" onClick={handleEnforceRetention}>
                  Enforce Policies Now
                </button>
                <button type="button" className="btn btn-secondary" onClick={handleQueueRetentionJob}>
                  Queue Retention Job
                </button>
                <button type="button" className="btn btn-danger" onClick={handleDeletionRequest}>
                  Delete Data Class
                </button>
              </div>
            </form>
          ) : (
            <p style={{ color: "var(--text-secondary)" }}>
              Tenant Admin privileges required to mutate retention policies. Active role:{" "}
              <strong>{activeTenant?.role}</strong>.
            </p>
          )}

          {retention && (
            <div style={{ marginBlockStart: "0.75rem", fontSize: "0.85rem" }}>
              <div>Active policies: {retention.policies.length}</div>
              <div>Logged export/deletion requests: {retention.requests.length}</div>
            </div>
          )}

          {enforceResult && (
            <pre
              className="mono"
              style={{
                background: "var(--bg-subtle)",
                padding: "0.65rem",
                borderRadius: "0.375rem",
                overflowX: "auto",
                marginBlockStart: "0.75rem",
              }}
            >
              {JSON.stringify(enforceResult, null, 2)}
            </pre>
          )}

          {exportBundle && (
            <pre
              className="mono"
              style={{
                background: "var(--bg-subtle)",
                padding: "0.65rem",
                borderRadius: "0.375rem",
                overflowX: "auto",
                marginBlockStart: "0.75rem",
              }}
            >
              {JSON.stringify(exportBundle, null, 2)}
            </pre>
          )}
        </section>
      </div>

      <section className="card" style={{ marginBlockStart: "1.25rem" }}>
        <h2 className="card-title">Account Password Rotation (Local Dev / Test Users)</h2>
        <p style={{ marginTop: 0, fontSize: "0.88rem", color: "var(--text-secondary)" }}>
          Signed in as <code className="mono">{user?.email}</code>. Local password changes require
          12+ characters with mixed case, digits, and symbols.
        </p>
        <form onSubmit={handleChangePassword} className="form-stack">
          <div className="grid-2">
            <div className="field">
              <label htmlFor="pwd-current">Current Password</label>
              <input
                id="pwd-current"
                name="current_password"
                type="password"
                required
                autoComplete="current-password"
                value={curPwd}
                onChange={(e) => setCurPwd(e.target.value)}
              />
            </div>
            <div className="field">
              <label htmlFor="pwd-confirm">Confirm New Password</label>
              <input
                id="pwd-confirm"
                name="confirm_password"
                type="password"
                required
                autoComplete="new-password"
                value={confirmPwd}
                aria-invalid={pwdMismatchErr ? "true" : undefined}
                onChange={(e) => {
                  setConfirmPwd(e.target.value);
                  setPwdMismatchErr("");
                }}
              />
              {pwdMismatchErr && (
                <div className="field-error" role="alert">
                  ✕ {pwdMismatchErr}
                </div>
              )}
            </div>
          </div>

          <div className="field">
            <label htmlFor="pwd-new">New Password</label>
            <ul id="pwd-change-rules" className="rules-list">
              <li>At least 12 characters</li>
              <li>Uppercase &amp; lowercase letters</li>
              <li>At least one digit and one special character</li>
            </ul>
            <input
              id="pwd-new"
              name="new_password"
              type="password"
              required
              minLength={12}
              pattern="(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[\W_]).{12,}"
              autoComplete="new-password"
              aria-describedby="pwd-change-rules"
              value={newPwd}
              onChange={(e) => setNewPwd(e.target.value)}
            />
            <div className="field-error-msg">
              <span role="img" aria-label="Error">✕</span> Password does not meet the complexity requirements above.
            </div>
          </div>

          <div>
            <button type="submit" className="btn btn-primary">
              Rotate Password
            </button>
          </div>
        </form>
      </section>

      {isAdmin && (
        <section className="card" style={{ marginBlockStart: "1.25rem" }}>
          <h2 className="card-title">Tenant Members &amp; Least-Privilege RBAC</h2>

          <form
            onSubmit={handleInviteMember}
            className="form-stack"
            style={{
              marginBlockEnd: "1.25rem",
              paddingBlockEnd: "1rem",
              borderBlockEnd: "1px solid var(--border-subtle)",
            }}
          >
            <h3 style={{ margin: 0, fontSize: "1rem" }}>Invite / Provision Member</h3>
            <div className="grid-2">
              <div className="field">
                <label htmlFor="inv-email">Member Email</label>
                <span id="inv-email-hint" className="field-hint">
                  Format: member@organisation.example
                </span>
                <input
                  id="inv-email"
                  name="email"
                  type="email"
                  required
                  aria-describedby="inv-email-hint"
                  autoComplete="email"
                  autoCorrect="off"
                  autoCapitalize="none"
                  spellCheck={false}
                  value={invEmail}
                  onChange={(e) => setInvEmail(e.target.value)}
                  placeholder="sec-analyst@acme.local"
                />
                <div className="field-error-msg">
                  <span role="img" aria-label="Error">✕</span> Enter a valid email address.
                </div>
              </div>
              <div className="field">
                <label htmlFor="inv-name">Display Name</label>
                <input
                  id="inv-name"
                  name="display_name"
                  required
                  minLength={2}
                  autoComplete="name"
                  value={invName}
                  onChange={(e) => setInvName(e.target.value)}
                  placeholder="Jordan Rivera"
                />
              </div>
            </div>

            <div className="grid-2">
              <div className="field">
                <label htmlFor="inv-role">Assigned Role</label>
                <select
                  id="inv-role"
                  value={invRole}
                  onChange={(e) => setInvRole(e.target.value as RoleName)}
                >
                  {ALL_ROLES.map((r) => (
                    <option key={r} value={r}>
                      {r}
                    </option>
                  ))}
                </select>
              </div>
              <div className="field">
                <label htmlFor="inv-provider">Auth Provider</label>
                <select
                  id="inv-provider"
                  value={invProvider}
                  onChange={(e) => setInvProvider(e.target.value as "oidc" | "local")}
                >
                  <option value="oidc">Enterprise OIDC SSO (Production Standard)</option>
                  <option value="local">Local Password (Dev / Test Only)</option>
                </select>
              </div>
            </div>

            {invProvider === "local" && (
              <div className="field">
                <label htmlFor="inv-pwd">Initial Password (12+ chars, strong)</label>
                <input
                  id="inv-pwd"
                  type="password"
                  required
                  minLength={12}
                  autoComplete="new-password"
                  value={invPassword}
                  onChange={(e) => setInvPassword(e.target.value)}
                />
              </div>
            )}

            <div>
              <button type="submit" className="btn btn-primary">
                Provision Tenant Member
              </button>
            </div>
          </form>

          <div className="table-region" tabIndex={0} role="region" aria-label="Tenant members table">
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col">Member</th>
                  <th scope="col">Provider / MFA</th>
                  <th scope="col">Status</th>
                  <th scope="col">Current Role</th>
                  <th scope="col">Lifecycle Actions</th>
                </tr>
              </thead>
              <tbody>
                {members.map((m) => (
                  <tr key={m.membership_id}>
                    <th scope="row" data-label="Member">
                      <div>{m.display_name}</div>
                      <div className="mono">{m.email}</div>
                    </th>
                    <td data-label="Provider / MFA">
                      <span className="mono">{m.auth_provider || "local"}</span> /{" "}
                      {m.mfa_enabled ? "✓ MFA" : "No MFA"}
                    </td>
                    <td data-label="Status">
                      <StatusBadge status={m.status} />
                    </td>
                    <td data-label="Current Role" className="mono">
                      {m.role}
                    </td>
                    <td data-label="Lifecycle Actions">
                      <div className="btn-row">
                        <label htmlFor={`role-${m.membership_id}`} className="visually-hidden">
                          Role for {m.email}
                        </label>
                        <select
                          id={`role-${m.membership_id}`}
                          value={m.role}
                          onChange={(e) =>
                            handleRoleChange(m.membership_id, e.target.value as RoleName)
                          }
                          style={{ minHeight: "38px" }}
                        >
                          {ALL_ROLES.map((r) => (
                            <option key={r} value={r}>
                              {r}
                            </option>
                          ))}
                        </select>
                        <button
                          type="button"
                          className={`btn btn-sm ${
                            m.status === "active" ? "btn-danger" : "btn-secondary"
                          }`}
                          aria-label={`${m.status === "active" ? "Suspend" : "Reactivate"} ${m.email}`}
                          onClick={() => handleToggleMemberStatus(m)}
                        >
                          {m.status === "active" ? "Suspend" : "Reactivate"}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {isAdmin && (
        <section className="card" style={{ marginBlockStart: "1.25rem" }}>
          <h2 className="card-title">Outbound Webhooks (HMAC-SHA256 Signed &amp; SSRF-Protected)</h2>
          <form onSubmit={handleCreateWebhook} className="form-stack" style={{ marginBlockEnd: "1.25rem" }}>
            <div className="grid-2">
              <div className="field">
                <label htmlFor="wh-name">Subscription Name</label>
                <input
                  id="wh-name"
                  required
                  minLength={2}
                  value={whName}
                  onChange={(e) => setWhName(e.target.value)}
                  placeholder="e.g. SOC SIEM Alert Feed"
                />
              </div>
              <div className="field">
                <label htmlFor="wh-url">Target HTTPS Endpoint</label>
                <span id="wh-url-hint" className="field-hint">
                  Private, loopback, and cloud metadata IPs are blocked by SSRF guard unless configured.
                </span>
                <input
                  id="wh-url"
                  type="url"
                  required
                  aria-describedby="wh-url-hint"
                  autoCorrect="off"
                  autoCapitalize="none"
                  spellCheck={false}
                  value={whUrl}
                  onChange={(e) => setWhUrl(e.target.value)}
                  placeholder="https://siem.example.com/webhooks/sentinelgraph"
                />
              </div>
            </div>

            <div className="grid-2">
              <div className="field">
                <label htmlFor="wh-score">Minimum Priority Score (0–100)</label>
                <input
                  id="wh-score"
                  type="number"
                  min={0}
                  max={100}
                  value={whMinScore}
                  onChange={(e) => setWhMinScore(e.target.value)}
                />
              </div>
              <div className="field">
                <label htmlFor="wh-secret">Signing Secret (optional, min 12 chars)</label>
                <input
                  id="wh-secret"
                  type="password"
                  minLength={12}
                  value={whSecret}
                  onChange={(e) => setWhSecret(e.target.value)}
                  placeholder="Auto-generated if left blank"
                />
              </div>
            </div>

            <fieldset>
              <legend>Subscribed Event Types</legend>
              <div className="btn-row">
                {WEBHOOK_EVENTS.map((ev) => (
                  <div className="checkbox-row" key={ev.id}>
                    <input
                      id={`wh-ev-${ev.id}`}
                      type="checkbox"
                      checked={whEvents.includes(ev.id)}
                      onChange={() => toggleWebhookEvent(ev.id)}
                    />
                    <label htmlFor={`wh-ev-${ev.id}`}>
                      <span className="mono">{ev.id}</span> ({ev.label})
                    </label>
                  </div>
                ))}
              </div>
            </fieldset>

            <div>
              <button type="submit" className="btn btn-primary">
                Register Webhook
              </button>
            </div>
          </form>

          <div className="table-region" tabIndex={0} role="region" aria-label="Webhook subscriptions table">
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col">Name / Target</th>
                  <th scope="col">Events</th>
                  <th scope="col">Min Score</th>
                  <th scope="col">Last Delivery</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {webhooks.length === 0 ? (
                  <tr>
                    <td colSpan={5} style={{ color: "var(--text-muted)" }}>
                      No webhook subscriptions configured for this tenant.
                    </td>
                  </tr>
                ) : (
                  webhooks.map((w) => (
                    <tr key={w.id}>
                      <th scope="row" data-label="Name / Target">
                        <div>{w.name}</div>
                        <div className="mono" style={{ fontSize: "0.78rem", color: "var(--text-muted)" }}>
                          {w.target_url}
                        </div>
                      </th>
                      <td data-label="Events" className="mono">
                        {w.event_types.join(", ")}
                      </td>
                      <td data-label="Min Score">{w.min_priority_score}</td>
                      <td data-label="Last Delivery">
                        {w.last_status_code !== null ? (
                          <StatusBadge status={w.last_status_code < 400 ? "succeeded" : "failed"} />
                        ) : (
                          <span className="badge badge-neutral">Never Sent</span>
                        )}
                        {w.last_error && (
                          <div style={{ fontSize: "0.78rem", color: "var(--danger)" }}>{w.last_error}</div>
                        )}
                      </td>
                      <td data-label="Actions">
                        <div className="btn-row">
                          <button
                            type="button"
                            className="btn btn-secondary btn-sm"
                            aria-label={`Test delivery for ${w.name}`}
                            onClick={() => handleTestWebhook(w.id)}
                          >
                            Test Ping
                          </button>
                          <button
                            type="button"
                            className="btn btn-danger btn-sm"
                            aria-label={`Delete webhook ${w.name}`}
                            onClick={() => handleDeleteWebhook(w.id)}
                          >
                            Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
};
