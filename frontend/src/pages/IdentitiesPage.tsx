import React, { useCallback, useEffect, useState } from "react";
import { useAuth } from "../app/AuthContext";
import { CriticalityBadge, ErrorBanner, StatusBadge } from "../components/Badges";
import { ModalDialog } from "../components/ModalDialog";
import { apiRequest } from "../lib/api";
import type { GroupItem, IdentityItem } from "../types/api";

export const IdentitiesPage: React.FC = () => {
  const { hasRole } = useAuth();
  const canEdit = hasRole("tenant_admin", "assessor", "analyst");

  const [identities, setIdentities] = useState<IdentityItem[]>([]);
  const [groups, setGroups] = useState<GroupItem[]>([]);
  const [tab, setTab] = useState<"identities" | "groups">("identities");
  const [search, setSearch] = useState("");
  const [error, setError] = useState<unknown>(null);

  const [createOpen, setCreateOpen] = useState(false);
  const [externalId, setExternalId] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [principalName, setPrincipalName] = useState("");
  const [identityType, setIdentityType] = useState("service_account");
  const [privLevel, setPrivLevel] = useState("elevated");

  const [editTarget, setEditTarget] = useState<IdentityItem | null>(null);
  const [editDispName, setEditDispName] = useState("");
  const [editPrivLevel, setEditPrivLevel] = useState("standard");
  const [editEnabled, setEditEnabled] = useState(true);
  const [notice, setNotice] = useState("");

  const loadData = useCallback(async () => {
    try {
      const qs = search.trim() ? `?search=${encodeURIComponent(search.trim())}` : "";
      const [idRes, grpRes] = await Promise.all([
        apiRequest<{ items: IdentityItem[] }>(`/identities${qs}`),
        apiRequest<{ items: GroupItem[] }>("/identities/groups"),
      ]);
      setIdentities(idRes.items);
      setGroups(grpRes.items);
    } catch (err) {
      setError(err);
    }
  }, [search]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleCreateIdentity = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      await apiRequest("/identities", {
        method: "POST",
        body: {
          identity_type: identityType,
          external_id: externalId.trim(),
          provider: "manual_inventory",
          display_name: displayName.trim(),
          principal_name: principalName.trim(),
          privilege_level: privLevel,
          privilege_indicators: ["analyst_documented"],
        },
      });
      setCreateOpen(false);
      setExternalId("");
      setDisplayName("");
      setPrincipalName("");
      setNotice("Created identity record.");
      await loadData();
    } catch (err) {
      setError(err);
    }
  };

  const openEditIdentity = (item: IdentityItem) => {
    setEditTarget(item);
    setEditDispName(item.display_name);
    setEditPrivLevel(item.privilege_level);
    setEditEnabled(item.enabled);
  };

  const handleUpdateIdentity = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editTarget) return;
    setError(null);
    try {
      await apiRequest(`/identities/${editTarget.id}`, {
        method: "PATCH",
        body: {
          display_name: editDispName.trim(),
          privilege_level: editPrivLevel,
          enabled: editEnabled,
        },
      });
      setNotice(`Updated identity "${editDispName.trim()}".`);
      setEditTarget(null);
      await loadData();
    } catch (err) {
      setError(err);
    }
  };

  const handleRetireIdentity = async () => {
    if (!editTarget) return;
    setError(null);
    try {
      await apiRequest(`/identities/${editTarget.id}`, {
        method: "PATCH",
        body: { retire: true },
      });
      setNotice(`Retired identity "${editTarget.display_name}".`);
      setEditTarget(null);
      await loadData();
    } catch (err) {
      setError(err);
    }
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Identities &amp; Privilege Groups</h1>
          <p className="page-subtitle">
            Human users, non-human service accounts, and administrative security groups (passwords
            and secret tokens are strictly excluded from storage).
          </p>
        </div>
        {canEdit && (
          <button type="button" className="btn btn-primary" onClick={() => setCreateOpen(true)}>
            + Add Identity
          </button>
        )}
      </div>

      <ErrorBanner error={error} onDismiss={() => setError(null)} />
      {notice && (
        <div className="alert alert-success" role="status">
          <strong>✓ {notice}</strong>
        </div>
      )}

      <div
        className="card"
        style={{
          marginBlockEnd: "1rem",
          display: "flex",
          flexWrap: "wrap",
          gap: "0.75rem",
          alignItems: "center",
          justifyContent: "space-between",
        }}
      >
        <div className="btn-row" role="tablist" aria-label="Identity views">
          <button
            type="button"
            role="tab"
            aria-selected={tab === "identities"}
            className={`btn ${tab === "identities" ? "btn-primary" : "btn-secondary"}`}
            onClick={() => setTab("identities")}
          >
            Identities ({identities.length})
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={tab === "groups"}
            className={`btn ${tab === "groups" ? "btn-primary" : "btn-secondary"}`}
            onClick={() => setTab("groups")}
          >
            Security Groups ({groups.length})
          </button>
        </div>

        <div className="field" style={{ minWidth: "16rem" }}>
          <label htmlFor="identity-search" className="visually-hidden">
            Search Identities
          </label>
          <input
            id="identity-search"
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search principal or external ID..."
            autoCorrect="off"
            autoCapitalize="none"
            spellCheck={false}
          />
        </div>
      </div>

      {tab === "identities" ? (
        <div className="table-region" tabIndex={0} role="region" aria-label="Identities table">
          <table className="data-table">
            <caption>Directory &amp; Service Identities ({identities.length})</caption>
            <thead>
              <tr>
                <th scope="col">Principal</th>
                <th scope="col">Type / Provider</th>
                <th scope="col">Privilege Level</th>
                <th scope="col">Indicators</th>
                <th scope="col">Status</th>
                <th scope="col">Confidence</th>
                {canEdit && <th scope="col">Actions</th>}
              </tr>
            </thead>
            <tbody>
              {identities.map((id) => (
                <tr key={id.id}>
                  <th scope="row" data-label="Principal">
                    <div>{id.display_name}</div>
                    <div className="mono">{id.principal_name}</div>
                  </th>
                  <td data-label="Type / Provider">
                    {id.identity_type} ({id.provider})
                  </td>
                  <td data-label="Privilege Level">
                    <CriticalityBadge
                      level={
                        id.privilege_level === "admin"
                          ? "critical"
                          : id.privilege_level === "elevated"
                          ? "high"
                          : "low"
                      }
                    />
                  </td>
                  <td data-label="Indicators">
                    {id.privilege_indicators.join(", ") || "none"}
                  </td>
                  <td data-label="Status">
                    <StatusBadge status={id.enabled ? "active" : "disabled"} />
                  </td>
                  <td data-label="Confidence">{Math.round(id.confidence * 100)}%</td>
                  {canEdit && (
                    <td data-label="Actions">
                      <button
                        type="button"
                        className="btn btn-secondary btn-sm"
                        aria-label={`Edit or retire ${id.display_name}`}
                        onClick={() => openEditIdentity(id)}
                      >
                        Edit / Retire
                      </button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="table-region" tabIndex={0} role="region" aria-label="Groups table">
          <table className="data-table">
            <caption>Privilege Groups &amp; Roles ({groups.length})</caption>
            <thead>
              <tr>
                <th scope="col">Group Name</th>
                <th scope="col">Provider / Type</th>
                <th scope="col">Privilege Indicators</th>
                <th scope="col">Confidence</th>
              </tr>
            </thead>
            <tbody>
              {groups.map((g) => (
                <tr key={g.id}>
                  <th scope="row" data-label="Group Name">
                    <div>{g.display_name}</div>
                    <div className="mono">{g.external_id}</div>
                  </th>
                  <td data-label="Provider / Type">
                    {g.provider} ({g.group_type})
                  </td>
                  <td data-label="Privilege Indicators">
                    {g.privilege_indicators.join(", ") || "standard"}
                  </td>
                  <td data-label="Confidence">{Math.round(g.confidence * 100)}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <ModalDialog open={createOpen} title="Add Identity Record" onClose={() => setCreateOpen(false)}>
        <form onSubmit={handleCreateIdentity} className="form-stack">
          <div className="field">
            <label htmlFor="id-ext">External ID</label>
            <input
              id="id-ext"
              required
              value={externalId}
              onChange={(e) => setExternalId(e.target.value)}
              placeholder="svc-reporting"
            />
          </div>
          <div className="field">
            <label htmlFor="id-disp">Display Name</label>
            <input
              id="id-disp"
              required
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
            />
          </div>
          <div className="field">
            <label htmlFor="id-princ">Principal Name (no passwords/secrets)</label>
            <input
              id="id-princ"
              required
              value={principalName}
              onChange={(e) => setPrincipalName(e.target.value)}
              placeholder="svc-reporting@lab.sentinelgraph.invalid"
            />
          </div>
          <div className="grid-2">
            <div className="field">
              <label htmlFor="id-type">Identity Type</label>
              <select
                id="id-type"
                value={identityType}
                onChange={(e) => setIdentityType(e.target.value)}
              >
                <option value="human_user">Human User</option>
                <option value="service_account">Service Account</option>
                <option value="machine_identity">Machine Identity</option>
                <option value="workload_identity">Workload Identity</option>
                <option value="role_identity">Role Identity</option>
              </select>
            </div>
            <div className="field">
              <label htmlFor="id-priv">Privilege Level</label>
              <select
                id="id-priv"
                value={privLevel}
                onChange={(e) => setPrivLevel(e.target.value)}
              >
                <option value="standard">Standard</option>
                <option value="elevated">Elevated</option>
                <option value="admin">Admin</option>
              </select>
            </div>
          </div>
          <div className="btn-row">
            <button type="submit" className="btn btn-primary">
              Create Identity
            </button>
            <button type="button" className="btn btn-secondary" onClick={() => setCreateOpen(false)}>
              Cancel
            </button>
          </div>
        </form>
      </ModalDialog>

      <ModalDialog
        open={Boolean(editTarget)}
        title={`Edit Identity: ${editTarget?.display_name || ""}`}
        onClose={() => setEditTarget(null)}
      >
        <form onSubmit={handleUpdateIdentity} className="form-stack">
          <div className="field">
            <label htmlFor="edit-id-disp">Display Name</label>
            <input
              id="edit-id-disp"
              required
              value={editDispName}
              onChange={(e) => setEditDispName(e.target.value)}
            />
          </div>
          <div className="field">
            <label htmlFor="edit-id-priv">Privilege Level</label>
            <select
              id="edit-id-priv"
              value={editPrivLevel}
              onChange={(e) => setEditPrivLevel(e.target.value)}
            >
              <option value="standard">Standard</option>
              <option value="elevated">Elevated</option>
              <option value="admin">Admin</option>
            </select>
          </div>
          <div className="checkbox-row">
            <input
              id="edit-id-enabled"
              type="checkbox"
              checked={editEnabled}
              onChange={(e) => setEditEnabled(e.target.checked)}
            />
            <label htmlFor="edit-id-enabled">Identity Active / Enabled</label>
          </div>
          <div className="btn-row">
            <button type="submit" className="btn btn-primary">
              Save Identity Changes
            </button>
            <button type="button" className="btn btn-danger" onClick={handleRetireIdentity}>
              Retire Identity
            </button>
            <button type="button" className="btn btn-secondary" onClick={() => setEditTarget(null)}>
              Cancel
            </button>
          </div>
        </form>
      </ModalDialog>
    </div>
  );
};
