import React, { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useAuth } from "../app/AuthContext";
import { CriticalityBadge, ErrorBanner, StatusBadge } from "../components/Badges";
import { ModalDialog } from "../components/ModalDialog";
import { apiRequest } from "../lib/api";
import type { AssetItem, ServiceItem } from "../types/api";

export const AssetsPage: React.FC = () => {
  const { hasRole } = useAuth();
  const [searchParams] = useSearchParams();
  const canEdit = hasRole("tenant_admin", "assessor", "analyst");

  const [assets, setAssets] = useState<AssetItem[]>([]);
  const [total, setTotal] = useState(0);
  const [search, setSearch] = useState("");
  const [criticality, setCriticality] = useState(searchParams.get("criticality") || "");
  const [environment, setEnvironment] = useState("");
  const [selectedAsset, setSelectedAsset] = useState<AssetItem | null>(null);
  const [error, setError] = useState<unknown>(null);

  const [createOpen, setCreateOpen] = useState(false);
  const [newCanonical, setNewCanonical] = useState("host:10.10.5.10");
  const [newName, setNewName] = useState("");
  const [newType, setNewType] = useState("server");
  const [newEnv, setNewEnv] = useState("prod");
  const [newCrit, setNewCrit] = useState("medium");
  const [newIp, setNewIp] = useState("10.10.5.10");
  const [newExternal, setNewExternal] = useState(false);
  const [newCrown, setNewCrown] = useState(false);

  const [correctSvc, setCorrectSvc] = useState<ServiceItem | null>(null);
  const [corrProduct, setCorrProduct] = useState("");
  const [corrVersion, setCorrVersion] = useState("");

  const [editOpen, setEditOpen] = useState(false);
  const [editName, setEditName] = useState("");
  const [editType, setEditType] = useState("server");
  const [editEnv, setEditEnv] = useState("prod");
  const [editCrit, setEditCrit] = useState("medium");
  const [editOwner, setEditOwner] = useState("");
  const [editUnit, setEditUnit] = useState("");
  const [editExternal, setEditExternal] = useState(false);
  const [editCrown, setEditCrown] = useState(false);
  const [notice, setNotice] = useState("");

  const loadAssets = useCallback(async () => {
    try {
      const qs = new URLSearchParams();
      if (search.trim()) qs.set("search", search.trim());
      if (criticality) qs.set("criticality", criticality);
      if (environment) qs.set("environment", environment);
      const res = await apiRequest<{ items: AssetItem[]; total: number }>(
        `/assets?${qs.toString()}`
      );
      setAssets(res.items);
      setTotal(res.total);
    } catch (err) {
      setError(err);
    }
  }, [criticality, environment, search]);

  useEffect(() => {
    loadAssets();
  }, [loadAssets]);

  const handleCreateAsset = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      const created = await apiRequest<AssetItem>("/assets", {
        method: "POST",
        body: {
          canonical_key: newCanonical.trim(),
          display_name: newName.trim(),
          asset_type: newType,
          environment: newEnv,
          criticality: newCrit,
          is_external_entry: newExternal,
          is_crown_jewel: newCrown,
          addresses: newIp.trim()
            ? [{ address_type: "ipv4", value: newIp.trim(), is_primary: true }]
            : [],
        },
      });
      setCreateOpen(false);
      setNewName("");
      setSelectedAsset(created);
      await loadAssets();
    } catch (err) {
      setError(err);
    }
  };

  const handleCorrectBanner = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!correctSvc) return;
    setError(null);
    try {
      await apiRequest(`/assets/services/${correctSvc.id}/correct`, {
        method: "PATCH",
        body: {
          corrected_product: corrProduct.trim() || null,
          corrected_version: corrVersion.trim() || null,
          confidence: 0.92,
        },
      });
      setCorrectSvc(null);
      await loadAssets();
      if (selectedAsset) {
        const refreshed = await apiRequest<AssetItem>(`/assets/${selectedAsset.id}`);
        setSelectedAsset(refreshed);
      }
    } catch (err) {
      setError(err);
    }
  };

  const openEditModal = (asset: AssetItem) => {
    setEditName(asset.display_name);
    setEditType(asset.asset_type);
    setEditEnv(asset.environment);
    setEditCrit(asset.criticality);
    setEditOwner(asset.owner);
    setEditUnit(asset.business_unit);
    setEditExternal(asset.is_external_entry);
    setEditCrown(asset.is_crown_jewel);
    setEditOpen(true);
  };

  const handleUpdateAsset = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAsset) return;
    setError(null);
    try {
      const updated = await apiRequest<AssetItem>(`/assets/${selectedAsset.id}`, {
        method: "PATCH",
        body: {
          display_name: editName.trim(),
          asset_type: editType,
          environment: editEnv,
          criticality: editCrit,
          owner: editOwner.trim() || "unassigned",
          business_unit: editUnit.trim() || "general",
          is_external_entry: editExternal,
          is_crown_jewel: editCrown,
        },
      });
      setEditOpen(false);
      setSelectedAsset(updated);
      setNotice(`Updated asset "${updated.display_name}".`);
      await loadAssets();
    } catch (err) {
      setError(err);
    }
  };

  const handleRetireAsset = async () => {
    if (!selectedAsset) return;
    setError(null);
    try {
      await apiRequest(`/assets/${selectedAsset.id}`, {
        method: "PATCH",
        body: { retire: true },
      });
      setEditOpen(false);
      setNotice(`Retired asset "${selectedAsset.display_name}".`);
      setSelectedAsset(null);
      await loadAssets();
    } catch (err) {
      setError(err);
    }
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Assets &amp; Service Exposure</h1>
          <p className="page-subtitle">
            Normalised hosts, exposed services, banner provenance, and CVE observations.
          </p>
        </div>
        {canEdit && (
          <button type="button" className="btn btn-primary" onClick={() => setCreateOpen(true)}>
            + Add Asset
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
          alignItems: "end",
        }}
      >
        <div className="field" style={{ flex: "1 1 14rem" }}>
          <label htmlFor="asset-search">Search Name, Canonical Key, Owner, or IP</label>
          <input
            id="asset-search"
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="web-dmz-01 or 10.10."
            autoCorrect="off"
            autoCapitalize="none"
            spellCheck={false}
          />
        </div>
        <div className="field" style={{ minWidth: "10rem" }}>
          <label htmlFor="asset-crit">Criticality</label>
          <select
            id="asset-crit"
            value={criticality}
            onChange={(e) => setCriticality(e.target.value)}
          >
            <option value="">All Criticalities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
        <div className="field" style={{ minWidth: "10rem" }}>
          <label htmlFor="asset-env">Environment</label>
          <select
            id="asset-env"
            value={environment}
            onChange={(e) => setEnvironment(e.target.value)}
          >
            <option value="">All Environments</option>
            <option value="prod">Production</option>
            <option value="staging">Staging</option>
            <option value="dev">Dev</option>
            <option value="lab">Lab</option>
          </select>
        </div>
      </div>

      <div className="split-drawer-layout">
        <div className="table-region" tabIndex={0} role="region" aria-label="Tenant assets table">
          <table className="data-table">
            <caption>Assets ({total} in active tenant)</caption>
            <thead>
              <tr>
                <th scope="col">Asset</th>
                <th scope="col">Type / Env</th>
                <th scope="col">Criticality</th>
                <th scope="col">Services</th>
                <th scope="col">Flags</th>
                <th scope="col">Action</th>
              </tr>
            </thead>
            <tbody>
              {assets.map((a) => (
                <tr key={a.id}>
                  <th scope="row" data-label="Asset">
                    <div>{a.display_name}</div>
                    <div className="mono">{a.canonical_key}</div>
                  </th>
                  <td data-label="Type / Env">
                    {a.asset_type} / {a.environment}
                  </td>
                  <td data-label="Criticality">
                    <CriticalityBadge level={a.criticality} />
                  </td>
                  <td data-label="Services">
                    {a.services.length} open ({a.open_findings.length} CVE)
                  </td>
                  <td data-label="Flags">
                    <div className="btn-row">
                      {a.is_external_entry && <span className="badge badge-info">Entry</span>}
                      {a.is_crown_jewel && <span className="badge badge-critical">Crown Jewel</span>}
                    </div>
                  </td>
                  <td data-label="Action">
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={() => setSelectedAsset(a)}
                    >
                      Inspect
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <aside className="card" aria-label="Asset detail panel">
          <h2 className="card-title">Asset Details</h2>
          {!selectedAsset ? (
            <p style={{ color: "var(--text-secondary)" }}>
              Select an asset row to inspect addresses, detected services, banner provenance, and
              non-exploitative CVE records.
            </p>
          ) : (
            <div className="form-stack">
              <div>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: "0.5rem" }}>
                  <div>
                    <strong>{selectedAsset.display_name}</strong>
                    <div className="mono">{selectedAsset.canonical_key}</div>
                  </div>
                  {canEdit && (
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={() => openEditModal(selectedAsset)}
                    >
                      Edit / Retire
                    </button>
                  )}
                </div>
                <div style={{ fontSize: "0.85rem", color: "var(--text-secondary)" }}>
                  Owner: {selectedAsset.owner} | Unit: {selectedAsset.business_unit} | Confidence:{" "}
                  {Math.round(selectedAsset.confidence * 100)}%
                </div>
              </div>

              <div>
                <h3 style={{ fontSize: "0.95rem", margin: "0 0 0.35rem" }}>Network Addresses</h3>
                <ul style={{ margin: 0, paddingInlineStart: "1.2rem" }}>
                  {selectedAsset.addresses.map((addr) => (
                    <li key={addr.id} className="mono">
                      {addr.address_type}: {addr.value} {addr.is_primary ? "(primary)" : ""}
                    </li>
                  ))}
                </ul>
              </div>

              <div>
                <h3 style={{ fontSize: "0.95rem", margin: "0 0 0.35rem" }}>
                  Services ({selectedAsset.services.length})
                </h3>
                {selectedAsset.services.map((svc) => (
                  <div
                    key={svc.id}
                    style={{
                      border: "1px solid var(--border-subtle)",
                      borderRadius: "0.375rem",
                      padding: "0.55rem",
                      marginBlockEnd: "0.5rem",
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", gap: "0.5rem" }}>
                      <strong className="mono">
                        {svc.port}/{svc.protocol} ({svc.service_name || "unknown"})
                      </strong>
                      <StatusBadge status={svc.state} />
                    </div>
                    <div style={{ fontSize: "0.85rem" }}>
                      Product: {svc.product || "—"} {svc.version || ""}
                      {svc.analyst_corrected_product && (
                        <span className="badge badge-info" style={{ marginInlineStart: "0.4rem" }}>
                          ✎ Analyst Corrected
                        </span>
                      )}
                    </div>
                    <div style={{ fontSize: "0.78rem", color: "var(--text-muted)" }}>
                      Raw banner: <span className="mono">{svc.banner_raw || "none"}</span>
                    </div>
                    {canEdit && (
                      <button
                        type="button"
                        className="btn btn-secondary btn-sm"
                        style={{ marginBlockStart: "0.35rem" }}
                        onClick={() => {
                          setCorrectSvc(svc);
                          setCorrProduct(svc.analyst_corrected_product || svc.product || "");
                          setCorrVersion(svc.analyst_corrected_version || svc.version || "");
                        }}
                      >
                        Correct Banner
                      </button>
                    )}
                  </div>
                ))}
              </div>

              <div>
                <h3 style={{ fontSize: "0.95rem", margin: "0 0 0.35rem" }}>
                  Vulnerability Observations ({selectedAsset.open_findings.length})
                </h3>
                {selectedAsset.open_findings.length === 0 ? (
                  <p style={{ fontSize: "0.85rem", color: "var(--text-muted)", margin: 0 }}>
                    No open CVE observations ingested.
                  </p>
                ) : (
                  selectedAsset.open_findings.map((f) => (
                    <div
                      key={f.id}
                      style={{
                        border: "1px solid var(--border-subtle)",
                        borderRadius: "0.375rem",
                        padding: "0.55rem",
                        marginBlockEnd: "0.5rem",
                      }}
                    >
                      <div className="btn-row">
                        <strong className="mono">{f.cve_id || "NO-CVE"}</strong>
                        <CriticalityBadge level={f.severity} />
                        {f.cvss_score !== null && (
                          <span className="badge badge-neutral">CVSS {f.cvss_score}</span>
                        )}
                      </div>
                      <div style={{ fontSize: "0.82rem", color: "var(--text-secondary)" }}>
                        Component: {f.affected_component || "unknown"}
                      </div>
                      <div style={{ fontSize: "0.78rem", fontWeight: 700, color: "#92400e" }}>
                        ⚠ Exploitability proven:{" "}
                        {f.exploitability_proven ? "Yes" : "No (scanner finding ≠ verified exploit)"}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </aside>
      </div>

      <ModalDialog open={createOpen} title="Add Asset to Tenant Inventory" onClose={() => setCreateOpen(false)}>
        <form onSubmit={handleCreateAsset} className="form-stack">
          <div className="field">
            <label htmlFor="new-asset-canon">Canonical Key</label>
            <input
              id="new-asset-canon"
              required
              value={newCanonical}
              onChange={(e) => setNewCanonical(e.target.value)}
            />
          </div>
          <div className="field">
            <label htmlFor="new-asset-name">Display Name</label>
            <input
              id="new-asset-name"
              required
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="e.g. billing-api-01"
            />
          </div>
          <div className="grid-2">
            <div className="field">
              <label htmlFor="new-asset-type">Asset Type</label>
              <select id="new-asset-type" value={newType} onChange={(e) => setNewType(e.target.value)}>
                <option value="server">Server</option>
                <option value="host">Host</option>
                <option value="endpoint">Endpoint</option>
                <option value="application">Application</option>
                <option value="database">Database</option>
                <option value="identity_provider">Identity Provider</option>
                <option value="network_device">Network Device</option>
                <option value="cloud_resource">Cloud Resource</option>
              </select>
            </div>
            <div className="field">
              <label htmlFor="new-asset-crit">Criticality</label>
              <select id="new-asset-crit" value={newCrit} onChange={(e) => setNewCrit(e.target.value)}>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </div>
          <div className="grid-2">
            <div className="field">
              <label htmlFor="new-asset-env">Environment</label>
              <select id="new-asset-env" value={newEnv} onChange={(e) => setNewEnv(e.target.value)}>
                <option value="prod">Production</option>
                <option value="staging">Staging</option>
                <option value="dev">Dev</option>
                <option value="lab">Lab</option>
              </select>
            </div>
            <div className="field">
              <label htmlFor="new-asset-ip">Primary IPv4</label>
              <input id="new-asset-ip" value={newIp} onChange={(e) => setNewIp(e.target.value)} />
            </div>
          </div>
          <div className="checkbox-row">
            <input
              id="new-asset-ext"
              type="checkbox"
              checked={newExternal}
              onChange={(e) => setNewExternal(e.target.checked)}
            />
            <label htmlFor="new-asset-ext">Mark as External / Entry Point</label>
          </div>
          <div className="checkbox-row">
            <input
              id="new-asset-crown"
              type="checkbox"
              checked={newCrown}
              onChange={(e) => setNewCrown(e.target.checked)}
            />
            <label htmlFor="new-asset-crown">Mark as Crown Jewel Target</label>
          </div>
          <div className="btn-row">
            <button type="submit" className="btn btn-primary">
              Create Asset
            </button>
            <button type="button" className="btn btn-secondary" onClick={() => setCreateOpen(false)}>
              Cancel
            </button>
          </div>
        </form>
      </ModalDialog>

      <ModalDialog
        open={Boolean(correctSvc)}
        title="Correct Service Banner (Preserves Raw Evidence)"
        onClose={() => setCorrectSvc(null)}
      >
        <form onSubmit={handleCorrectBanner} className="form-stack">
          <p style={{ margin: 0, color: "var(--text-secondary)" }}>
            Original raw banner: <code className="mono">{correctSvc?.banner_raw || "none"}</code>.
            This correction adds an analyst override without overwriting raw imported evidence.
          </p>
          <div className="field">
            <label htmlFor="corr-prod">Corrected Product</label>
            <input
              id="corr-prod"
              value={corrProduct}
              onChange={(e) => setCorrProduct(e.target.value)}
            />
          </div>
          <div className="field">
            <label htmlFor="corr-ver">Corrected Version</label>
            <input
              id="corr-ver"
              value={corrVersion}
              onChange={(e) => setCorrVersion(e.target.value)}
            />
          </div>
          <div className="btn-row">
            <button type="submit" className="btn btn-primary">
              Save Correction
            </button>
            <button type="button" className="btn btn-secondary" onClick={() => setCorrectSvc(null)}>
              Cancel
            </button>
          </div>
        </form>
      </ModalDialog>

      <ModalDialog
        open={editOpen && Boolean(selectedAsset)}
        title={`Edit Asset: ${selectedAsset?.display_name || ""}`}
        onClose={() => setEditOpen(false)}
      >
        <form onSubmit={handleUpdateAsset} className="form-stack">
          <div className="field">
            <label htmlFor="edit-asset-name">Display Name</label>
            <input
              id="edit-asset-name"
              required
              value={editName}
              onChange={(e) => setEditName(e.target.value)}
            />
          </div>
          <div className="grid-2">
            <div className="field">
              <label htmlFor="edit-asset-type">Asset Type</label>
              <select id="edit-asset-type" value={editType} onChange={(e) => setEditType(e.target.value)}>
                <option value="server">Server</option>
                <option value="host">Host</option>
                <option value="endpoint">Endpoint</option>
                <option value="application">Application</option>
                <option value="database">Database</option>
                <option value="identity_provider">Identity Provider</option>
                <option value="network_device">Network Device</option>
                <option value="cloud_resource">Cloud Resource</option>
              </select>
            </div>
            <div className="field">
              <label htmlFor="edit-asset-crit">Criticality</label>
              <select id="edit-asset-crit" value={editCrit} onChange={(e) => setEditCrit(e.target.value)}>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </div>
          <div className="grid-2">
            <div className="field">
              <label htmlFor="edit-asset-env">Environment</label>
              <select id="edit-asset-env" value={editEnv} onChange={(e) => setEditEnv(e.target.value)}>
                <option value="prod">Production</option>
                <option value="staging">Staging</option>
                <option value="dev">Dev</option>
                <option value="lab">Lab</option>
              </select>
            </div>
            <div className="field">
              <label htmlFor="edit-asset-owner">Owner</label>
              <input id="edit-asset-owner" value={editOwner} onChange={(e) => setEditOwner(e.target.value)} />
            </div>
          </div>
          <div className="field">
            <label htmlFor="edit-asset-unit">Business Unit</label>
            <input id="edit-asset-unit" value={editUnit} onChange={(e) => setEditUnit(e.target.value)} />
          </div>
          <div className="checkbox-row">
            <input
              id="edit-asset-ext"
              type="checkbox"
              checked={editExternal}
              onChange={(e) => setEditExternal(e.target.checked)}
            />
            <label htmlFor="edit-asset-ext">Mark as External / Entry Point</label>
          </div>
          <div className="checkbox-row">
            <input
              id="edit-asset-crown"
              type="checkbox"
              checked={editCrown}
              onChange={(e) => setEditCrown(e.target.checked)}
            />
            <label htmlFor="edit-asset-crown">Mark as Crown Jewel Target</label>
          </div>
          <div className="btn-row">
            <button type="submit" className="btn btn-primary">
              Save Asset Changes
            </button>
            <button type="button" className="btn btn-danger" onClick={handleRetireAsset}>
              Retire Asset
            </button>
            <button type="button" className="btn btn-secondary" onClick={() => setEditOpen(false)}>
              Cancel
            </button>
          </div>
        </form>
      </ModalDialog>
    </div>
  );
};
