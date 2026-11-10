import React, { useCallback, useEffect, useState } from "react";
import { useAuth } from "../app/AuthContext";
import { ErrorBanner, ProvenanceBadge } from "../components/Badges";
import { ModalDialog } from "../components/ModalDialog";
import { apiRequest } from "../lib/api";
import type { AssetItem, GroupItem, IdentityItem, RelationshipItem } from "../types/api";

export const RelationshipsPage: React.FC = () => {
  const { hasRole } = useAuth();
  const canEdit = hasRole("tenant_admin", "assessor", "analyst");

  const [items, setItems] = useState<RelationshipItem[]>([]);
  const [assets, setAssets] = useState<AssetItem[]>([]);
  const [identities, setIdentities] = useState<IdentityItem[]>([]);
  const [groups, setGroups] = useState<GroupItem[]>([]);
  const [relFilter, setRelFilter] = useState("");
  const [factFilter, setFactFilter] = useState("");
  const [error, setError] = useState<unknown>(null);

  const [createOpen, setCreateOpen] = useState(false);
  const [sourceRef, setSourceRef] = useState("");
  const [targetRef, setTargetRef] = useState("");
  const [relationType, setRelationType] = useState("CONNECTS_TO");
  const [factKind, setFactKind] = useState("analyst_assertion");
  const [confidence, setConfidence] = useState("0.8");

  const [suppressTarget, setSuppressTarget] = useState<RelationshipItem | null>(null);
  const [suppressReason, setSuppressReason] = useState("");

  const loadAll = useCallback(async () => {
    try {
      const qs = new URLSearchParams({ include_suppressed: "true" });
      if (relFilter) qs.set("relation_type", relFilter);
      if (factFilter) qs.set("fact_kind", factFilter);
      const [relRes, assetRes, idRes, grpRes] = await Promise.all([
        apiRequest<{ items: RelationshipItem[] }>(`/relationships?${qs.toString()}`),
        apiRequest<{ items: AssetItem[] }>("/assets?limit=100"),
        apiRequest<{ items: IdentityItem[] }>("/identities?limit=100"),
        apiRequest<{ items: GroupItem[] }>("/identities/groups?limit=100"),
      ]);
      setItems(relRes.items);
      setAssets(assetRes.items);
      setIdentities(idRes.items);
      setGroups(grpRes.items);
    } catch (err) {
      setError(err);
    }
  }, [factFilter, relFilter]);

  useEffect(() => {
    loadAll();
  }, [loadAll]);

  const nodeOptions = [
    ...assets.map((a) => ({ value: `asset:${a.id}`, label: `[Asset] ${a.display_name}` })),
    ...identities.map((i) => ({ value: `identity:${i.id}`, label: `[Identity] ${i.display_name}` })),
    ...groups.map((g) => ({ value: `group:${g.id}`, label: `[Group] ${g.display_name}` })),
  ];

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    const [sourceKind, sourceId] = sourceRef.split(":");
    const [targetKind, targetId] = targetRef.split(":");
    if (!sourceId || !targetId) return;
    try {
      await apiRequest("/relationships", {
        method: "POST",
        body: {
          source_kind: sourceKind,
          source_id: sourceId,
          target_kind: targetKind,
          target_id: targetId,
          relation_type: relationType,
          fact_kind: factKind,
          confidence: Number(confidence),
        },
      });
      setCreateOpen(false);
      await loadAll();
    } catch (err) {
      setError(err);
    }
  };

  const handleToggleSuppress = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!suppressTarget) return;
    setError(null);
    try {
      await apiRequest(`/relationships/${suppressTarget.id}/suppress`, {
        method: "POST",
        body: {
          suppressed: !suppressTarget.is_suppressed,
          reason: suppressReason.trim(),
        },
      });
      setSuppressTarget(null);
      setSuppressReason("");
      await loadAll();
    } catch (err) {
      setError(err);
    }
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Relationships &amp; Evidence Provenance</h1>
          <p className="page-subtitle">
            Strict domain-validated edges separating observed facts, inferred edges, and analyst
            assertions. Suppressing an edge excludes it from graph paths while retaining raw
            evidence.
          </p>
        </div>
        {canEdit && (
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => {
              if (!sourceRef && nodeOptions[0]) setSourceRef(nodeOptions[0].value);
              if (!targetRef && nodeOptions[1]) setTargetRef(nodeOptions[1].value);
              setCreateOpen(true);
            }}
          >
            + Assert Relationship
          </button>
        )}
      </div>

      <ErrorBanner error={error} onDismiss={() => setError(null)} />

      <div
        className="card"
        style={{ marginBlockEnd: "1rem", display: "flex", flexWrap: "wrap", gap: "0.75rem" }}
      >
        <div className="field" style={{ minWidth: "12rem" }}>
          <label htmlFor="rel-type-filter">Relation Type</label>
          <select
            id="rel-type-filter"
            value={relFilter}
            onChange={(e) => setRelFilter(e.target.value)}
          >
            <option value="">All Edge Types</option>
            <option value="HOSTS">HOSTS</option>
            <option value="CONNECTS_TO">CONNECTS_TO</option>
            <option value="RUNS_SERVICE">RUNS_SERVICE</option>
            <option value="EXPOSES">EXPOSES</option>
            <option value="DEPENDS_ON">DEPENDS_ON</option>
            <option value="MEMBER_OF">MEMBER_OF</option>
            <option value="HAS_ROLE">HAS_ROLE</option>
            <option value="CAN_ADMINISTER">CAN_ADMINISTER</option>
            <option value="TRUSTS">TRUSTS</option>
            <option value="OWNS">OWNS</option>
          </select>
        </div>

        <div className="field" style={{ minWidth: "12rem" }}>
          <label htmlFor="rel-fact-filter">Fact Provenance</label>
          <select
            id="rel-fact-filter"
            value={factFilter}
            onChange={(e) => setFactFilter(e.target.value)}
          >
            <option value="">All Fact Kinds</option>
            <option value="observed_fact">Observed Fact</option>
            <option value="inferred_relationship">Inferred Relationship</option>
            <option value="analyst_assertion">Analyst Assertion</option>
          </select>
        </div>
      </div>

      <div className="table-region" tabIndex={0} role="region" aria-label="Relationships table">
        <table className="data-table">
          <caption>Evidence-Backed Relationships ({items.length})</caption>
          <thead>
            <tr>
              <th scope="col">Source → Target</th>
              <th scope="col">Relation</th>
              <th scope="col">Provenance</th>
              <th scope="col">Confidence</th>
              <th scope="col">Evidence Source</th>
              <th scope="col">Challenge / Suppress</th>
            </tr>
          </thead>
          <tbody>
            {items.map((r) => (
              <tr key={r.id}>
                <th scope="row" data-label="Source → Target">
                  <div>
                    {r.source_label} → {r.target_label}
                  </div>
                  <div className="mono">
                    {r.source_kind} → {r.target_kind}
                  </div>
                </th>
                <td data-label="Relation" className="mono">
                  {r.relation_type}
                </td>
                <td data-label="Provenance">
                  <ProvenanceBadge factKind={r.fact_kind} suppressed={r.is_suppressed} />
                  {r.suppressed_reason && (
                    <div style={{ fontSize: "0.78rem", color: "var(--text-muted)" }}>
                      Reason: {r.suppressed_reason}
                    </div>
                  )}
                </td>
                <td data-label="Confidence">{Math.round(r.confidence * 100)}%</td>
                <td data-label="Evidence Source" className="mono">
                  {r.provenance?.source_product || "unknown"}
                </td>
                <td data-label="Challenge / Suppress">
                  {canEdit ? (
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={() => {
                        setSuppressTarget(r);
                        setSuppressReason("");
                      }}
                    >
                      {r.is_suppressed ? "Restore Edge" : "Suppress Edge"}
                    </button>
                  ) : (
                    <span>Read-only</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <ModalDialog
        open={createOpen}
        title="Assert Validated Graph Relationship"
        onClose={() => setCreateOpen(false)}
      >
        <form onSubmit={handleCreate} className="form-stack">
          <div className="field">
            <label htmlFor="rel-src">Source Entity</label>
            <select id="rel-src" value={sourceRef} onChange={(e) => setSourceRef(e.target.value)}>
              {nodeOptions.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="rel-type-new">Relation Type (enforced by endpoint schema)</label>
            <select
              id="rel-type-new"
              value={relationType}
              onChange={(e) => setRelationType(e.target.value)}
            >
              <option value="HOSTS">HOSTS (asset → asset/service)</option>
              <option value="CONNECTS_TO">CONNECTS_TO (asset/service → asset/service)</option>
              <option value="RUNS_SERVICE">RUNS_SERVICE (asset → service)</option>
              <option value="EXPOSES">EXPOSES (asset/service → asset/service)</option>
              <option value="DEPENDS_ON">DEPENDS_ON (asset/service → asset/service/identity)</option>
              <option value="MEMBER_OF">MEMBER_OF (identity/group → group)</option>
              <option value="HAS_ROLE">HAS_ROLE (asset/service/identity/group → identity/group)</option>
              <option value="CAN_ADMINISTER">CAN_ADMINISTER (identity/group/asset → asset/service/group/identity)</option>
              <option value="TRUSTS">TRUSTS (asset/identity/group trust boundary)</option>
              <option value="OWNS">OWNS (identity/group → asset/service/group)</option>
            </select>
          </div>
          <div className="field">
            <label htmlFor="rel-dst">Target Entity</label>
            <select id="rel-dst" value={targetRef} onChange={(e) => setTargetRef(e.target.value)}>
              {nodeOptions.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </div>
          <div className="grid-2">
            <div className="field">
              <label htmlFor="rel-fact">Fact Kind</label>
              <select id="rel-fact" value={factKind} onChange={(e) => setFactKind(e.target.value)}>
                <option value="analyst_assertion">Analyst Assertion</option>
                <option value="observed_fact">Observed Fact</option>
                <option value="inferred_relationship">Inferred Relationship</option>
              </select>
            </div>
            <div className="field">
              <label htmlFor="rel-conf">Confidence (0.05 – 1.0)</label>
              <input
                id="rel-conf"
                type="number"
                step="0.05"
                min="0.05"
                max="1"
                value={confidence}
                onChange={(e) => setConfidence(e.target.value)}
              />
            </div>
          </div>
          <div className="btn-row">
            <button type="submit" className="btn btn-primary">
              Create Relationship
            </button>
            <button type="button" className="btn btn-secondary" onClick={() => setCreateOpen(false)}>
              Cancel
            </button>
          </div>
        </form>
      </ModalDialog>

      <ModalDialog
        open={Boolean(suppressTarget)}
        title={
          suppressTarget?.is_suppressed
            ? "Restore Relationship Evidence"
            : "Suppress False-Positive Relationship"
        }
        onClose={() => setSuppressTarget(null)}
      >
        <form onSubmit={handleToggleSuppress} className="form-stack">
          <p style={{ margin: 0 }}>
            {suppressTarget?.source_label} --[{suppressTarget?.relation_type}]--&gt;{" "}
            {suppressTarget?.target_label}. Raw evidence provenance remains untouched in the
            database and audit trail.
          </p>
          <div className="field">
            <label htmlFor="sup-reason">
              Justification Reason <span aria-hidden="true">*</span>
            </label>
            <textarea
              id="sup-reason"
              required
              minLength={3}
              value={suppressReason}
              onChange={(e) => setSuppressReason(e.target.value)}
              placeholder="e.g. Firewall ticket #FW-912 confirms segmented drop rule"
            />
          </div>
          <div className="btn-row">
            <button type="submit" className="btn btn-primary">
              {suppressTarget?.is_suppressed ? "Confirm Restore" : "Confirm Suppress"}
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => setSuppressTarget(null)}
            >
              Cancel
            </button>
          </div>
        </form>
      </ModalDialog>
    </div>
  );
};
