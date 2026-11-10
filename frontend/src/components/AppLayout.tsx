import React, { useId, useState } from "react";
import { Link, NavLink, useNavigate } from "react-router-dom";
import { useAuth } from "../app/AuthContext";
import { apiRequest } from "../lib/api";
import type { SearchResultsResponse } from "../types/api";
import { ModalDialog } from "./ModalDialog";

const NAV_GROUPS = [
  {
    section: "Intelligence",
    items: [
      { to: "/overview", label: "Overview", icon: "◈" },
      { to: "/assessments", label: "Assessments & Graph", icon: "⬡" },
      { to: "/paths", label: "Attack Paths", icon: "⚡" },
      { to: "/remediations", label: "Remediation Planner", icon: "🛡" },
    ],
  },
  {
    section: "Evidence & Model",
    items: [
      { to: "/assets", label: "Assets", icon: "▣" },
      { to: "/findings", label: "Findings & Triage", icon: "⚑" },
      { to: "/identities", label: "Identities & Groups", icon: "◉" },
      { to: "/relationships", label: "Relationships", icon: "⇄" },
      { to: "/imports", label: "Imports (Staged)", icon: "⇣" },
    ],
  },
  {
    section: "Governance",
    items: [
      { to: "/integrations", label: "Connectors", icon: "⊞" },
      { to: "/reports", label: "Reports", icon: "▤" },
      { to: "/jobs", label: "Background Jobs", icon: "⟳" },
      { to: "/audit", label: "Audit Log", icon: "⚖" },
      { to: "/settings", label: "Settings & Privacy", icon: "⚙" },
    ],
  },
];

export const AppLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { user, activeTenant, memberships, switchTenant, logout } = useAuth();
  const [navOpen, setNavOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<SearchResultsResponse | null>(null);
  const [searchOpen, setSearchOpen] = useState(false);
  const navigate = useNavigate();
  const navId = useId();
  const searchInputId = useId();

  const handleGlobalSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    const q = searchQuery.trim();
    if (!q) return;
    const res = await apiRequest<SearchResultsResponse>(`/search?q=${encodeURIComponent(q)}`);
    setSearchResults(res);
    setSearchOpen(true);
  };

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Skip to main content
      </a>

      {activeTenant?.is_demo && (
        <div className="demo-watermark-banner" role="status">
          <span>
            ⚠ DEMO / SYNTHETIC LAB TENANT ({activeTenant.name}) — All infrastructure data, hosts,
            and scores are isolated synthetic lab artefacts.
          </span>
          <span className="mono">
            Active Role: {activeTenant.role} | User: {user?.email}
          </span>
        </div>
      )}

      <header className="app-header">
        <div className="app-brand">
          <button
            type="button"
            className="nav-toggle-btn"
            aria-expanded={navOpen}
            aria-controls={navId}
            onClick={() => setNavOpen((o) => !o)}
          >
            ☰ Menu
          </button>
          <span className="brand-mark" aria-hidden="true">
            SG
          </span>
          <div>
            <div className="brand-title">SentinelGraph</div>
            <div className="brand-sub">Authorised Attack-Path Intelligence</div>
          </div>
        </div>

        <div className="header-controls">
          <search>
            <form className="header-search-form" onSubmit={handleGlobalSearch}>
              <label htmlFor={searchInputId} className="visually-hidden">
                Search tenant assets, identities, or attack paths
              </label>
              <input
                id={searchInputId}
                className="header-search-input"
                type="search"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search tenant inventory..."
                autoCorrect="off"
                autoCapitalize="none"
                spellCheck={false}
              />
              <button type="submit" className="btn btn-secondary btn-sm">
                Search
              </button>
            </form>
          </search>

          {memberships.length > 1 ? (
            <div>
              <label htmlFor="header-tenant-switch" className="visually-hidden">
                Active Tenant
              </label>
              <select
                id="header-tenant-switch"
                value={activeTenant?.id || ""}
                onChange={(e) => {
                  switchTenant(e.target.value).then(() => navigate("/overview"));
                }}
                style={{ minHeight: "44px", borderRadius: "0.375rem", padding: "0 0.5rem" }}
              >
                {memberships.map((m) => (
                  <option key={m.tenant_id} value={m.tenant_id}>
                    {m.tenant_name} ({m.role})
                  </option>
                ))}
              </select>
            </div>
          ) : (
            <span className="badge badge-info">
              Tenant: {activeTenant?.slug} ({activeTenant?.role})
            </span>
          )}

          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={async () => {
              await logout();
              navigate("/login");
            }}
          >
            Sign Out
          </button>
        </div>
      </header>

      <div className="app-body">
        <nav
          id={navId}
          className={`primary-nav ${navOpen ? "is-open" : ""}`}
          aria-label="Primary"
        >
          {NAV_GROUPS.map((grp) => (
            <React.Fragment key={grp.section}>
              <div className="nav-section-label">{grp.section}</div>
              <ul className="nav-list">
                {grp.items.map((item) => (
                  <li key={item.to}>
                    <NavLink
                      to={item.to}
                      className="nav-link"
                      onClick={() => setNavOpen(false)}
                    >
                      <span aria-hidden="true">{item.icon}</span>
                      <span>{item.label}</span>
                    </NavLink>
                  </li>
                ))}
              </ul>
            </React.Fragment>
          ))}
        </nav>

        <main id="main-content" className="main-content" tabIndex={-1}>
          {children}
        </main>
      </div>

      <ModalDialog
        open={searchOpen}
        title={`Tenant Search Results: "${searchResults?.query || ""}"`}
        onClose={() => setSearchOpen(false)}
      >
        {searchResults && (
          <div className="form-stack">
            <div>
              <h3 className="card-title">Assets ({searchResults.assets.length})</h3>
              {searchResults.assets.length === 0 ? (
                <p style={{ color: "var(--text-muted)" }}>No matching assets in active tenant.</p>
              ) : (
                <ul>
                  {searchResults.assets.map((a) => (
                    <li key={a.id}>
                      <Link to="/assets" onClick={() => setSearchOpen(false)}>
                        {a.display_name} (<code className="mono">{a.canonical_key}</code>) —{" "}
                        {a.criticality}
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </div>
            <div>
              <h3 className="card-title">Identities ({searchResults.identities.length})</h3>
              {searchResults.identities.length === 0 ? (
                <p style={{ color: "var(--text-muted)" }}>No matching identities.</p>
              ) : (
                <ul>
                  {searchResults.identities.map((i) => (
                    <li key={i.id}>
                      <Link to="/identities" onClick={() => setSearchOpen(false)}>
                        {i.display_name} (<code className="mono">{i.principal_name}</code>)
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </div>
            <div>
              <h3 className="card-title">Attack Paths ({searchResults.paths.length})</h3>
              {searchResults.paths.length === 0 ? (
                <p style={{ color: "var(--text-muted)" }}>No matching paths.</p>
              ) : (
                <ul>
                  {searchResults.paths.map((p) => (
                    <li key={p.id}>
                      <Link to={`/paths/${p.id}`} onClick={() => setSearchOpen(false)}>
                        {p.title} (Score: {p.priority_score})
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        )}
      </ModalDialog>
    </div>
  );
};
