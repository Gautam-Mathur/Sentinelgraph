# Release Notes — SentinelGraph

## v1.1.0 (Production-Readiness Upgrades)

**Release Date:** 2026-11-10

### New Capabilities

- **Enterprise Identity & Token Lifecycle:**
  - Added full OIDC Authorization Code + PKCE (`S256`) login & callback endpoints (`/auth/oidc/login`, `/auth/oidc/callback`, frontend `/auth/callback` route) with state/nonce replay protection and asymmetric RS/ES JWKS signature verification.
  - Added refresh token rotation (`/auth/refresh`), explicit JWT `jti` revocation (`/auth/logout`), password rotation (`/auth/change-password`), tenant member provisioning (`POST /tenants/members`), and member suspend/reactivate with `LAST_ADMIN_PROTECTED` guard.
- **Additional Offline Enterprise Ingestion Adapters:**
  - Added `nessus_xml` (`.nessus` via `defusedxml`), `sarif_json` (SARIF v2.1.0 & Trivy JSON), `bloodhound_json` (SharpHound/BloodHound offline exports), and `aws_iam_export_json` (offline AWS IAM & Security Group JSON snapshots).
  - Live external cloud polling (`aws_config`, etc.) remains strictly disabled (`422 PHASE2_CONNECTOR_DISABLED`).
- **Analyst Triage, Inventory Lifecycle & Multi-Format Exports:**
  - Added searchable Findings Explorer & Triage (`/api/v1/findings`, `PATCH /findings/{id}`, `/findings` UI).
  - Added Asset & Identity editing, classification, and soft-retirement (`PATCH /assets/{id}`, `PATCH /identities/{id}`).
  - Added JSON, CSV (with formula-injection neutralisation), and SARIF v2.1.0 report download formats (`/reports/{id}/download?format=html|json|csv|sarif`).
  - Added Background Worker Jobs Console (`/jobs` UI with semantic `<progress>` tracking and RQ enqueue triggers across assessments, paths, reports, and retention).
- **Governance, Webhooks, Rate Limiting & Operations:**
  - Added full retention deletion classes (`observations`, `reports`, `assessments`) plus `POST /retention/enforce` and RQ worker `enforce_retention`.
  - Added SSRF-safe HMAC-SHA256 signed outbound webhooks (`/api/v1/webhooks`) triggered on high-risk attack paths or manual test pings.
  - Added fixed-window rate limiting (`429 RATE_LIMITED`), Prometheus metrics (`/api/v1/metrics/prometheus`), HTTP OTLP JSON span export, `S3StagingStorage`, `infra/nginx/nginx.tls.conf`, `scripts/backup-db.sh`, `scripts/restore-db.sh`, `backend/requirements-dev.txt`, and `.github/workflows/ci.yml`.

---

## v1.0.0 (Initial MVP Baseline)

### Highlights

- Initial complete release of the **SentinelGraph Enterprise Attack-Path Intelligence Engine**.
- Implemented PostgreSQL Row-Level Security (`FORCE ROW LEVEL SECURITY`) with `sentinelgraph_app` (`NOBYPASSRLS`) and SQLAlchemy per-transaction `after_begin` context binding.
- Implemented hardened offline ingestion adapters (`nmap_xml` via `defusedxml`, `network_topology_json`, `identity_json`, `vulnerability_json`, `relationship_json`) with two-step staged preview, approval, and idempotent commit.
- Implemented pure Python + NetworkX graph compilation, BFS & Dijkstra traversal, Tarjan SCC cycles, bridge centrality scoring, deterministic `v1.0.0` priority ranking, and step-by-step explainability traces.
- Built isolated sandbox remediation simulation (`remove_relationship`, `downgrade_relationship`, `disable_role`, `segment_network`, `rotate_service_identity`, `patch_vulnerability`) and follow-up assessment validation.
- Delivered React + TypeScript + Cytoscape.js operational console adhering to high-contrast accessibility guidelines, tamper-evident hash-chained audit logs, and auto-escaped HTML reports.

---

## Explicit Security & Operational Boundaries

1. **No Live Network Scanning from UI/API:** Nmap/Nessus scans must be executed externally under approved change control and uploaded as XML exports.
2. **Offline Cloud/Directory Exports Only:** AWS Config, Azure Resource Graph, GCP Cloud Asset Inventory, and Microsoft Graph connectors are documented Phase 2 live connectors (`enabled_in_mvp=false`) and reject runtime polling. Offline AWS IAM/SG JSON snapshots (`aws_iam_export_json`) and BloodHound JSON (`bloodhound_json`) are supported cleanly offline.
3. **Modelled Plausibility Only:** Priority scores (0–100) reflect structural exposure, privilege leverage, and evidence confidence — NOT calibrated breach probability or proven exploitability.
