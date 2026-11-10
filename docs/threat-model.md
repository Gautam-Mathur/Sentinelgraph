# Threat Model & Security Controls

## Assets Protected

1. Tenant infrastructure topologies, host inventories, exposed port maps, and vulnerability postures.
2. Identity/group privilege hierarchies and service account associations.
3. Immutable audit trail proving who authorised, uploaded, suppressed, simulated, and exported data.
4. MultiFernet encryption keys, JWT signing keys, and credential hashes.

---

## Trust Boundaries

1. **Client → API Boundary:** Untrusted HTTP requests, file uploads, query filters, and JSON bodies.
2. **API / Worker → PostgreSQL Boundary:** Privileged DDL (`postgres` migration role) vs restricted runtime (`sentinelgraph_app` with `NOBYPASSRLS`).
3. **Upload → Parser Boundary:** External XML/JSON artefacts potentially containing XXE, billion laughs, huge payloads, or secret leaks.
4. **Stored Evidence → HTML Report / Browser Boundary:** Potentially malicious service banners or hostnames rendered into browser DOM/HTML.

---

## Abuse Cases & Concrete Mitigations

| ID | Threat / Abuse Case | Mitigation Implemented | Verification Test |
| :--- | :--- | :--- | :--- |
| **TM-01** | Cross-tenant IDOR across UUID endpoints (`/assets/{id}`, `/paths/{id}`, etc.) | Explicit `tenant_id == ctx.tenant_id` filtering + PostgreSQL `FORCE ROW LEVEL SECURITY` under `sentinelgraph_app`; cross-tenant lookups return `404 Not Found` | `test_tenant_isolation_idor.py` |
| **TM-02** | DB pool GUC loss or superuser bypassing RLS | Dedicated `NOBYPASSRLS` DB role + SQLAlchemy `after_begin` session listener calling `set_config(..., is_local => true)` per transaction | `test_tenant_isolation_idor.py` (direct SQL check) |
| **TM-03** | XXE & XML entity expansion bomb in Nmap uploads | `defusedxml.ElementTree.fromstring(..., forbid_dtd=True, forbid_entities=True, forbid_external=True)`, 25 MB upload cap, extension & MIME verification | `test_nmap_adapter.py` |
| **TM-04** | Password/NTLM/private-key exfiltration inside identity exports | Recursive deep key blocker rejecting `password`, `password_hash`, `ntlm_hash`, `token`, `secret`, `private_key`, etc. | `test_other_adapters.py` |
| **TM-05** | Stored XSS via malicious hostname/service banner in HTML reports & UI | Jinja2 `autoescape=True`, React text interpolation, `<iframe sandbox="" srcDoc=...>` preview, `X-Content-Type-Options: nosniff` | `test_security_controls.py` |
| **TM-06** | Mass assignment privilege escalation (`role=tenant_admin` in create payload) | Pydantic `ConfigDict(extra="forbid")` on all request models; RBAC checks via server-side `Membership` join | `test_permissions_rbac.py`, `test_security_controls.py` |
| **TM-07** | Shell command injection via background worker job payloads | Strict Pydantic job payload models rejecting shell keys (`cmd`, `shell`, `exec`) and shell metacharacters; membership re-checked before execution | `test_worker_jobs.py` |
| **TM-08** | Tampering or deleting compliance audit records | PostgreSQL trigger `trg_audit_events_immutable` blocking `UPDATE`/`DELETE` + SHA-256 chained `prev_hash` / `event_hash` | `test_audit_and_provenance.py` |
| **TM-09** | Ingestion without scope approval | Assessments require `approve-scope` before non-draft operations; out-of-scope CIDRs/domains flagged in import preview warnings | `test_api_workflow.py` |
| **TM-10** | Secret/bearer token leakage in logs | Custom JSON formatter redacting `Bearer ...`, JWTs, `secret`, `password`, `token` patterns | `test_security_controls.py` |

---

## Residual Risks (Documented)

- **Local Development Demo Accounts:** Enabled ONLY when `APP_ENV in {"development", "test", "local"}`; `APP_ENV=production` refuses local password auth and refuses to run `app.seed`.
- **Single-Region Deployment Assumption:** High-availability PostgreSQL replication and external KMS/HSM secret backends are deferred to infrastructure deployment configuration.
