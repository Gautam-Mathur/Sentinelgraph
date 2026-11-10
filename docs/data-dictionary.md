# SentinelGraph Data Dictionary

All tenant-owned tables below enforce PostgreSQL `FORCE ROW LEVEL SECURITY` scoped by `app.current_tenant_id` (`sentinelgraph_app` runtime role has `NOBYPASSRLS`).

## Core Governance & Identity Tables

| Table | Purpose | Key Columns & Provenance Notes |
| :--- | :--- | :--- |
| `tenants` | Organisation isolation boundary | `id` (UUID), `slug`, `name`, `is_demo` |
| `users` | Platform operators | `id`, `email`, `display_name`, `auth_provider`, `password_hash` (Argon2id), `mfa_enabled` |
| `roles` | Built-in RBAC roles (`6` roles) | `name` (`tenant_admin`, `assessor`, `analyst`, `remediation_owner`, `auditor`, `read_only`), `permissions` |
| `memberships` | Tenant-scoped user role binding | `tenant_id`, `user_id`, `role_id`, `status`; RLS policy permits read by member user during tenant resolution |
| `data_sources` | Configured evidence connectors | `tenant_id`, `source_type`, `encrypted_secret` (MultiFernet at rest), `config_metadata` |
| `audit_events` | Tamper-evident compliance log | Append-only DB trigger `trg_audit_events_immutable` blocks `UPDATE`/`DELETE`; SHA-256 chain (`prev_hash`, `event_hash`) |
| `retention_policies` | Retention schedules per data class | `tenant_id`, `data_class`, `retention_days`, `lawful_basis` |
| `retention_requests` | GDPR export/deletion workflow log | `tenant_id`, `request_type`, `data_class`, `status`, `details` |

---

## Inventory, Observations & Provenance Tables

| Table | Purpose | Key Columns & Provenance Notes |
| :--- | :--- | :--- |
| `assessments` | Authorised analysis engagement | `approved_scope_cidrs`, `time_window_start`, `time_window_end`, `status` (`draft` → `approved` → `graph_built`), `graph_stats` |
| `imports` | Staged file ingestion & validation | `source_format`, `parser_version`, `file_sha256`, `status` (`staged`/`approved`/`rejected`/`committed`), `idempotency_key`, `preview_summary` |
| `assets` | Normalised compute/network/app nodes | `canonical_key`, `asset_type`, `environment`, `criticality`, `is_external_entry`, `is_crown_jewel`, `source_refs` (JSONB provenance) |
| `asset_addresses` | IPv4, IPv6, MAC, hostname, CIDR mappings | Unique per `(tenant_id, asset_id, address_type, value)` |
| `services` | Listening ports/banners per asset | `port`, `protocol`, `state`, `product`, `version`, `banner_raw`, `analyst_corrected_product`, `analyst_corrected_version`, `provenance` |
| `identities` | Users, service/workload/role accounts | Never stores secret tokens or password hashes (`identity_type`, `privilege_level`, `privilege_indicators`, `source_refs`) |
| `groups` | Security groups & directory roles | `external_id`, `provider`, `group_type`, `privilege_indicators`, `source_refs` |
| `observations` | Raw timestamped source records | `source_product`, `source_record_id`, `evidence_hash`, `collection_time`, `suppressed_at` |
| `relationships` | Domain-validated graph edges | `source_kind`/`id`, `target_kind`/`id`, `relation_type` (10 allowed enums), `fact_kind` (`observed_fact` / `inferred_relationship` / `analyst_assertion`), `confidence`, `valid_from`, `valid_to`, `is_suppressed`, `provenance` |
| `findings` | CVE observations (NOT verified exploits) | `cve_id`, `severity`, `cvss_score`, `affected_component`, `status`, `evidence` (`exploitability_proven=false`) |

---

## Analysis, Simulation & Reporting Tables

| Table | Purpose | Key Columns & Provenance Notes |
| :--- | :--- | :--- |
| `attack_paths` | Ranked plausible traversal paths | `algorithm`, `scoring_version` (`v1.0.0`), `priority_score`, factor breakdown, `is_truncated`, `assumptions`, `explanation_narrative`, `explanation_trace`, `determinism_hash` |
| `path_steps` | Ordered step edges within a path | `step_order`, `relationship_id`, `fact_kind`, `confidence`, `preconditions`, `assumptions`, `evidence_refs` |
| `remediation_actions` | Isolated sandbox transform plans | `transforms`, `baseline_metrics`, `modelled_metrics`, `delta_summary`, `is_modelled_only`, `validation_assessment_id`, `validation_result` |
| `reports` | Generated HTML compliance/tech reports | `title`, `report_format` (`html`), `is_synthetic_watermarked`, `scoring_version`, `html_content` (auto-escaped Jinja2) |
| `jobs` | Async worker execution records | `job_type` (`build_graph`/`generate_paths`/`generate_report`), `status`, `progress`, `attempts`, `payload`, `result` |

---

## Controlled Domain Enumerations

- **AssetType:** `host`, `endpoint`, `server`, `cloud_resource`, `application`, `database`, `network_device`, `identity_provider`
- **IdentityType:** `human_user`, `service_account`, `machine_identity`, `workload_identity`, `role_identity`
- **RelationType (`10`):** `HOSTS`, `CONNECTS_TO`, `RUNS_SERVICE`, `EXPOSES`, `DEPENDS_ON`, `MEMBER_OF`, `HAS_ROLE`, `CAN_ADMINISTER`, `TRUSTS`, `OWNS`
- **FactKind (`3`):** `observed_fact`, `inferred_relationship`, `analyst_assertion`
