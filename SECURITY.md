# Security Policy

## Product Safety Boundaries

SentinelGraph is an **authorised, evidence-driven attack-path analysis and remediation prioritisation platform**. It explicitly prohibits and does not implement:
- Exploit execution, payload generation, or credential theft/spraying
- Stealth, persistence, or autonomous lateral movement
- Unauthorised internet-wide scanning or live Nmap invocation from web requests
- Automatic mutation of target infrastructure or cloud/directory environments

Every assessment requires an explicit tenant, approved CIDR/host scope, authorised operator, assessment time window, and source provenance.

## Trust Zone Controls

1. **Tenant Isolation**: Service-layer membership enforcement paired with PostgreSQL Row-Level Security (`FORCE ROW LEVEL SECURITY` under non-superuser `sentinelgraph_app`). Cross-tenant lookups return uniform `404 Not Found`.
2. **Parser Hardening**: Nmap XML parsing uses `defusedxml` with DTD/entity expansion disabled, strict upload size limits (`MAX_IMPORT_BYTES`), MIME sniffing, extension checks, and an explicit script allowlist.
3. **Audit Integrity**: Append-only `audit_events` table protected by PostgreSQL triggers blocking `UPDATE`/`DELETE` and linked via a per-tenant SHA-256 hash chain.
4. **Secret Handling**: Password hashes, session tokens, and private keys are rejected on identity ingestion. Connector credentials are encrypted at rest via Fernet (or external Secrets Manager in production) and redacted in logs.
5. **Output Escaping**: HTML reports strictly escape all user-supplied and ingested strings via Jinja2 autoescaping and clearly watermark synthetic/demo datasets.

## Reporting Vulnerabilities

Please do not open public issues for security vulnerabilities. Report suspected security flaws confidentially to the platform security maintainers with reproduction steps, impact assessment, and affected version.
