# Backup, Restore & Disaster Recovery Runbook

## Recovery Objectives (Reference Targets)

- **RPO (Recovery Point Objective):** ≤ 15 minutes with WAL archiving / continuous PITR in PostgreSQL.
- **RTO (Recovery Time Objective):** ≤ 60 minutes for API, Redis queue, and PostgreSQL primary restore.

---

## Database Backup Procedure (PostgreSQL)

Always back up using a privileged administrative/backup role (`postgres`), NEVER the restricted `sentinelgraph_app` runtime role, because `FORCE ROW LEVEL SECURITY` intentionally blocks unrestricted cross-tenant dumps for the app role.

```bash
# Logical backup compressed with custom format
docker compose exec -T postgres pg_dump -U postgres -d sentinelgraph -Fc > sentinelgraph_$(date +%Y%m%d_%H%M%S).dump

# Encrypt archive at rest before off-site transfer (e.g. age / KMS envelope)
```

---

## Verification & Restore Procedure

1. Restore into an isolated scratch PostgreSQL instance before promoting:
   ```bash
   createdb -U postgres sentinelgraph_restore_verify
   pg_restore -U postgres -d sentinelgraph_restore_verify --no-owner sentinelgraph_backup.dump
   ```
2. Verify schema controls remain intact after restore:
   - Confirm `sentinelgraph_app` still has `NOBYPASSRLS`.
   - Confirm `pg_tables.rowsecurity = true` across all tenant-scoped tables.
   - Confirm `trg_audit_events_immutable` trigger exists on `audit_events`.
   - Run an integrity check over `audit_events` hash chains (`prev_hash -> event_hash`).
3. Do NOT treat Redis as durable storage: Redis strictly holds ephemeral RQ job dispatch state; source-of-truth job metadata resides in PostgreSQL `jobs` table.
