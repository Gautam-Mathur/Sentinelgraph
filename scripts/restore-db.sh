#!/usr/bin/env bash
set -euo pipefail

# SentinelGraph PostgreSQL Restore & Security Controls Verification Script

if [ "${#}" -lt 1 ]; then
  echo "Usage: $0 <path-to-backup.dump> [target-db-name]" >&2
  exit 2
fi

DUMP_FILE="$1"
TARGET_DB="${2:-${POSTGRES_DB:-sentinelgraph}}"
DB_USER="${POSTGRES_USER:-postgres}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [ ! -f "${DUMP_FILE}" ]; then
  echo "[restore] Error: dump file not found: ${DUMP_FILE}" >&2
  exit 1
fi

if [ -f "${DUMP_FILE}.sha256" ]; then
  echo "[restore] Verifying SHA-256 checksum..."
  sha256sum -c "${DUMP_FILE}.sha256"
fi

run_psql() {
  if command -v docker >/dev/null 2>&1 && docker compose -f "${REPO_ROOT}/docker-compose.yml" ps --status running postgres >/dev/null 2>&1; then
    docker compose -f "${REPO_ROOT}/docker-compose.yml" exec -T postgres psql -U "${DB_USER}" -d "${TARGET_DB}" -Atc "$1"
  else
    psql -h "${PGHOST:-localhost}" -p "${PGPORT:-5432}" -U "${DB_USER}" -d "${TARGET_DB}" -Atc "$1"
  fi
}

echo "[restore] Restoring ${DUMP_FILE} into database '${TARGET_DB}'..."
if command -v docker >/dev/null 2>&1 && docker compose -f "${REPO_ROOT}/docker-compose.yml" ps --status running postgres >/dev/null 2>&1; then
  docker compose -f "${REPO_ROOT}/docker-compose.yml" exec -T postgres \
    pg_restore -U "${DB_USER}" -d "${TARGET_DB}" --clean --if-exists --no-owner < "${DUMP_FILE}"
else
  pg_restore -h "${PGHOST:-localhost}" -p "${PGPORT:-5432}" -U "${DB_USER}" -d "${TARGET_DB}" \
    --clean --if-exists --no-owner "${DUMP_FILE}"
fi

echo "[restore] Verifying database security invariants..."
NOBYPASS="$(run_psql "SELECT rolbypassrls FROM pg_roles WHERE rolname = 'sentinelgraph_app';")"
if [ "${NOBYPASS}" != "f" ]; then
  echo "[restore] ERROR: sentinelgraph_app rolbypassrls=${NOBYPASS} (expected f)" >&2
  exit 1
fi

RLS_COUNT="$(run_psql "SELECT count(*) FROM pg_tables WHERE schemaname='public' AND rowsecurity=true;")"
if [ "${RLS_COUNT}" -lt 10 ]; then
  echo "[restore] ERROR: expected >=10 RLS-protected tables, found ${RLS_COUNT}" >&2
  exit 1
fi

IMMUT_TRIGGER="$(run_psql "SELECT count(*) FROM pg_trigger WHERE tgname='trg_audit_events_immutable';")"
if [ "${IMMUT_TRIGGER}" != "1" ]; then
  echo "[restore] ERROR: audit_events immutability trigger missing after restore" >&2
  exit 1
fi

echo "[restore] Restore verified successfully (NOBYPASSRLS=true, RLS tables=${RLS_COUNT}, audit trigger intact)."
