#!/usr/bin/env bash
set -euo pipefail

# SentinelGraph PostgreSQL Custom-Format Backup Script
# Uses privileged 'postgres' role so FORCE ROW LEVEL SECURITY does not truncate cross-tenant tables.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BACKUP_DIR="${BACKUP_DIR:-${REPO_ROOT}/backups}"
DB_NAME="${POSTGRES_DB:-sentinelgraph}"
DB_USER="${POSTGRES_USER:-postgres}"
TIMESTAMP="$(date -u +%Y%m%d_%H%M%SZ)"
OUT_FILE="${1:-${BACKUP_DIR}/sentinelgraph_${TIMESTAMP}.dump}"

mkdir -p "$(dirname "${OUT_FILE}")"

echo "[backup] Creating custom-format PostgreSQL dump -> ${OUT_FILE}"
if command -v docker >/dev/null 2>&1 && docker compose -f "${REPO_ROOT}/docker-compose.yml" ps --status running postgres >/dev/null 2>&1; then
  docker compose -f "${REPO_ROOT}/docker-compose.yml" exec -T postgres \
    pg_dump -U "${DB_USER}" -d "${DB_NAME}" -Fc --no-owner > "${OUT_FILE}"
else
  PGHOST="${PGHOST:-localhost}"
  PGPORT="${PGPORT:-5432}"
  export PGHOST PGPORT
  pg_dump -U "${DB_USER}" -d "${DB_NAME}" -Fc --no-owner > "${OUT_FILE}"
fi

sha256sum "${OUT_FILE}" > "${OUT_FILE}.sha256"
echo "[backup] Backup complete ($(wc -c < "${OUT_FILE}") bytes)"
echo "[backup] SHA-256 manifest: ${OUT_FILE}.sha256"
