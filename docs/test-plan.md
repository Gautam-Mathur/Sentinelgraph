# Test Plan & Verification Matrix

## Verification Layers

| Layer | Directory | Target Scope & Pass Criteria |
| :--- | :--- | :--- |
| **Unit Tests** | `tests/unit/` | Adapters (`nmap_xml`, `network_topology`, `identity_export`, `vuln_scanner`), domain relationship matrix, scoring `v1.0.0`, graph traversal, sandbox remediation simulation, property invariants |
| **Integration & Security Tests** | `tests/integration/` | Full end-to-end API workflow (`upload -> approve -> commit -> build graph -> generate paths -> simulate -> validate -> report`), cross-tenant IDOR + PostgreSQL RLS SQL enforcement, 6-role RBAC matrix, immutable audit trigger + hash chain, worker shell injection & revocation, XSS/SQLi/mass-assignment |
| **Performance Baseline** | `tests/performance/` | Scale benchmark harness verifying target throughput on dense multi-hop graphs and bounded traversal latency |
| **Browser End-to-End Tests** | `tests/e2e/` | Playwright Chromium headless verification against live backend + frontend covering login, KPI dashboard, graph canvas, path explainability, remediation planner, report preview, audit trail, zero console/page errors |
| **Frontend Static Gates** | `frontend/` | `tsc --noEmit`, `eslint src`, `vite build` |

---

## Execution Commands

```bash
# 1. Start backing services
docker compose up -d postgres redis

# 2. Apply schema & seed synthetic demo tenants
cd backend
python3 -m alembic upgrade head
python3 -m app.seed

# 3. Execute Python suites
pytest ../tests/unit ../tests/integration ../tests/performance -v
pytest ../tests/e2e -v

# 4. Execute Frontend checks
cd ../frontend
npm run typecheck && npm run lint && npm run build
```
