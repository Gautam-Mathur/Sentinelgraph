# SentinelGraph Architecture

## Design Paradigm

SentinelGraph uses a **Modular Monolith + Isolated Worker Queue** architecture prioritising strict tenant isolation, deterministic graph analysis, and clean separation of pure domain logic from I/O adapters and HTTP controllers.

```
backend/app/
  ├── api/        FastAPI controllers, JWT/tenant context extraction, request validation
  ├── core/       Config, ErrorEnvelope, Argon2/JWT/MultiFernet security, JSON logging, OTel
  ├── db/         SQLAlchemy models & session management (after_begin RLS context binding)
  ├── domain/     Pure Python + NetworkX graph engine, relationship matrix, scoring v1.0.0,
  │               step semantics, and sandbox remediation simulation (zero HTTP/DB imports)
  ├── adapters/   Untrusted input parsers (defusedxml Nmap XML, topology/identity/vuln JSON)
  ├── services/   Transaction orchestration, staged imports, RBAC enforcement, audit hashing
  └── workers/    Redis/RQ background jobs (shell-free typed Pydantic payloads + re-auth check)
```

---

## System Topology & Trust Zones

```mermaid
flowchart LR
    subgraph ZoneA["Zone A: Untrusted Client & Browser"]
        UI["React + Vite + Cytoscape SPA\nSandboxed iframe reports"]
        Files["Evidence Files\nNmap XML / JSON exports"]
    end

    subgraph ZoneB["Zone B: Application DMZ"]
        NGINX["Nginx Reverse Proxy\nTLS / Security Headers"]
        API["FastAPI Modular Monolith\nJWT + X-Tenant-ID + RBAC"]
    end

    subgraph ZoneC["Zone C: Pure Compute & Worker Sandbox"]
        Adapters["Hardened Parsers\ndefusedxml + schema checks"]
        Graph["NetworkX Engine & Sandbox\nDijkstra/BFS + SCC + Scoring v1.0.0"]
        Worker["RQ Async Worker\nActor re-validation before run"]
    end

    subgraph ZoneD["Zone D: Persistent Storage"]
        PG["PostgreSQL 16\nsentinelgraph_app (NOBYPASSRLS)\nFORCE RLS + Immutable Audit Trigger"]
        Redis["Redis 7\nJob Queue Broker"]
    end

    UI -->|HTTPS / JSON| NGINX --> API
    Files -->|Multipart Stage| API --> Adapters
    API --> Graph
    API -->|Job Envelope| Redis --> Worker --> Graph
    API -->|SET LOCAL tenant_id| PG
    Worker -->|SET LOCAL tenant_id| PG
```

---

## Explicitly Enforced MVP Boundaries

| Capability | MVP Status | Enforcement |
| :--- | :--- | :--- |
| Live Nmap execution from API/UI | **Excluded** | No subprocess calls to `nmap`; file upload ingestion only |
| Direct cloud connectors (AWS/Azure/GCP/MS Graph) | **Phase 2 Stub** | Catalog displays `enabled_in_mvp: false`; no outbound polling |
| Graph database (Neo4j / Memgraph) | **Excluded** | Relational persistence in PostgreSQL + on-demand `NetworkX` MultiDiGraph |
| PDF / XLSX exports | **Excluded** | Auto-escaped HTML reports (`text/html`) rendered in sandboxed iframe |
| Autonomous exploit verification | **Prohibited** | Findings explicitly flagged `exploitability_proven: false` |
