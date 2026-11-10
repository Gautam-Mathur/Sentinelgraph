import csv
import io
import json
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

from app.core.config import get_settings
from app.db.models import AuditEvent
from app.db.session import SessionLocal, set_rls_context


def test_audit_events_append_only_trigger_blocks_update_and_delete(
    client: TestClient,
    acme_admin_headers: dict[str, str],
) -> None:
    events = client.get("/api/v1/audit?limit=10", headers=acme_admin_headers).json()["items"]
    assert len(events) >= 2
    target_id = uuid.UUID(events[0]["id"])
    acme_tid = uuid.UUID(acme_admin_headers["X-Tenant-ID"])

    # Verify via sentinelgraph_app role
    with SessionLocal() as db:
        set_rls_context(db, tenant_id=acme_tid)
        with pytest.raises(DBAPIError, match="append-only"):
            db.execute(
                text("UPDATE audit_events SET action = 'tampered' WHERE id = :id"),
                {"id": target_id},
            )
            db.commit()
        db.rollback()

        set_rls_context(db, tenant_id=acme_tid)
        with pytest.raises(DBAPIError, match="append-only"):
            db.execute(
                text("DELETE FROM audit_events WHERE id = :id"),
                {"id": target_id},
            )
            db.commit()
        db.rollback()

    # Even database admin role cannot mutate audit_events directly (trigger fires for all roles)
    admin_engine = create_engine(get_settings().database_admin_url, future=True)
    try:
        with admin_engine.begin() as conn, pytest.raises(DBAPIError, match="append-only"):
            conn.execute(
                text("DELETE FROM audit_events WHERE id = :id"),
                {"id": target_id},
            )
    finally:
        admin_engine.dispose()


def test_audit_hash_chain_and_exports(
    client: TestClient,
    acme_admin_headers: dict[str, str],
) -> None:
    # Create an isolated disposable tenant so the full chain from GENESIS is clean and linear
    slug = f"audit-{uuid.uuid4().hex[:8]}"
    res_ten = client.post(
        "/api/v1/tenants",
        headers=acme_admin_headers,
        json={"name": "Audit Chain Tenant", "slug": slug, "is_demo": True},
    )
    assert res_ten.status_code == 201
    tid = res_ten.json()["id"]
    sw = client.post(
        "/api/v1/auth/switch-tenant",
        headers=acme_admin_headers,
        json={"tenant_id": tid},
    ).json()
    h = {"Authorization": f"Bearer {sw['access_token']}", "X-Tenant-ID": tid}

    # Trigger a couple of auditable writes in order
    assert (
        client.post(
            "/api/v1/assets",
            headers=h,
            json={"canonical_key": "host:10.99.1.1", "display_name": "audit-host-1", "asset_type": "server"},
        ).status_code
        == 201
    )
    assert (
        client.post(
            "/api/v1/assets",
            headers=h,
            json={"canonical_key": "host:10.99.1.2", "display_name": "audit-host-2", "asset_type": "server"},
        ).status_code
        == 201
    )

    with SessionLocal() as db:
        set_rls_context(db, tenant_id=uuid.UUID(tid))
        from sqlalchemy import select

        rows = list(
            db.execute(
                select(AuditEvent)
                .where(AuditEvent.tenant_id == uuid.UUID(tid))
                .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
            ).scalars()
        )
        assert len(rows) >= 3
        assert rows[0].prev_hash == "0" * 64
        for idx in range(1, len(rows)):
            assert len(rows[idx].event_hash) == 64
            assert rows[idx].prev_hash == rows[idx - 1].event_hash

    # Verify JSON & CSV exports
    exp_json = client.get("/api/v1/audit/export?format=json", headers=h)
    assert exp_json.status_code == 200
    parsed = json.loads(exp_json.text)
    assert len(parsed) >= 3
    assert "event_hash" in parsed[0]

    exp_csv = client.get("/api/v1/audit/export?format=csv", headers=h)
    assert exp_csv.status_code == 200
    reader = list(csv.reader(io.StringIO(exp_csv.text)))
    assert reader[0][-2:] == ["prev_hash", "event_hash"]
    assert len(reader) >= 5


def test_relationship_suppression_preserves_provenance_and_removes_from_paths(
    client: TestClient,
    acme_admin_headers: dict[str, str],
) -> None:
    slug = f"prov-{uuid.uuid4().hex[:8]}"
    res_ten = client.post(
        "/api/v1/tenants",
        headers=acme_admin_headers,
        json={"name": "Provenance Tenant", "slug": slug, "is_demo": True},
    ).json()
    tid = res_ten["id"]
    sw = client.post(
        "/api/v1/auth/switch-tenant",
        headers=acme_admin_headers,
        json={"tenant_id": tid},
    ).json()
    h = {"Authorization": f"Bearer {sw['access_token']}", "X-Tenant-ID": tid}

    from datetime import UTC, datetime, timedelta

    now = datetime.now(UTC)
    assess = client.post(
        "/api/v1/assessments",
        headers=h,
        json={
            "name": "Suppression Assessment",
            "approved_scope_cidrs": ["10.50.0.0/16"],
            "time_window_start": (now - timedelta(hours=1)).isoformat(),
            "time_window_end": (now + timedelta(days=2)).isoformat(),
            "is_synthetic": True,
        },
    ).json()
    aid = assess["id"]
    assert client.post(f"/api/v1/assessments/{aid}/approve-scope", headers=h).status_code == 200

    entry = client.post(
        "/api/v1/assets",
        headers=h,
        json={
            "canonical_key": "host:10.50.0.1",
            "display_name": "entry-gw",
            "asset_type": "server",
            "is_external_entry": True,
        },
    ).json()
    crown = client.post(
        "/api/v1/assets",
        headers=h,
        json={
            "canonical_key": "host:10.50.0.2",
            "display_name": "crown-vault",
            "asset_type": "database",
            "criticality": "critical",
            "is_crown_jewel": True,
        },
    ).json()

    rel = client.post(
        "/api/v1/relationships",
        headers=h,
        json={
            "assessment_id": aid,
            "source_kind": "asset",
            "source_id": entry["id"],
            "target_kind": "asset",
            "target_id": crown["id"],
            "relation_type": "CONNECTS_TO",
            "fact_kind": "analyst_assertion",
            "confidence": 0.9,
        },
    ).json()
    rel_id = rel["id"]
    original_prov = rel["provenance"]

    # Baseline build + generate sees 1 path
    assert client.post(f"/api/v1/assessments/{aid}/build-graph", headers=h).status_code == 200
    gen1 = client.post(
        "/api/v1/paths/generate",
        headers=h,
        json={"assessment_id": aid, "algorithm": "dijkstra"},
    ).json()
    assert gen1["paths_count"] == 1

    # Suppress relationship -> provenance remains intact, graph excludes edge, paths = 0
    sup = client.post(
        f"/api/v1/relationships/{rel_id}/suppress",
        headers=h,
        json={"suppressed": True, "reason": "Firewall ACL denies flow"},
    )
    assert sup.status_code == 200
    assert sup.json()["is_suppressed"] is True
    assert sup.json()["provenance"] == original_prov

    bg2 = client.post(f"/api/v1/assessments/{aid}/build-graph", headers=h).json()
    assert bg2["stats"]["suppressed_edge_count"] == 1
    assert bg2["stats"]["edge_count"] == 0

    gen2 = client.post(
        "/api/v1/paths/generate",
        headers=h,
        json={"assessment_id": aid, "algorithm": "dijkstra"},
    ).json()
    assert gen2["paths_count"] == 0

    # Restore relationship -> path returns
    rest = client.post(
        f"/api/v1/relationships/{rel_id}/suppress",
        headers=h,
        json={"suppressed": False, "reason": "Re-enabled for re-evaluation"},
    )
    assert rest.status_code == 200
    assert rest.json()["is_suppressed"] is False
    gen3 = client.post(
        "/api/v1/paths/generate",
        headers=h,
        json={"assessment_id": aid, "algorithm": "dijkstra"},
    ).json()
    assert gen3["paths_count"] == 1
