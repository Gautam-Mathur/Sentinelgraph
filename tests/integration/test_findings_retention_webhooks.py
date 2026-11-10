import hashlib
import hmac
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import update

from app.db.models import Identity, Report
from app.db.session import SessionLocal, set_rls_context
from app.services.context import ActorContext
from app.services.webhook_service import test_webhook_delivery as run_webhook_test_delivery

SAMPLE_DIR = Path(__file__).resolve().parents[2] / "sample-data"


def _create_isolated_tenant_headers(client: TestClient, acme_admin_headers: dict[str, str]) -> tuple[str, dict[str, str]]:
    slug = f"iso-{uuid.uuid4().hex[:8]}"
    res = client.post(
        "/api/v1/tenants",
        headers=acme_admin_headers,
        json={"name": f"Isolated {slug}", "slug": slug, "is_demo": True},
    )
    assert res.status_code == 201, res.text
    tid = res.json()["id"]
    sw = client.post(
        "/api/v1/auth/switch-tenant",
        headers=acme_admin_headers,
        json={"tenant_id": tid},
    ).json()
    return tid, {"Authorization": f"Bearer {sw['access_token']}", "X-Tenant-ID": tid}


def test_member_lifecycle_and_last_admin_protection(
    client: TestClient,
    acme_admin_headers: dict[str, str],
) -> None:
    _, th = _create_isolated_tenant_headers(client, acme_admin_headers)

    members = client.get("/api/v1/tenants/members", headers=th).json()["items"]
    assert len(members) == 1
    own_mid = members[0]["membership_id"]

    # Sole tenant_admin cannot be demoted or suspended
    demote_last = client.patch(
        f"/api/v1/tenants/members/{own_mid}",
        headers=th,
        json={"role": "analyst"},
    )
    assert demote_last.status_code == 409
    assert demote_last.json()["code"] == "LAST_ADMIN_PROTECTED"

    suspend_last = client.patch(
        f"/api/v1/tenants/members/{own_mid}",
        headers=th,
        json={"status": "suspended"},
    )
    assert suspend_last.status_code == 409
    assert suspend_last.json()["code"] == "LAST_ADMIN_PROTECTED"

    # Provision OIDC member
    email = f"oidc.member.{uuid.uuid4().hex[:6]}@corp.example"
    inv = client.post(
        "/api/v1/tenants/members",
        headers=th,
        json={
            "email": email,
            "display_name": "Invited OIDC Assessor",
            "role": "assessor",
            "auth_provider": "oidc",
        },
    )
    assert inv.status_code == 201, inv.text
    inv_id = inv.json()["membership_id"]

    dup = client.post(
        "/api/v1/tenants/members",
        headers=th,
        json={
            "email": email,
            "display_name": "Duplicate",
            "role": "analyst",
            "auth_provider": "oidc",
        },
    )
    assert dup.status_code == 409
    assert dup.json()["code"] == "MEMBERSHIP_EXISTS"

    # Suspend & reactivate secondary member works
    susp = client.patch(f"/api/v1/tenants/members/{inv_id}", headers=th, json={"status": "suspended"})
    assert susp.status_code == 200
    assert susp.json()["status"] == "suspended"

    react = client.patch(
        f"/api/v1/tenants/members/{inv_id}",
        headers=th,
        json={"status": "active", "role": "auditor"},
    )
    assert react.status_code == 200
    assert react.json()["status"] == "active"
    assert react.json()["role"] == "auditor"


def test_asset_and_identity_edit_and_retire(
    client: TestClient,
    acme_admin_headers: dict[str, str],
) -> None:
    _, th = _create_isolated_tenant_headers(client, acme_admin_headers)

    asset_res = client.post(
        "/api/v1/assets",
        headers=th,
        json={
            "canonical_key": "host:10.55.1.10",
            "display_name": "edge-gw-old",
            "asset_type": "server",
            "environment": "staging",
            "criticality": "low",
        },
    )
    assert asset_res.status_code == 201
    aid = asset_res.json()["id"]

    upd = client.patch(
        f"/api/v1/assets/{aid}",
        headers=th,
        json={
            "display_name": "edge-gw-prod",
            "environment": "prod",
            "criticality": "critical",
            "is_external_entry": True,
            "is_crown_jewel": True,
        },
    )
    assert upd.status_code == 200
    assert upd.json()["display_name"] == "edge-gw-prod"
    assert upd.json()["is_external_entry"] is True
    assert upd.json()["is_crown_jewel"] is True

    ret_asset = client.patch(f"/api/v1/assets/{aid}", headers=th, json={"retire": True})
    assert ret_asset.status_code == 200
    assert ret_asset.json()["retired"] is True
    assert client.get(f"/api/v1/assets/{aid}", headers=th).status_code == 404

    ident_res = client.post(
        "/api/v1/identities",
        headers=th,
        json={
            "identity_type": "service_account",
            "external_id": f"svc-{uuid.uuid4().hex[:6]}",
            "provider": "aws_iam",
            "display_name": "svc-etl",
            "principal_name": "arn:aws:iam::111122223333:role/etl",
            "privilege_level": "standard",
        },
    )
    assert ident_res.status_code == 201
    iid = ident_res.json()["id"]

    upd_id = client.patch(
        f"/api/v1/identities/{iid}",
        headers=th,
        json={"privilege_level": "privileged", "display_name": "svc-etl-priv"},
    )
    assert upd_id.status_code == 200
    assert upd_id.json()["privilege_level"] == "privileged"

    ret_id = client.patch(f"/api/v1/identities/{iid}", headers=th, json={"retire": True})
    assert ret_id.status_code == 200
    assert ret_id.json()["retired"] is True
    assert ret_id.json()["enabled"] is False
    assert client.get(f"/api/v1/identities/{iid}", headers=th).status_code == 404


def test_findings_nessus_ingest_triage_and_multi_format_csv_sarif_reports(
    client: TestClient,
    acme_admin_headers: dict[str, str],
    beta_admin_headers: dict[str, str],
) -> None:
    _, th = _create_isolated_tenant_headers(client, acme_admin_headers)
    now = datetime.now(UTC)

    assess = client.post(
        "/api/v1/assessments",
        headers=th,
        json={
            "name": "Nessus + Multi-Format Assessment",
            "approved_scope_cidrs": ["10.10.0.0/16", "lab.sentinelgraph.invalid"],
            "time_window_start": (now - timedelta(hours=1)).isoformat(),
            "time_window_end": (now + timedelta(days=5)).isoformat(),
            "is_synthetic": True,
        },
    ).json()
    aid = assess["id"]
    assert client.post(f"/api/v1/assessments/{aid}/approve-scope", headers=th).status_code == 200

    # Seed entry/crown assets where one display_name starts with '=' to test CSV formula neutralization
    entry = client.post(
        "/api/v1/assets",
        headers=th,
        json={
            "canonical_key": "host:10.10.2.20",
            "display_name": "=HYPERLINK(\"http://evil\",\"app-core-01\")",
            "asset_type": "server",
            "criticality": "high",
            "is_external_entry": True,
        },
    ).json()
    crown = client.post(
        "/api/v1/assets",
        headers=th,
        json={
            "canonical_key": "host:10.10.4.50",
            "display_name": "db-crown-01",
            "asset_type": "database",
            "criticality": "critical",
            "is_crown_jewel": True,
        },
    ).json()

    up = client.post(
        "/api/v1/imports",
        headers=th,
        data={"assessment_id": aid, "source_format": "nessus_xml"},
        files={"file": ("demo_nessus_scan.nessus", (SAMPLE_DIR / "demo_nessus_scan.nessus").read_bytes(), "application/xml")},
    )
    assert up.status_code == 201, up.text
    imp_id = up.json()["id"]
    assert client.post(f"/api/v1/imports/{imp_id}/approve", headers=th).status_code == 200
    assert client.post(f"/api/v1/imports/{imp_id}/commit", headers=th).status_code == 200

    # Add edge & build graph + path
    client.post(
        "/api/v1/relationships",
        headers=th,
        json={
            "assessment_id": aid,
            "source_kind": "asset",
            "source_id": entry["id"],
            "target_kind": "asset",
            "target_id": crown["id"],
            "relation_type": "CONNECTS_TO",
            "fact_kind": "observed_fact",
            "confidence": 0.9,
        },
    )
    assert client.post(f"/api/v1/assessments/{aid}/build-graph", headers=th).status_code == 200
    assert (
        client.post(
            "/api/v1/paths/generate",
            headers=th,
            json={"assessment_id": aid, "max_hops": 4, "top_k": 5},
        ).status_code
        == 200
    )

    # Findings filter & triage + cross-tenant protection
    f_list = client.get("/api/v1/findings?severity=critical", headers=th).json()["items"]
    assert len(f_list) >= 1
    target_f = f_list[0]
    assert target_f["cve_id"] == "CVE-2024-10979"
    assert target_f["exploitability_proven"] is False

    triaged = client.patch(
        f"/api/v1/findings/{target_f['id']}",
        headers=th,
        json={"status": "mitigated", "triage_note": "Applied PostgreSQL 15.9 hotfix"},
    )
    assert triaged.status_code == 200
    assert triaged.json()["status"] == "mitigated"
    assert triaged.json()["exploitability_proven"] is False
    assert triaged.json()["triaged_at"] is not None

    cross_tenant_triage = client.patch(
        f"/api/v1/findings/{target_f['id']}",
        headers=beta_admin_headers,
        json={"status": "false_positive"},
    )
    assert cross_tenant_triage.status_code == 404
    assert cross_tenant_triage.json()["code"] == "FINDING_NOT_FOUND"

    # Generate & download HTML, JSON, CSV (formula neutralized), and SARIF v2.1.0
    rep = client.post(
        "/api/v1/reports",
        headers=th,
        json={"assessment_id": aid, "title": "=SUM(1,2) Security Assessment"},
    ).json()
    rid = rep["id"]

    r_json = client.get(f"/api/v1/reports/{rid}/download?format=json", headers=th)
    assert r_json.status_code == 200
    j_doc = r_json.json()
    assert len(j_doc["findings"]) >= 2
    assert len(j_doc["attack_paths"]) >= 1

    r_csv = client.get(f"/api/v1/reports/{rid}/download?format=csv", headers=th)
    assert r_csv.status_code == 200
    assert "text/csv" in r_csv.headers["content-type"]
    # Leading '=' formula cell must be escaped with leading single quote
    assert "'=HYPERLINK" in r_csv.text

    r_sarif = client.get(f"/api/v1/reports/{rid}/download?format=sarif", headers=th)
    assert r_sarif.status_code == 200
    sarif = r_sarif.json()
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "SentinelGraph"
    assert len(sarif["runs"][0]["results"]) >= 3


def test_retention_enforce_delete_and_worker_job(
    client: TestClient,
    acme_admin_headers: dict[str, str],
) -> None:
    tid_str, th = _create_isolated_tenant_headers(client, acme_admin_headers)
    tid = uuid.UUID(tid_str)
    me = client.get("/api/v1/auth/me", headers=th).json()
    uid = uuid.UUID(me["user"]["id"])

    now = datetime.now(UTC)
    old_ts = now - timedelta(days=30)

    assess = client.post(
        "/api/v1/assessments",
        headers=th,
        json={
            "name": "Expired Assessment Test",
            "approved_scope_cidrs": ["10.90.0.0/16"],
            "time_window_start": (old_ts - timedelta(days=5)).isoformat(),
            "time_window_end": old_ts.isoformat(),
            "is_synthetic": True,
        },
    ).json()
    rep = client.post("/api/v1/reports", headers=th, json={"assessment_id": assess["id"]}).json()
    ident = client.post(
        "/api/v1/identities",
        headers=th,
        json={
            "identity_type": "human_user",
            "external_id": f"old-u-{uuid.uuid4().hex[:6]}",
            "provider": "lab",
            "display_name": "Old User",
            "principal_name": "old@lab.invalid",
        },
    ).json()

    # Backdate records cleanly inside RLS-scoped session so 7-day policy matches them
    with SessionLocal() as db:
        set_rls_context(db, tenant_id=tid, user_id=uid)
        db.execute(update(Report).where(Report.id == uuid.UUID(rep["id"])).values(created_at=old_ts))
        db.execute(update(Identity).where(Identity.id == uuid.UUID(ident["id"])).values(last_seen=old_ts))
        db.commit()

    assert (
        client.put(
            "/api/v1/retention/policies",
            headers=th,
            json={"data_class": "reports", "retention_days": 7, "lawful_basis": "minimization"},
        ).status_code
        == 200
    )
    assert (
        client.put(
            "/api/v1/retention/policies",
            headers=th,
            json={"data_class": "identities", "retention_days": 7, "lawful_basis": "minimization"},
        ).status_code
        == 200
    )

    # Dry run via worker job counts expired records without deleting
    job_dry = client.post(
        "/api/v1/jobs",
        headers=th,
        json={"job_type": "enforce_retention", "payload": {"dry_run": True}, "run_inline": True},
    )
    assert job_dry.status_code == 202, job_dry.text
    assert job_dry.json()["status"] == "succeeded"
    assert job_dry.json()["result"]["counts_by_class"]["reports"] == 1
    assert job_dry.json()["result"]["counts_by_class"]["identities"] == 1
    assert len(client.get("/api/v1/reports", headers=th).json()["items"]) == 1

    # Execute actual enforcement
    enf = client.post("/api/v1/retention/enforce", headers=th, json={"dry_run": False})
    assert enf.status_code == 200
    assert enf.json()["total_affected"] == 2
    assert len(client.get("/api/v1/reports", headers=th).json()["items"]) == 0
    assert len(client.get("/api/v1/identities", headers=th).json()["items"]) == 0

    # Delete assessment class via /retention/delete
    del_assess = client.post("/api/v1/retention/delete", headers=th, json={"data_class": "assessments"})
    assert del_assess.status_code == 200
    assert del_assess.json()["affected_records"] >= 1


def test_webhooks_ssrf_guard_and_hmac_sha256_delivery(
    client: TestClient,
    acme_admin_headers: dict[str, str],
) -> None:
    tid_str, th = _create_isolated_tenant_headers(client, acme_admin_headers)
    tid = uuid.UUID(tid_str)
    me = client.get("/api/v1/auth/me", headers=th).json()

    # SSRF targets rejected
    for blocked_url in (
        "http://127.0.0.1:8080/hook",
        "http://169.254.169.254/latest/meta-data",
        "http://localhost:9000/callback",
    ):
        res = client.post(
            "/api/v1/webhooks",
            headers=th,
            json={
                "name": "Blocked Hook",
                "target_url": blocked_url,
                "event_types": ["attack_path.high_risk"],
            },
        )
        assert res.status_code == 422
        assert res.json()["code"] == "SSRF_URL_BLOCKED"

    # Valid external URL accepted and secret stays hidden
    secret = "super-secret-webhook-hmac-key-2026"
    created = client.post(
        "/api/v1/webhooks",
        headers=th,
        json={
            "name": "SOC SIEM Webhook",
            "target_url": "https://webhooks.example.invalid/sentinelgraph",
            "event_types": ["attack_path.high_risk", "test.ping"],
            "signing_secret": secret,
            "min_priority_score": 65.0,
        },
    )
    assert created.status_code == 201, created.text
    wh = created.json()
    assert wh["has_signing_secret"] is True
    assert secret not in json.dumps(wh)

    captured_requests: list[httpx.Request] = []

    def sink_handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        return httpx.Response(202, json={"received": True})

    ctx = ActorContext(
        user_id=uuid.UUID(me["user"]["id"]),
        email=me["user"]["email"],
        display_name=me["user"]["display_name"],
        tenant_id=tid,
        tenant_slug=me["active_tenant"]["slug"],
        tenant_name=me["active_tenant"]["name"],
        tenant_is_demo=True,
        role=me["active_tenant"]["role"],
        request_id="req-wh-test",
    )
    with SessionLocal() as db:
        set_rls_context(db, tenant_id=tid, user_id=ctx.user_id)
        delivery = run_webhook_test_delivery(
            db,
            ctx,
            webhook_id=uuid.UUID(wh["id"]),
            http_transport=httpx.MockTransport(sink_handler),
        )
    assert delivery["delivered"] is True
    assert delivery["status_code"] == 202
    assert len(captured_requests) == 1

    req = captured_requests[0]
    sig_header = req.headers["X-SentinelGraph-Signature"]
    parts = dict(item.split("=", 1) for item in sig_header.split(","))
    expected = hmac.new(
        secret.encode("utf-8"),
        f"{parts['t']}.".encode() + req.content,
        hashlib.sha256,
    ).hexdigest()
    assert hmac.compare_digest(parts["v1"], expected)

    del_wh = client.delete(f"/api/v1/webhooks/{wh['id']}", headers=th)
    assert del_wh.status_code == 200
    assert del_wh.json()["status"] == "deleted"
