from fastapi.testclient import TestClient
from sqlalchemy import text

from app.db.session import SessionLocal, set_rls_context


def test_cross_tenant_idor_blocked_with_uniform_404(
    client: TestClient,
    acme_admin_headers: dict[str, str],
    beta_admin_headers: dict[str, str],
) -> None:
    acme_assets = client.get("/api/v1/assets", headers=acme_admin_headers).json()["items"]
    beta_assets = client.get("/api/v1/assets", headers=beta_admin_headers).json()["items"]
    assert len(acme_assets) >= 1
    assert len(beta_assets) == 1
    beta_asset_id = beta_assets[0]["id"]
    assert beta_assets[0]["canonical_key"] == "host:172.30.0.10"

    # Acme cannot list Beta asset, nor fetch it by UUID (uniform 404 anti-enumeration)
    assert not any(a["id"] == beta_asset_id for a in acme_assets)
    r_asset = client.get(f"/api/v1/assets/{beta_asset_id}", headers=acme_admin_headers)
    assert r_asset.status_code == 404

    # Acme resources invisible to Beta
    acme_assess_id = client.get("/api/v1/assessments", headers=acme_admin_headers).json()["items"][0]["id"]
    acme_path_id = client.get("/api/v1/paths", headers=acme_admin_headers).json()["items"][0]["id"]
    acme_rel_id = client.get("/api/v1/relationships", headers=acme_admin_headers).json()["items"][0]["id"]
    acme_imp_id = client.get("/api/v1/imports", headers=acme_admin_headers).json()["items"][0]["id"]
    acme_rep_id = client.get("/api/v1/reports", headers=acme_admin_headers).json()["items"][0]["id"]

    assert client.get(f"/api/v1/assessments/{acme_assess_id}", headers=beta_admin_headers).status_code == 404
    assert client.get(f"/api/v1/assessments/{acme_assess_id}/graph", headers=beta_admin_headers).status_code == 404
    assert client.get(f"/api/v1/paths/{acme_path_id}", headers=beta_admin_headers).status_code == 404
    assert client.post(
        f"/api/v1/relationships/{acme_rel_id}/suppress",
        headers=beta_admin_headers,
        json={"suppressed": True, "reason": "cross tenant tamper test"},
    ).status_code == 404
    assert client.get(f"/api/v1/imports/{acme_imp_id}", headers=beta_admin_headers).status_code == 404
    assert client.get(f"/api/v1/reports/{acme_rep_id}", headers=beta_admin_headers).status_code == 404

    # Cross-tenant search returns nothing from Acme
    search_beta = client.get("/api/v1/search?q=db-crown-01", headers=beta_admin_headers).json()
    assert search_beta["assets"] == []
    assert search_beta["paths"] == []

    # Spoofing X-Tenant-ID header to Beta while using Acme's JWT must be denied (403 TENANT_ACCESS_DENIED)
    spoof_headers = {
        "Authorization": acme_admin_headers["Authorization"],
        "X-Tenant-ID": beta_admin_headers["X-Tenant-ID"],
    }
    spoof_res = client.get("/api/v1/assets", headers=spoof_headers)
    assert spoof_res.status_code == 403


def test_direct_postgresql_rls_enforced_under_sentinelgraph_app_role(
    client: TestClient,
    acme_admin_headers: dict[str, str],
    beta_admin_headers: dict[str, str],
) -> None:
    beta_tid = beta_admin_headers["X-Tenant-ID"]
    acme_tid = acme_admin_headers["X-Tenant-ID"]

    with SessionLocal() as db:
        role_info = db.execute(
            text("SELECT current_user, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
        ).one()
        assert role_info[0] == "sentinelgraph_app"
        assert role_info[1] is False
        assert role_info[2] is False

        # Without tenant GUC set -> 0 rows visible even with unfiltered raw SQL
        set_rls_context(db, clear=True)
        count_unset = db.execute(text("SELECT count(*) FROM assets")).scalar_one()
        assert count_unset == 0

        # With Acme tenant GUC -> cannot see Beta's 172.30.0.10 host
        import uuid

        set_rls_context(db, tenant_id=uuid.UUID(acme_tid))
        beta_in_acme = db.execute(
            text("SELECT count(*) FROM assets WHERE canonical_key = 'host:172.30.0.10'")
        ).scalar_one()
        assert beta_in_acme == 0

        # With Beta tenant GUC -> sees ONLY Beta's 172.30.0.10 host
        set_rls_context(db, tenant_id=uuid.UUID(beta_tid))
        beta_count = db.execute(text("SELECT count(*) FROM assets")).scalar_one()
        assert beta_count == 1
