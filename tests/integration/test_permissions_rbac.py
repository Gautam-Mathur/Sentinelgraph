from fastapi.testclient import TestClient
from tests.conftest import login_token


def test_six_role_rbac_enforcement(client: TestClient, acme_admin_headers: dict[str, str]) -> None:
    viewer = login_token(client, "viewer@acme.local")
    viewer_h = {"Authorization": viewer["Authorization"], "X-Tenant-ID": viewer["X-Tenant-ID"]}

    analyst = login_token(client, "analyst@acme.local")
    analyst_h = {"Authorization": analyst["Authorization"], "X-Tenant-ID": analyst["X-Tenant-ID"]}

    auditor = login_token(client, "auditor@acme.local")
    auditor_h = {"Authorization": auditor["Authorization"], "X-Tenant-ID": auditor["X-Tenant-ID"]}

    remed = login_token(client, "remediation@acme.local")
    remed_h = {"Authorization": remed["Authorization"], "X-Tenant-ID": remed["X-Tenant-ID"]}

    # read_only can view dashboard/assets/paths
    assert client.get("/api/v1/dashboard", headers=viewer_h).status_code == 200
    assert client.get("/api/v1/assets", headers=viewer_h).status_code == 200
    assert client.get("/api/v1/paths", headers=viewer_h).status_code == 200

    # read_only CANNOT create assets, read audit log, simulate remediation, or list members
    assert (
        client.post(
            "/api/v1/assets",
            headers=viewer_h,
            json={"canonical_key": "host:10.10.9.9", "display_name": "no", "asset_type": "server"},
        ).status_code
        == 403
    )
    assert client.get("/api/v1/audit", headers=viewer_h).status_code == 403
    assert client.get("/api/v1/tenants/members", headers=viewer_h).status_code == 403

    # analyst CAN create assets/paths, CANNOT approve imports or manage members
    staged_id = client.get("/api/v1/imports", headers=acme_admin_headers).json()["items"][0]["id"]
    assert client.post(f"/api/v1/imports/{staged_id}/approve", headers=analyst_h).status_code == 403
    assert client.get("/api/v1/tenants/members", headers=analyst_h).status_code == 403

    # auditor CAN read & export audit logs, CANNOT create assets
    assert client.get("/api/v1/audit", headers=auditor_h).status_code == 200
    assert client.get("/api/v1/audit/export?format=csv", headers=auditor_h).status_code == 200
    assert (
        client.post(
            "/api/v1/assets",
            headers=auditor_h,
            json={"canonical_key": "host:10.10.9.8", "display_name": "no", "asset_type": "server"},
        ).status_code
        == 403
    )

    # remediation_owner CAN list remediations & simulate, CANNOT approve assessment scope
    assert client.get("/api/v1/remediations", headers=remed_h).status_code == 200
    assess_id = client.get("/api/v1/assessments", headers=acme_admin_headers).json()["items"][0]["id"]
    assert client.post(f"/api/v1/assessments/{assess_id}/approve-scope", headers=remed_h).status_code == 403
