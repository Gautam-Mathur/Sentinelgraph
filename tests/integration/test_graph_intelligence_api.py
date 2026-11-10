from fastapi.testclient import TestClient
from tests.conftest import login_token


def test_assessment_and_path_intelligence_api_and_simulation_parity(
    client: TestClient,
    acme_admin_headers: dict[str, str],
) -> None:
    ass_list = client.get("/api/v1/assessments", headers=acme_admin_headers)
    assert ass_list.status_code == 200
    assess = next(
        a for a in ass_list.json()["items"] if "Synthetic Lab" in a["name"]
    )
    assess_id = assess["id"]

    # 1. Fetch assessment graph intelligence
    intel_res = client.get(
        f"/api/v1/assessments/{assess_id}/intelligence",
        headers=acme_admin_headers,
    )
    assert intel_res.status_code == 200, intel_res.text
    intel = intel_res.json()

    assert intel["assessment_id"] == assess_id
    assert intel["summary"]["total_active_paths"] >= 1
    assert len(intel["paths_overlay"]) == intel["summary"]["total_active_paths"]
    assert len(intel["cut_sets"]) >= 1
    assert len(intel["sensitivity_analysis"]) >= 2

    top_cut = intel["cut_sets"][0]
    assert top_cut["transforms"]

    # 2. Run actual remediation simulation using recommended cut-set transforms and confirm parity
    sim_res = client.post(
        "/api/v1/remediations/simulate",
        headers=acme_admin_headers,
        json={
            "assessment_id": assess_id,
            "name": f"Parity Check: {top_cut['label']}",
            "description": top_cut["rationale"],
            "transforms": top_cut["transforms"],
        },
    )
    assert sim_res.status_code == 201, sim_res.text
    sim = sim_res.json()
    assert sim["baseline_metrics"]["total_paths"] == top_cut["baseline_paths"]
    assert sim["delta_summary"]["paths_eliminated"] == top_cut["paths_broken"]
    assert sim["modelled_metrics"]["total_paths"] == top_cut["residual_paths"]

    # 3. Fetch single-path intelligence
    paths_res = client.get(
        f"/api/v1/paths?assessment_id={assess_id}",
        headers=acme_admin_headers,
    )
    assert paths_res.status_code == 200
    path_item = paths_res.json()["items"][0]
    path_id = path_item["id"]

    p_intel_res = client.get(
        f"/api/v1/paths/{path_id}/intelligence",
        headers=acme_admin_headers,
    )
    assert p_intel_res.status_code == 200, p_intel_res.text
    p_intel = p_intel_res.json()

    assert p_intel["path_id"] == path_id
    assert len(p_intel["why_exists"]["capability_chain"]) == path_item["hop_count"]
    assert len(p_intel["assumptions_register"]) >= 1
    assert len(p_intel["per_step_sensitivity"]) == path_item["hop_count"]
    assert len(p_intel["recommended_remediations"]) >= 1
    assert len(p_intel["subgraph"]["highlighted_edge_ids"]) == path_item["hop_count"]
    assert len(p_intel["subgraph"]["edges"]) >= path_item["hop_count"]


def test_intelligence_endpoints_enforce_tenant_isolation_and_rbac(
    client: TestClient,
    acme_admin_headers: dict[str, str],
    beta_admin_headers: dict[str, str],
) -> None:
    assess = client.get("/api/v1/assessments", headers=acme_admin_headers).json()["items"][0]
    assess_id = assess["id"]
    path_id = client.get(
        f"/api/v1/paths?assessment_id={assess_id}",
        headers=acme_admin_headers,
    ).json()["items"][0]["id"]

    # Cross-tenant isolation: uniform 404 anti-enumeration
    assert (
        client.get(
            f"/api/v1/assessments/{assess_id}/intelligence",
            headers=beta_admin_headers,
        ).status_code
        == 404
    )
    assert (
        client.get(
            f"/api/v1/paths/{path_id}/intelligence",
            headers=beta_admin_headers,
        ).status_code
        == 404
    )

    # Read-only RBAC user in acme-demo can read graph and path intelligence
    ro = login_token(client, "viewer@acme.local", tenant_slug="acme-demo")
    ro_headers = {"Authorization": ro["Authorization"], "X-Tenant-ID": ro["X-Tenant-ID"]}
    assert (
        client.get(
            f"/api/v1/assessments/{assess_id}/intelligence",
            headers=ro_headers,
        ).status_code
        == 200
    )
    assert (
        client.get(
            f"/api/v1/paths/{path_id}/intelligence",
            headers=ro_headers,
        ).status_code
        == 200
    )
