import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

SAMPLE_DIR = Path(__file__).resolve().parents[2] / "sample-data"


def test_full_assessment_import_path_remediation_validation_and_report_workflow(
    client: TestClient,
    acme_admin_headers: dict[str, str],
) -> None:
    slug = f"wf-{uuid.uuid4().hex[:8]}"
    res_ten = client.post(
        "/api/v1/tenants",
        headers=acme_admin_headers,
        json={"name": f"Workflow Org {slug}", "slug": slug, "is_demo": True},
    )
    assert res_ten.status_code == 201, res_ten.text
    wf_tenant_id = res_ten.json()["id"]

    res_sw = client.post(
        "/api/v1/auth/switch-tenant",
        headers=acme_admin_headers,
        json={"tenant_id": wf_tenant_id},
    )
    assert res_sw.status_code == 200, res_sw.text
    wf_headers = {
        "Authorization": f"Bearer {res_sw.json()['access_token']}",
        "X-Tenant-ID": wf_tenant_id,
    }

    now = datetime.now(UTC)
    # 1. Create baseline assessment in draft and verify draft upload blocked
    res_ass = client.post(
        "/api/v1/assessments",
        headers=wf_headers,
        json={
            "name": "Baseline Lab Workflow",
            "description": "E2E workflow test",
            "approved_scope_cidrs": ["10.10.0.0/16", "lab.sentinelgraph.invalid"],
            "time_window_start": (now - timedelta(hours=1)).isoformat(),
            "time_window_end": (now + timedelta(days=7)).isoformat(),
            "is_synthetic": True,
        },
    )
    assert res_ass.status_code == 201
    baseline_id = res_ass.json()["id"]

    nmap_bytes = (SAMPLE_DIR / "demo_nmap_scan.xml").read_bytes()
    blocked_upload = client.post(
        "/api/v1/imports",
        headers=wf_headers,
        data={"assessment_id": baseline_id, "source_format": "nmap_xml"},
        files={"file": ("demo_nmap_scan.xml", nmap_bytes, "application/xml")},
    )
    assert blocked_upload.status_code == 422
    assert blocked_upload.json()["code"] == "SCOPE_NOT_APPROVED"

    # 2. Approve scope
    assert client.post(f"/api/v1/assessments/{baseline_id}/approve-scope", headers=wf_headers).status_code == 200

    # Pre-classify entry host & crown jewel host so auto-entry/target path & remediation simulation work end-to-end
    assert (
        client.post(
            "/api/v1/assets",
            headers=wf_headers,
            json={
                "canonical_key": "host:10.10.1.10",
                "display_name": "web-dmz-01",
                "asset_type": "server",
                "criticality": "high",
                "is_external_entry": True,
                "is_crown_jewel": False,
                "addresses": [{"address_type": "ipv4", "value": "10.10.1.10", "is_primary": True}],
            },
        ).status_code
        == 201
    )
    assert (
        client.post(
            "/api/v1/assets",
            headers=wf_headers,
            json={
                "canonical_key": "host:10.10.4.50",
                "display_name": "db-crown-01",
                "asset_type": "database",
                "criticality": "critical",
                "is_external_entry": False,
                "is_crown_jewel": True,
                "addresses": [{"address_type": "ipv4", "value": "10.10.4.50", "is_primary": True}],
            },
        ).status_code
        == 201
    )

    # 3. Staged uploads with idempotency check + approve + commit
    idem = f"idem-nmap-{uuid.uuid4()}"
    up1 = client.post(
        "/api/v1/imports",
        headers={**wf_headers, "Idempotency-Key": idem},
        data={"assessment_id": baseline_id, "source_format": "nmap_xml"},
        files={"file": ("demo_nmap_scan.xml", nmap_bytes, "application/xml")},
    )
    assert up1.status_code == 201, up1.text
    imp1_id = up1.json()["id"]

    up_replay = client.post(
        "/api/v1/imports",
        headers={**wf_headers, "Idempotency-Key": idem},
        data={"assessment_id": baseline_id, "source_format": "nmap_xml"},
        files={"file": ("demo_nmap_scan.xml", nmap_bytes, "application/xml")},
    )
    assert up_replay.status_code == 201
    assert up_replay.json()["id"] == imp1_id

    assert client.post(f"/api/v1/imports/{imp1_id}/approve", headers=wf_headers).status_code == 200
    c1 = client.post(f"/api/v1/imports/{imp1_id}/commit", headers=wf_headers)
    assert c1.status_code == 200
    assert c1.json()["status"] == "committed"
    # Idempotent commit replay
    assert client.post(f"/api/v1/imports/{imp1_id}/commit", headers=wf_headers).status_code == 200

    for fname, fmt in [
        ("demo_topology.json", "network_topology_json"),
        ("demo_identities.json", "identity_json"),
        ("demo_vulnerabilities.json", "vulnerability_json"),
        ("demo_relationships.json", "relationship_json"),
    ]:
        up = client.post(
            "/api/v1/imports",
            headers=wf_headers,
            data={"assessment_id": baseline_id, "source_format": fmt},
            files={"file": (fname, (SAMPLE_DIR / fname).read_bytes(), "application/json")},
        )
        assert up.status_code == 201, f"{fname}: {up.text}"
        iid = up.json()["id"]
        assert client.post(f"/api/v1/imports/{iid}/approve", headers=wf_headers).status_code == 200
        assert client.post(f"/api/v1/imports/{iid}/commit", headers=wf_headers).status_code == 200

    # Mark web-dmz as external entry and db-crown as crown jewel critical
    assets = client.get("/api/v1/assets", headers=wf_headers).json()["items"]
    entry = next(a for a in assets if "10.10.1.10" in a["canonical_key"])
    crown = next(a for a in assets if "10.10.4.50" in a["canonical_key"])
    # Also create explicit direct path endpoints cleanly by seeding CAN_ADMINISTER or using uploaded ones
    assert entry["id"] != crown["id"]

    # 4. Build graph & generate paths using explicit start/target keys
    bg = client.post(f"/api/v1/assessments/{baseline_id}/build-graph", headers=wf_headers)
    assert bg.status_code == 200, bg.text
    assert bg.json()["stats"]["edge_count"] > 0
    assert "blocked_precondition_edge_count" in bg.json()["stats"]
    assert bg.json()["stats"]["blocked_precondition_edge_count"] >= 0

    gp = client.post(
        "/api/v1/paths/generate",
        headers=wf_headers,
        json={
            "assessment_id": baseline_id,
            "start_node_keys": [f"asset:{entry['id']}"],
            "target_node_keys": [f"asset:{crown['id']}"],
            "algorithm": "dijkstra",
            "max_hops": 6,
            "top_k": 5,
        },
    )
    assert gp.status_code == 200, gp.text
    assert gp.json()["paths_count"] >= 1
    assert gp.json()["candidate_search_complete"] is True
    assert gp.json()["top_k_is_global"] is True
    assert gp.json()["ranking_scope"] == "global_candidate_universe"
    assert gp.json()["candidates_evaluated"] >= gp.json()["paths_count"]
    assert "blocked_precondition_edge_count" in gp.json()
    top_path = gp.json()["paths"][0]
    assert top_path["scoring_version"] == "v2.0.0"
    assert "structural_score" in top_path
    assert "evidence_weighted_score" in top_path

    # 5. Simulate remediation removing step relationship
    rel_to_cut = top_path["steps"][0]["relationship_id"]
    sim = client.post(
        "/api/v1/remediations/simulate",
        headers=wf_headers,
        json={
            "assessment_id": baseline_id,
            "name": "Segment edge test",
            "transforms": [
                {"transform_type": "remove_relationship", "relationship_id": rel_to_cut}
            ],
        },
    )
    assert sim.status_code == 201, sim.text
    rem_id = sim.json()["id"]
    assert sim.json()["is_modelled_only"] is True
    assert sim.json()["baseline_metrics"]["total_paths"] >= 1
    assert sim.json()["delta_summary"]["paths_eliminated"] >= 1

    # 6. Create followup assessment, ingest followup_nmap_scan.xml, validate remediation
    res_follow = client.post(
        "/api/v1/assessments",
        headers=wf_headers,
        json={
            "name": "Followup Validation Scan",
            "approved_scope_cidrs": ["10.10.0.0/16", "lab.sentinelgraph.invalid"],
            "time_window_start": (now - timedelta(hours=1)).isoformat(),
            "time_window_end": (now + timedelta(days=7)).isoformat(),
            "is_synthetic": True,
        },
    )
    follow_id = res_follow.json()["id"]
    assert client.post(f"/api/v1/assessments/{follow_id}/approve-scope", headers=wf_headers).status_code == 200
    f_up = client.post(
        "/api/v1/imports",
        headers=wf_headers,
        data={"assessment_id": follow_id, "source_format": "nmap_xml"},
        files={
            "file": (
                "followup_nmap_scan.xml",
                (SAMPLE_DIR / "followup_nmap_scan.xml").read_bytes(),
                "application/xml",
            )
        },
    )
    assert f_up.status_code == 201
    fiid = f_up.json()["id"]
    assert client.post(f"/api/v1/imports/{fiid}/approve", headers=wf_headers).status_code == 200
    assert client.post(f"/api/v1/imports/{fiid}/commit", headers=wf_headers).status_code == 200
    assert client.post(f"/api/v1/assessments/{follow_id}/build-graph", headers=wf_headers).status_code == 200

    val_res = client.post(
        f"/api/v1/remediations/{rem_id}/validate",
        headers=wf_headers,
        json={"later_assessment_id": follow_id},
    )
    assert val_res.status_code == 200
    assert val_res.json()["validation_assessment_id"] == follow_id
    assert val_res.json()["status"] == "validated_later"
    assert val_res.json()["validation_result"]["matches_modelled_reduction"] is True

    # 7. Generate HTML report and verify download + synthetic watermark
    rep = client.post(
        "/api/v1/reports",
        headers=wf_headers,
        json={"assessment_id": baseline_id, "remediation_action_id": rem_id},
    )
    assert rep.status_code == 201
    rep_id = rep.json()["id"]
    assert rep.json()["is_synthetic_watermarked"] is True
    dl = client.get(f"/api/v1/reports/{rep_id}/download", headers=wf_headers)
    assert dl.status_code == 200
    assert "text/html" in dl.headers["content-type"]
    assert "SYNTHETIC" in dl.text.upper()
