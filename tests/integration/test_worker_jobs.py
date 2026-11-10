import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.errors import AuthorizationError
from app.db.models import BackgroundJob, Membership
from app.db.session import SessionLocal, set_rls_context
from app.workers.queue import execute_job_in_worker


def test_background_jobs_inline_idempotency_and_unsafe_payload_rejection(
    client: TestClient,
    acme_admin_headers: dict[str, str],
) -> None:
    assess_id = client.get("/api/v1/assessments", headers=acme_admin_headers).json()["items"][0]["id"]

    # Reject shell metacharacters / dangerous keys
    bad_key = client.post(
        "/api/v1/jobs",
        headers=acme_admin_headers,
        json={"job_type": "build_graph", "payload": {"cmd": "rm -rf /"}},
    )
    assert bad_key.status_code == 422
    assert bad_key.json()["code"] == "UNSAFE_JOB_PAYLOAD"

    bad_chars = client.post(
        "/api/v1/jobs",
        headers=acme_admin_headers,
        json={
            "job_type": "generate_report",
            "payload": {"assessment_id": assess_id, "title": "bad; $(whoami)"},
        },
    )
    assert bad_chars.status_code == 422
    assert bad_chars.json()["code"] == "UNSAFE_JOB_PAYLOAD"

    # Enqueue build_graph inline with Idempotency-Key
    idem = f"job-idem-{uuid.uuid4()}"
    r1 = client.post(
        "/api/v1/jobs",
        headers={**acme_admin_headers, "Idempotency-Key": idem},
        json={"job_type": "build_graph", "payload": {"assessment_id": assess_id}, "run_inline": True},
    )
    assert r1.status_code == 202, r1.text
    j1 = r1.json()
    assert j1["status"] == "succeeded"
    assert j1["progress"] == 100
    assert j1["result"]["stats"]["node_count"] > 0

    # Idempotent replay returns same job ID without double execution
    r2 = client.post(
        "/api/v1/jobs",
        headers={**acme_admin_headers, "Idempotency-Key": idem},
        json={"job_type": "build_graph", "payload": {"assessment_id": assess_id}, "run_inline": True},
    )
    assert r2.status_code == 202
    assert r2.json()["id"] == j1["id"]

    # Inline generate_report & generate_paths
    r_paths = client.post(
        "/api/v1/jobs",
        headers=acme_admin_headers,
        json={
            "job_type": "generate_paths",
            "payload": {"assessment_id": assess_id, "algorithm": "dijkstra", "max_hops": 6, "top_k": 5},
            "run_inline": True,
        },
    )
    assert r_paths.status_code == 202
    assert r_paths.json()["status"] == "succeeded"
    assert r_paths.json()["result"]["paths_count"] >= 1

    r_rep = client.post(
        "/api/v1/jobs",
        headers=acme_admin_headers,
        json={
            "job_type": "generate_report",
            "payload": {"assessment_id": assess_id, "title": "Worker Async Report"},
            "run_inline": True,
        },
    )
    assert r_rep.status_code == 202
    assert r_rep.json()["status"] == "succeeded"
    assert "report_id" in r_rep.json()["result"]

    # Verify list & get endpoints
    fetched = client.get(f"/api/v1/jobs/{j1['id']}", headers=acme_admin_headers)
    assert fetched.status_code == 200
    listed = client.get("/api/v1/jobs", headers=acme_admin_headers).json()["items"]
    assert any(item["id"] == j1["id"] for item in listed)


def test_job_cancellation_and_worker_membership_revalidation(
    client: TestClient,
    acme_admin_headers: dict[str, str],
) -> None:
    assess_id = client.get("/api/v1/assessments", headers=acme_admin_headers).json()["items"][0]["id"]
    tid = uuid.UUID(acme_admin_headers["X-Tenant-ID"])
    me = client.get("/api/v1/auth/me", headers=acme_admin_headers).json()
    uid = uuid.UUID(me["user"]["id"])

    # Create a queued job directly to test cancel + skipped worker execution
    with SessionLocal() as db:
        set_rls_context(db, tenant_id=tid, user_id=uid)
        queued_job = BackgroundJob(
            tenant_id=tid,
            job_type="build_graph",
            status="queued",
            progress=0,
            payload={"assessment_id": assess_id},
            created_by_user_id=uid,
            max_attempts=3,
        )
        db.add(queued_job)
        db.commit()
        qid = str(queued_job.id)

    cancel_res = client.post(f"/api/v1/jobs/{qid}/cancel", headers=acme_admin_headers)
    assert cancel_res.status_code == 200
    assert cancel_res.json()["status"] == "cancelled"
    assert execute_job_in_worker(qid, str(tid)) == {"status": "cancelled"}

    # Test membership revocation check before worker runs in a disposable tenant
    slug = f"rev-{uuid.uuid4().hex[:8]}"
    new_ten = client.post(
        "/api/v1/tenants",
        headers=acme_admin_headers,
        json={"name": "Revoked Worker Tenant", "slug": slug, "is_demo": True},
    ).json()
    rev_tid = uuid.UUID(new_ten["id"])

    with SessionLocal() as db:
        set_rls_context(db, tenant_id=rev_tid, user_id=uid)
        job_row = BackgroundJob(
            tenant_id=rev_tid,
            job_type="build_graph",
            status="queued",
            progress=0,
            payload={"assessment_id": assess_id},
            created_by_user_id=uid,
            max_attempts=3,
        )
        db.add(job_row)
        mem = db.execute(
            select(Membership).where(Membership.tenant_id == rev_tid, Membership.user_id == uid)
        ).scalar_one()
        mem.status = "suspended"
        db.commit()
        rev_jid = str(job_row.id)

    with pytest.raises(AuthorizationError):
        execute_job_in_worker(rev_jid, str(rev_tid))
