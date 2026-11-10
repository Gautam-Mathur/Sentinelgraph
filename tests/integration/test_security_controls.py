import json
import logging
import uuid
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.errors import AuthenticationError
from app.core.logging import StructuredJsonFormatter, redact_dict
from app.core.security import decrypt_secret, encrypt_secret, rotate_secret
from app.db.session import SessionLocal
from app.services.auth_service import authenticate_local_user


def test_xss_escaping_in_html_reports(
    client: TestClient,
    acme_admin_headers: dict[str, str],
) -> None:
    assess_id = client.get("/api/v1/assessments", headers=acme_admin_headers).json()["items"][0]["id"]
    payload_title = '<script>alert("xss")</script><img src=x onerror=alert(2)>'
    rep = client.post(
        "/api/v1/reports",
        headers=acme_admin_headers,
        json={"assessment_id": assess_id, "title": payload_title},
    )
    assert rep.status_code == 201
    rep_id = rep.json()["id"]
    html_res = client.get(f"/api/v1/reports/{rep_id}/download", headers=acme_admin_headers)
    assert html_res.status_code == 200
    assert '<script>alert("xss")</script>' not in html_res.text
    assert "&lt;script&gt;" in html_res.text


def test_mass_assignment_and_sql_injection_controls(
    client: TestClient,
    acme_admin_headers: dict[str, str],
) -> None:
    # extra="forbid" rejects privilege/mass-assignment fields cleanly
    ma_asset = client.post(
        "/api/v1/assets",
        headers=acme_admin_headers,
        json={
            "canonical_key": "host:10.99.9.9",
            "display_name": "mass-assign-test",
            "asset_type": "server",
            "is_admin": True,
        },
    )
    assert ma_asset.status_code == 422
    assert ma_asset.json()["code"] == "VALIDATION_ERROR"

    ma_tenant = client.post(
        "/api/v1/tenants",
        headers=acme_admin_headers,
        json={"name": "Bad", "slug": f"bad-{uuid.uuid4().hex[:6]}", "extra_role": "super"},
    )
    assert ma_tenant.status_code == 422

    # SQL injection search strings are safely parameterized
    sqli_assets = client.get("/api/v1/assets?search=' OR 1=1--", headers=acme_admin_headers)
    assert sqli_assets.status_code == 200
    assert sqli_assets.json()["items"] == []

    sqli_search = client.get("/api/v1/search?q=' UNION SELECT NULL--", headers=acme_admin_headers)
    assert sqli_search.status_code == 200
    assert sqli_search.json()["assets"] == []


def test_secret_encryption_redaction_and_phase2_connector_boundary(
    client: TestClient,
    acme_admin_headers: dict[str, str],
) -> None:
    # Phase 2 connector disabled
    p2 = client.post(
        "/api/v1/integrations",
        headers=acme_admin_headers,
        json={"name": "AWS Poll", "source_type": "aws_config"},
    )
    assert p2.status_code == 422
    assert p2.json()["code"] == "PHASE2_CONNECTOR_DISABLED"

    # Secret write-only storage + MultiFernet roundtrip
    cipher = encrypt_secret("top-secret-hmac-key")
    assert cipher != "top-secret-hmac-key"
    assert decrypt_secret(cipher) == "top-secret-hmac-key"
    rotated = rotate_secret(cipher)
    assert decrypt_secret(rotated) == "top-secret-hmac-key"

    ok = client.post(
        "/api/v1/integrations",
        headers=acme_admin_headers,
        json={
            "name": "Verified Nmap Feed",
            "source_type": "nmap_xml",
            "secret_token": "super-secret-signature-token",
        },
    )
    assert ok.status_code == 201
    assert ok.json()["has_secret_configured"] is True
    assert "super-secret-signature-token" not in json.dumps(ok.json())

    # Logging redaction
    redacted = redact_dict(
        {
            "password": "my-password",
            "authorization": "Bearer eyJabc.def.ghi",
            "nested": {"api_key": "k123", "note": "used Bearer xyz123"},
        }
    )
    assert redacted["password"] == "[REDACTED]"
    assert redacted["authorization"] == "[REDACTED]"
    assert redacted["nested"]["api_key"] == "[REDACTED]"
    assert "xyz123" not in redacted["nested"]["note"]

    fmt = StructuredJsonFormatter()
    rec = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="t.py",
        lineno=1,
        msg="Token leaked: Bearer super.jwt.token",
        args=(),
        exc_info=None,
    )
    formatted = fmt.format(rec)
    assert "super.jwt.token" not in formatted
    assert "Bearer [REDACTED]" in formatted


def test_local_auth_disabled_in_production_and_retention_governance(
    client: TestClient,
    acme_admin_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import app.services.auth_service as auth_mod

    prod_settings = Settings(
        app_env="production",
        secret_key="production-verified-strong-key-exceeding-thirty-two-bytes-length",
    )
    monkeypatch.setattr(auth_mod, "get_settings", lambda: prod_settings)
    with SessionLocal() as db:
        with pytest.raises(AuthenticationError) as exc_info:
            authenticate_local_user(
                db,
                email="admin@acme.local",
                password="irrelevant",
                tenant_slug="acme-demo",
                request_id="req-prod-test",
            )
        assert exc_info.value.code == "LOCAL_AUTH_DISABLED"

    # Retention & GDPR governance inside a fresh disposable tenant
    slug = f"ret-{uuid.uuid4().hex[:8]}"
    new_ten = client.post(
        "/api/v1/tenants",
        headers=acme_admin_headers,
        json={"name": "Retention Tenant", "slug": slug, "is_demo": True},
    ).json()
    tid = new_ten["id"]
    sw = client.post(
        "/api/v1/auth/switch-tenant",
        headers=acme_admin_headers,
        json={"tenant_id": tid},
    ).json()
    h = {"Authorization": f"Bearer {sw['access_token']}", "X-Tenant-ID": tid}

    assert (
        client.put(
            "/api/v1/retention/policies",
            headers=h,
            json={"data_class": "imports", "retention_days": 30, "lawful_basis": "contract"},
        ).status_code
        == 200
    )
    bundle = client.post("/api/v1/retention/export", headers=h)
    assert bundle.status_code == 200
    assert bundle.json()["tenant_id"] == tid

    now = datetime.now(UTC)
    assert (
        client.post(
            "/api/v1/identities",
            headers=h,
            json={
                "identity_type": "service_account",
                "external_id": f"svc-del-{now.timestamp()}",
                "provider": "lab",
                "display_name": "Disposable Svc",
                "principal_name": "svc@lab.invalid",
            },
        ).status_code
        == 201
    )
    del_res = client.post(
        "/api/v1/retention/delete",
        headers=h,
        json={"data_class": "identities"},
    )
    assert del_res.status_code == 200
    assert del_res.json()["affected_records"] == 1
    assert len(client.get("/api/v1/identities", headers=h).json()["items"]) == 0
