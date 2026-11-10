import base64
import hashlib
import json
import time
import uuid
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm

import app.core.rate_limit as rl_mod
import app.services.oidc_service as oidc_mod
from app.core.config import get_settings
from app.core.rate_limit import reset_rate_limiter
from app.core.token_store import reset_memory_revocation_cache


@pytest.fixture(autouse=True)
def reset_security_state() -> object:
    reset_rate_limiter()
    reset_memory_revocation_cache()
    oidc_mod.reset_oidc_caches()
    yield
    reset_rate_limiter()
    reset_memory_revocation_cache()
    oidc_mod.reset_oidc_caches()


def _pkce_s256(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")


def test_oidc_pkce_rs256_login_jit_and_state_replay_rejection(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk_dict = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    jwk_dict["kid"] = "sg-test-kid-1"
    jwk_dict["use"] = "sig"
    jwk_dict["alg"] = "RS256"

    issuer = "https://idp.sentinelgraph.test"
    client_id = "sentinelgraph-spa-test"
    unique_sub = f"oidc-sub-{uuid.uuid4().hex[:10]}"
    user_email = f"{unique_sub}@acme.local"

    captured_auth_params: dict[str, str] = {}
    captured_token_verifiers: list[str] = []

    def idp_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/openid-configuration":
            return httpx.Response(
                200,
                json={
                    "issuer": issuer,
                    "authorization_endpoint": f"{issuer}/authorize",
                    "token_endpoint": f"{issuer}/oauth2/token",
                    "jwks_uri": f"{issuer}/.well-known/jwks.json",
                },
            )
        if request.url.path == "/.well-known/jwks.json":
            return httpx.Response(200, json={"keys": [jwk_dict]})
        if request.url.path == "/oauth2/token":
            form = parse_qs(request.content.decode("utf-8"))
            assert form["grant_type"] == ["authorization_code"]
            assert form["code"] == ["code-ok-123"]
            verifier = form["code_verifier"][0]
            captured_token_verifiers.append(verifier)
            assert _pkce_s256(verifier) == captured_auth_params["code_challenge"]

            now = int(time.time())
            id_token = jwt.encode(
                {
                    "sub": unique_sub,
                    "iss": issuer,
                    "aud": client_id,
                    "nonce": captured_auth_params["nonce"],
                    "email": user_email,
                    "email_verified": True,
                    "name": "OIDC PKCE Analyst",
                    "iat": now,
                    "exp": now + 300,
                },
                private_key,
                algorithm="RS256",
                headers={"kid": "sg-test-kid-1"},
            )
            return httpx.Response(200, json={"id_token": id_token, "token_type": "Bearer"})
        return httpx.Response(404, json={"error": "unknown_route"})

    mock_transport = httpx.MockTransport(idp_handler)
    real_httpx_client = httpx.Client

    def patched_httpx_client(*args: object, **kwargs: object) -> httpx.Client:
        if kwargs.get("transport") is None:
            kwargs["transport"] = mock_transport
        return real_httpx_client(*args, **kwargs)  # type: ignore[arg-type]

    test_settings = get_settings().model_copy(
        update={
            "oidc_issuer_url": issuer,
            "oidc_client_id": client_id,
            "oidc_redirect_uri": "http://localhost:5173/auth/callback",
            "oidc_jit_tenant_slug": "acme-demo",
            "oidc_jit_role": "analyst",
        }
    )
    import app.services.auth_service as auth_svc_mod

    monkeypatch.setattr(oidc_mod, "get_settings", lambda: test_settings)
    monkeypatch.setattr(auth_svc_mod, "get_settings", lambda: test_settings)
    monkeypatch.setattr(oidc_mod.httpx, "Client", patched_httpx_client)

    cfg = client.get("/api/v1/auth/oidc/config")
    assert cfg.status_code == 200
    assert cfg.json()["oidc_enabled"] is True

    start_res = client.get("/api/v1/auth/oidc/login?tenant_slug=acme-demo")
    assert start_res.status_code == 200, start_res.text
    start_body = start_res.json()
    assert start_body["oidc_enabled"] is True
    parsed_url = urlparse(start_body["authorization_url"])
    qs = parse_qs(parsed_url.query)
    assert qs["code_challenge_method"] == ["S256"]
    captured_auth_params["code_challenge"] = qs["code_challenge"][0]
    captured_auth_params["nonce"] = qs["nonce"][0]

    cb_res = client.post(
        "/api/v1/auth/oidc/callback",
        json={"code": "code-ok-123", "state": start_body["state"], "tenant_slug": "acme-demo"},
    )
    assert cb_res.status_code == 200, cb_res.text
    cb_data = cb_res.json()
    assert cb_data["oidc_subject"] == unique_sub
    assert cb_data["active_tenant"]["slug"] == "acme-demo"
    assert cb_data["active_tenant"]["role"] == "analyst"
    assert cb_data["refresh_token"]
    assert len(captured_token_verifiers) == 1

    # Verify issued access token authenticates cleanly against /auth/me
    me_res = client.get(
        "/api/v1/auth/me",
        headers={
            "Authorization": f"Bearer {cb_data['access_token']}",
            "X-Tenant-ID": cb_data["active_tenant"]["id"],
        },
    )
    assert me_res.status_code == 200
    assert me_res.json()["user"]["email"] == user_email

    # Single-use OIDC state must reject replay
    replay_res = client.post(
        "/api/v1/auth/oidc/callback",
        json={"code": "code-ok-123", "state": start_body["state"], "tenant_slug": "acme-demo"},
    )
    assert replay_res.status_code == 401
    assert replay_res.json()["code"] == "OIDC_STATE_INVALID"


def test_refresh_token_rotation_and_logout_jti_revocation(client: TestClient) -> None:
    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@acme.local", "password": "SentinelDemo!2026", "tenant_slug": "acme-demo"},
    )
    assert login_res.status_code == 200
    tokens_1 = login_res.json()
    tid = tokens_1["active_tenant"]["id"]

    # Rotate refresh token
    ref_res = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens_1["refresh_token"]})
    assert ref_res.status_code == 200, ref_res.text
    tokens_2 = ref_res.json()
    assert tokens_2["refresh_token"] != tokens_1["refresh_token"]
    assert tokens_2["access_token"] != tokens_1["access_token"]

    # Reusing already-rotated refresh token fails
    reuse_ref = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens_1["refresh_token"]})
    assert reuse_ref.status_code == 401
    assert reuse_ref.json()["code"] == "TOKEN_REVOKED"

    # Logout revokes current access jti AND supplied refresh token
    out_res = client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {tokens_2['access_token']}", "X-Tenant-ID": tid},
        json={"refresh_token": tokens_2["refresh_token"]},
    )
    assert out_res.status_code == 200
    assert out_res.json()["status"] == "logged_out"

    # Access token is immediately blocked
    me_after = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {tokens_2['access_token']}", "X-Tenant-ID": tid},
    )
    assert me_after.status_code == 401
    assert me_after.json()["code"] == "TOKEN_REVOKED"

    # Refresh token from logged-out session is also blocked
    ref_after = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens_2["refresh_token"]})
    assert ref_after.status_code == 401
    assert ref_after.json()["code"] == "TOKEN_REVOKED"


def test_local_password_change_strength_and_rotation(
    client: TestClient,
    acme_admin_headers: dict[str, str],
) -> None:
    slug = f"pwd-org-{uuid.uuid4().hex[:6]}"
    ten = client.post(
        "/api/v1/tenants",
        headers=acme_admin_headers,
        json={"name": "Password Test Org", "slug": slug, "is_demo": True},
    ).json()
    tid = ten["id"]
    sw = client.post(
        "/api/v1/auth/switch-tenant",
        headers=acme_admin_headers,
        json={"tenant_id": tid},
    ).json()
    th = {"Authorization": f"Bearer {sw['access_token']}", "X-Tenant-ID": tid}

    email = f"rot-{uuid.uuid4().hex[:8]}@acme.local"
    init_pwd = "InitialPass!2026"
    new_pwd = "RotatedStrong!2027"
    mem = client.post(
        "/api/v1/tenants/members",
        headers=th,
        json={
            "email": email,
            "display_name": "Rotation User",
            "role": "analyst",
            "auth_provider": "local",
            "password": init_pwd,
        },
    )
    assert mem.status_code == 201, mem.text

    u_login = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": init_pwd, "tenant_slug": slug},
    ).json()
    uh = {"Authorization": f"Bearer {u_login['access_token']}", "X-Tenant-ID": tid}

    # Weak password rejected
    weak = client.post(
        "/api/v1/auth/change-password",
        headers=uh,
        json={"current_password": init_pwd, "new_password": "alllowercaseonly12"},
    )
    assert weak.status_code == 422
    assert weak.json()["code"] == "WEAK_PASSWORD"

    # Valid rotation succeeds
    ok = client.post(
        "/api/v1/auth/change-password",
        headers=uh,
        json={"current_password": init_pwd, "new_password": new_pwd},
    )
    assert ok.status_code == 200
    assert ok.json()["status"] == "password_updated"

    # Old password fails, new password succeeds
    old_try = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": init_pwd, "tenant_slug": slug},
    )
    assert old_try.status_code == 401
    new_try = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": new_pwd, "tenant_slug": slug},
    )
    assert new_try.status_code == 200


def test_rate_limiting_returns_429_and_retry_after(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rl_settings = get_settings().model_copy(
        update={"rate_limit_enabled": True, "rate_limit_auth_rpm": 2}
    )
    monkeypatch.setattr(rl_mod, "get_settings", lambda: rl_settings)
    reset_rate_limiter()

    ip_headers = {"X-Forwarded-For": f"198.51.100.{uuid.uuid4().int % 200 + 10}"}
    try:
        r1 = client.post(
            "/api/v1/auth/login",
            headers=ip_headers,
            json={"email": "viewer@acme.local", "password": "wrong-password-1"},
        )
        r2 = client.post(
            "/api/v1/auth/login",
            headers=ip_headers,
            json={"email": "viewer@acme.local", "password": "wrong-password-2"},
        )
        r3 = client.post(
            "/api/v1/auth/login",
            headers=ip_headers,
            json={"email": "viewer@acme.local", "password": "wrong-password-3"},
        )
        assert r1.status_code == 401
        assert r2.status_code == 401
        assert r3.status_code == 429
        assert r3.json()["code"] == "RATE_LIMITED"
        assert int(r3.headers["Retry-After"]) >= 1
        assert r3.headers["X-RateLimit-Limit"] == "2"
        assert r3.headers["X-RateLimit-Remaining"] == "0"
    finally:
        reset_rate_limiter()


def test_prometheus_metrics_endpoint_exposes_counters(
    client: TestClient,
    acme_admin_headers: dict[str, str],
) -> None:
    # Ensure at least one request metric is recorded
    client.get("/api/v1/healthz")
    client.get("/api/v1/dashboard", headers=acme_admin_headers)
    prom = client.get("/api/v1/metrics/prometheus", headers=acme_admin_headers)
    assert prom.status_code == 200
    assert "text/plain" in prom.headers["content-type"]
    assert "sentinelgraph_counter_api_requests_total" in prom.text
    assert "sentinelgraph_latency_ms_api_request_ms" in prom.text
