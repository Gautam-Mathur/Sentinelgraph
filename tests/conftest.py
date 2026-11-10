import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
SAMPLE_DATA_DIR = ROOT_DIR / "sample-data"

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.db.session import SessionLocal  # noqa: E402
from app.main import app  # noqa: E402
from app.seed import DEMO_PASSWORD, seed_database  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def ensure_seeded_database() -> None:
    with SessionLocal() as db:
        seed_database(db)


@pytest.fixture()
def client() -> TestClient:
    return TestClient(app)


def login_token(
    client: TestClient,
    email: str,
    password: str = DEMO_PASSWORD,
    tenant_slug: str | None = None,
) -> dict[str, str]:
    res = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password, "tenant_slug": tenant_slug},
    )
    assert res.status_code == 200, f"Login failed for {email}: {res.text}"
    data = res.json()
    return {
        "Authorization": f"Bearer {data['access_token']}",
        "X-Tenant-ID": data["active_tenant"]["id"],
        "tenant_id": data["active_tenant"]["id"],
        "user_id": data["user"]["id"],
    }


@pytest.fixture()
def acme_admin_headers(client: TestClient) -> dict[str, str]:
    info = login_token(client, "admin@acme.local", tenant_slug="acme-demo")
    return {"Authorization": info["Authorization"], "X-Tenant-ID": info["X-Tenant-ID"]}


@pytest.fixture()
def beta_admin_headers(client: TestClient) -> dict[str, str]:
    info = login_token(client, "admin@beta.local", tenant_slug="beta-isolated")
    return {"Authorization": info["Authorization"], "X-Tenant-ID": info["X-Tenant-ID"]}
