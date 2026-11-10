from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.permissions import RoleName
from app.core.security import hash_password
from app.db.models import Assessment, Asset, Membership, Tenant, User
from app.db.session import SessionLocal, set_rls_context
from app.services.assessment_service import (
    approve_assessment_scope,
    build_assessment_graph,
    create_assessment,
)
from app.services.asset_service import create_asset
from app.services.auth_service import ensure_default_roles
from app.services.context import ActorContext
from app.services.import_service import approve_import, commit_import, upload_and_stage_import
from app.services.path_service import generate_paths_for_assessment
from app.services.remediation_service import simulate_remediation_plan
from app.services.report_service import generate_html_report

DEMO_PASSWORD = "SentinelDemo!2026"

SEED_USERS = [
    ("admin@acme.local", "Acme Tenant Admin", RoleName.TENANT_ADMIN.value),
    ("assessor@acme.local", "Acme Lead Assessor", RoleName.ASSESSOR.value),
    ("analyst@acme.local", "Acme Security Analyst", RoleName.ANALYST.value),
    ("remediation@acme.local", "Acme Remediation Owner", RoleName.REMEDIATION_OWNER.value),
    ("auditor@acme.local", "Acme Compliance Auditor", RoleName.AUDITOR.value),
    ("viewer@acme.local", "Acme Read-Only Viewer", RoleName.READ_ONLY.value),
]


def _resolve_sample_dir() -> Path:
    candidates = [
        Path(__file__).resolve().parents[2] / "sample-data",
        Path("/app/sample-data"),
        Path.cwd() / "sample-data",
    ]
    for c in candidates:
        if c.exists():
            return c
    raise FileNotFoundError("Unable to locate sample-data directory for seeding.")


def seed_database(db: Session) -> None:
    settings = get_settings()
    if not settings.local_dev_auth_enabled:
        raise RuntimeError("Seeding local demo accounts is forbidden outside development/test/local.")

    roles = ensure_default_roles(db)
    db.commit()

    # Tenant 1: Acme Demo
    acme = db.execute(select(Tenant).where(Tenant.slug == "acme-demo")).scalar_one_or_none()
    if acme is None:
        acme = Tenant(slug="acme-demo", name="Acme Lab Corp (Demo)", is_demo=True)
        db.add(acme)
        db.commit()

    set_rls_context(db, tenant_id=acme.id)
    admin_user: User | None = None
    for email, display_name, role_name in SEED_USERS:
        user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
        if user is None:
            user = User(
                email=email,
                display_name=display_name,
                auth_provider="local",
                password_hash=hash_password(DEMO_PASSWORD),
                is_active=True,
                mfa_enabled=True,
            )
            db.add(user)
            db.flush()
        if email == "admin@acme.local":
            admin_user = user

        set_rls_context(db, tenant_id=acme.id, user_id=user.id)
        mem = db.execute(
            select(Membership).where(
                Membership.tenant_id == acme.id,
                Membership.user_id == user.id,
            )
        ).scalar_one_or_none()
        if mem is None:
            db.add(
                Membership(
                    tenant_id=acme.id,
                    user_id=user.id,
                    role_id=roles[role_name].id,
                    status="active",
                )
            )
    db.commit()
    assert admin_user is not None

    # Tenant 2: Beta Isolated (for multi-tenant isolation proof)
    beta = db.execute(select(Tenant).where(Tenant.slug == "beta-isolated")).scalar_one_or_none()
    if beta is None:
        beta = Tenant(slug="beta-isolated", name="Beta Isolated Org", is_demo=True)
        db.add(beta)
        db.commit()

    beta_user = db.execute(select(User).where(User.email == "admin@beta.local")).scalar_one_or_none()
    if beta_user is None:
        beta_user = User(
            email="admin@beta.local",
            display_name="Beta Tenant Admin",
            auth_provider="local",
            password_hash=hash_password(DEMO_PASSWORD),
            is_active=True,
            mfa_enabled=True,
        )
        db.add(beta_user)
        db.commit()

    set_rls_context(db, tenant_id=beta.id, user_id=beta_user.id)
    beta_mem = db.execute(
        select(Membership).where(
            Membership.tenant_id == beta.id,
            Membership.user_id == beta_user.id,
        )
    ).scalar_one_or_none()
    if beta_mem is None:
        db.add(
            Membership(
                tenant_id=beta.id,
                user_id=beta_user.id,
                role_id=roles[RoleName.TENANT_ADMIN.value].id,
                status="active",
            )
        )
        db.commit()

    beta_ctx = ActorContext(
        user_id=beta_user.id,
        email=beta_user.email,
        display_name=beta_user.display_name,
        tenant_id=beta.id,
        tenant_slug=beta.slug,
        tenant_name=beta.name,
        tenant_is_demo=beta.is_demo,
        role=RoleName.TENANT_ADMIN.value,
        request_id="seed-beta",
    )
    beta_existing = db.execute(
        select(Asset).where(Asset.tenant_id == beta.id, Asset.canonical_key == "host:172.30.0.10")
    ).scalar_one_or_none()
    if beta_existing is None:
        create_asset(
            db,
            beta_ctx,
            canonical_key="host:172.30.0.10",
            display_name="beta-secret-vault-01",
            asset_type="database",
            environment="prod",
            criticality="critical",
            owner="beta-secops",
            business_unit="treasury",
            lifecycle_state="active",
            confidence=0.95,
            is_external_entry=False,
            is_crown_jewel=True,
            addresses=[{"address_type": "ipv4", "value": "172.30.0.10", "is_primary": True}],
        )

    # Populate Acme Demo synthetic assessment & dataset if not yet seeded
    set_rls_context(db, tenant_id=acme.id, user_id=admin_user.id)
    existing_assess = db.execute(
        select(Assessment).where(
            Assessment.tenant_id == acme.id,
            Assessment.name == "Q4 Synthetic Lab Assessment",
        )
    ).scalar_one_or_none()
    if existing_assess is not None:
        return

    acme_ctx = ActorContext(
        user_id=admin_user.id,
        email=admin_user.email,
        display_name=admin_user.display_name,
        tenant_id=acme.id,
        tenant_slug=acme.slug,
        tenant_name=acme.name,
        tenant_is_demo=acme.is_demo,
        role=RoleName.TENANT_ADMIN.value,
        request_id="seed-acme",
    )

    now = datetime.now(UTC)
    assess = create_assessment(
        db,
        acme_ctx,
        name="Q4 Synthetic Lab Assessment",
        description="Isolated synthetic enterprise lab network demonstrating attack-path prioritization and remediation simulation.",
        approved_scope_cidrs=["10.10.0.0/16", "lab.sentinelgraph.invalid"],
        time_window_start=now - timedelta(days=1),
        time_window_end=now + timedelta(days=30),
        is_synthetic=True,
    )
    import uuid

    assess_id = uuid.UUID(assess["id"])
    approve_assessment_scope(db, acme_ctx, assessment_id=assess_id)

    sample_dir = _resolve_sample_dir()
    ingest_plan = [
        ("demo_nmap_scan.xml", "nmap_xml", "seed-nmap-1"),
        ("demo_topology.json", "network_topology_json", "seed-topo-1"),
        ("demo_identities.json", "identity_json", "seed-ident-1"),
        ("demo_vulnerabilities.json", "vulnerability_json", "seed-vuln-1"),
        ("demo_relationships.json", "relationship_json", "seed-rel-1"),
    ]
    for fname, fmt, idem in ingest_plan:
        raw_bytes = (sample_dir / fname).read_bytes()
        staged = upload_and_stage_import(
            db,
            acme_ctx,
            assessment_id=assess_id,
            source_format=fmt,
            filename=fname,
            raw_bytes=raw_bytes,
            idempotency_key=idem,
        )
        imp_id = uuid.UUID(staged["id"])
        approve_import(db, acme_ctx, import_id=imp_id)
        commit_import(db, acme_ctx, import_id=imp_id)

    # Enrich synthetic host classifications
    enrichments = {
        "host:10.10.1.10": {
            "display_name": "web-dmz-01",
            "asset_type": "server",
            "criticality": "high",
            "is_external_entry": True,
            "is_crown_jewel": False,
            "owner": "web-platform",
        },
        "host:10.10.2.20": {
            "display_name": "app-core-01",
            "asset_type": "application",
            "criticality": "high",
            "is_external_entry": False,
            "is_crown_jewel": False,
            "owner": "core-engineering",
        },
        "host:10.10.3.10": {
            "display_name": "dir-dc-01",
            "asset_type": "identity_provider",
            "criticality": "critical",
            "is_external_entry": False,
            "is_crown_jewel": False,
            "owner": "iam-ops",
        },
        "host:10.10.4.50": {
            "display_name": "db-crown-01",
            "asset_type": "database",
            "criticality": "critical",
            "is_external_entry": False,
            "is_crown_jewel": True,
            "owner": "data-security",
        },
        "host:10.10.1.25": {
            "display_name": "bastion-ops-01",
            "asset_type": "network_device",
            "criticality": "medium",
            "is_external_entry": True,
            "is_crown_jewel": False,
            "owner": "sre-infra",
        },
    }
    for ckey, vals in enrichments.items():
        asset = db.execute(
            select(Asset).where(Asset.tenant_id == acme.id, Asset.canonical_key == ckey)
        ).scalar_one_or_none()
        if asset is not None:
            asset.display_name = str(vals["display_name"])
            asset.asset_type = str(vals["asset_type"])
            asset.criticality = str(vals["criticality"])
            asset.is_external_entry = bool(vals["is_external_entry"])
            asset.is_crown_jewel = bool(vals["is_crown_jewel"])
            asset.owner = str(vals["owner"])
    db.commit()

    build_assessment_graph(db, acme_ctx, assessment_id=assess_id)
    path_res = generate_paths_for_assessment(
        db,
        acme_ctx,
        assessment_id=assess_id,
        start_node_keys=None,
        target_node_keys=None,
        algorithm="dijkstra",
        allowed_edge_types=None,
        excluded_node_keys=None,
        excluded_environments=None,
        min_confidence=0.2,
        max_hops=6,
        max_candidates=200,
        top_k=10,
        include_inferred=True,
    )

    # Seed one sandbox remediation simulation removing the weak legacy DB admin relationship
    if path_res["paths"]:
        top_path = path_res["paths"][0]
        member_step = next(
            (s for s in top_path["steps"] if s["relation_type"] == "MEMBER_OF"),
            top_path["steps"][-1],
        )
        sim = simulate_remediation_plan(
            db,
            acme_ctx,
            assessment_id=assess_id,
            name="Remove svc-etl-legacy from Crown DB Admins",
            description="Sandbox model severing legacy service account group privilege escalation edge.",
            transforms_in=[
                {
                    "transform_type": "remove_relationship",
                    "relationship_id": member_step["relationship_id"],
                    "notes": "Revoke standing MEMBER_OF privilege for svc-etl-legacy",
                }
            ],
        )
        generate_html_report(
            db,
            acme_ctx,
            assessment_id=assess_id,
            title="Q4 Synthetic Lab Attack-Path & Remediation Report",
            remediation_action_id=uuid.UUID(sim["id"]),
        )


def main() -> None:
    with SessionLocal() as db:
        seed_database(db)
    print("SentinelGraph seed completed successfully.")


if __name__ == "__main__":
    main()
