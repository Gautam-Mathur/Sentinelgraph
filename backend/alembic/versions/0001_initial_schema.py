"""Initial SentinelGraph schema with PostgreSQL RLS and append-only audit trigger.

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-11-10
"""

from alembic import op
from app.db import models  # noqa: F401
from app.db.base import Base

revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None

TENANT_SCOPED_TABLES = [
    "data_sources",
    "assessments",
    "imports",
    "assets",
    "asset_addresses",
    "services",
    "identities",
    "groups",
    "observations",
    "relationships",
    "findings",
    "attack_paths",
    "path_steps",
    "remediation_actions",
    "audit_events",
    "reports",
    "jobs",
    "retention_policies",
    "retention_requests",
]


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)

    # Ensure non-superuser application role exists and has table privileges
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'sentinelgraph_app') THEN
                CREATE ROLE sentinelgraph_app LOGIN PASSWORD 'sentinelgraph_dev_pw'
                    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
            END IF;
        END
        $$;
        GRANT USAGE ON SCHEMA public TO sentinelgraph_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO sentinelgraph_app;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sentinelgraph_app;
        """
    )

    # Enable & force PostgreSQL Row-Level Security on all tenant-owned tables
    for tbl in TENANT_SCOPED_TABLES:
        op.execute(f"ALTER TABLE {tbl} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {tbl} FORCE ROW LEVEL SECURITY;")
        op.execute(
            f"""
            CREATE POLICY tenant_isolation_{tbl} ON {tbl}
                USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
                WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
            """
        )

    # Memberships: readable by the member user during auth or within active tenant context
    op.execute("ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE memberships FORCE ROW LEVEL SECURITY;")
    op.execute(
        """
        CREATE POLICY tenant_or_user_memberships ON memberships
            USING (
                tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
                OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
            )
            WITH CHECK (
                tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            );
        """
    )

    # Append-only immutability trigger on audit_events (blocks UPDATE and DELETE except CASCADE on tenant delete?
    # Note: Even DELETE/UPDATE directly on audit_events is blocked by BEFORE UPDATE OR DELETE trigger!)
    op.execute(
        """
        CREATE OR REPLACE FUNCTION prevent_audit_events_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'audit_events is append-only; % is prohibited', TG_OP;
        END;
        $$ LANGUAGE plpgsql;

        CREATE TRIGGER trg_audit_events_immutable
            BEFORE UPDATE OR DELETE ON audit_events
            FOR EACH ROW
            EXECUTE FUNCTION prevent_audit_events_mutation();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_audit_events_immutable ON audit_events;")
    op.execute("DROP FUNCTION IF EXISTS prevent_audit_events_mutation();")

    op.execute("DROP POLICY IF EXISTS tenant_or_user_memberships ON memberships;")
    op.execute("ALTER TABLE memberships DISABLE ROW LEVEL SECURITY;")

    for tbl in TENANT_SCOPED_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation_{tbl} ON {tbl};")
        op.execute(f"ALTER TABLE {tbl} DISABLE ROW LEVEL SECURITY;")

    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
