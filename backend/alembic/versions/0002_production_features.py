"""Add token revocation, webhook subscriptions (with RLS), and finding triage fields.

Revision ID: 0002_production_features
Revises: 0001_initial_schema
Create Date: 2026-11-10
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0002_production_features"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    # 1. Findings triage columns (idempotent in case 0001 created from fresh metadata)
    existing_finding_cols = {c["name"] for c in inspector.get_columns("findings")}
    if "triage_note" not in existing_finding_cols:
        op.add_column("findings", sa.Column("triage_note", sa.Text(), nullable=True))
    if "triaged_by_user_id" not in existing_finding_cols:
        op.add_column(
            "findings", sa.Column("triaged_by_user_id", postgresql.UUID(as_uuid=True), nullable=True)
        )
    if "triaged_at" not in existing_finding_cols:
        op.add_column(
            "findings", sa.Column("triaged_at", sa.DateTime(timezone=True), nullable=True)
        )

    # 2. Revoked tokens table
    if not inspector.has_table("revoked_tokens"):
        op.create_table(
            "revoked_tokens",
            sa.Column("jti", sa.String(length=64), primary_key=True),
            sa.Column(
                "user_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("token_type", sa.String(length=32), nullable=False, server_default="access"),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
        )
        op.create_index("ix_revoked_tokens_user_id", "revoked_tokens", ["user_id"])
        op.create_index("ix_revoked_tokens_expires_at", "revoked_tokens", ["expires_at"])

    # 3. Webhook subscriptions table (tenant-scoped with FORCE RLS)
    if not inspector.has_table("webhook_subscriptions"):
        op.create_table(
            "webhook_subscriptions",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column(
                "tenant_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("tenants.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("name", sa.String(length=200), nullable=False),
            sa.Column("target_url", sa.String(length=1024), nullable=False),
            sa.Column(
                "event_types",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=sa.text("'[]'::jsonb"),
            ),
            sa.Column("encrypted_signing_secret", sa.Text(), nullable=False),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("min_priority_score", sa.Float(), nullable=False, server_default="70.0"),
            sa.Column("last_delivery_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_status_code", sa.Integer(), nullable=True),
            sa.Column("last_error", sa.Text(), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
        )
        op.create_index("ix_webhooks_tenant", "webhook_subscriptions", ["tenant_id"])

    # Grant app role access + FORCE RLS policy on webhook_subscriptions
    op.execute(
        """
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO sentinelgraph_app;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sentinelgraph_app;
        ALTER TABLE webhook_subscriptions ENABLE ROW LEVEL SECURITY;
        ALTER TABLE webhook_subscriptions FORCE ROW LEVEL SECURITY;
        DROP POLICY IF EXISTS tenant_isolation_webhook_subscriptions ON webhook_subscriptions;
        CREATE POLICY tenant_isolation_webhook_subscriptions ON webhook_subscriptions
            USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
            WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
        """
    )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("webhook_subscriptions"):
        op.execute(
            "DROP POLICY IF EXISTS tenant_isolation_webhook_subscriptions ON webhook_subscriptions;"
        )
        op.execute("ALTER TABLE webhook_subscriptions DISABLE ROW LEVEL SECURITY;")
        op.drop_table("webhook_subscriptions")

    if inspector.has_table("revoked_tokens"):
        op.drop_table("revoked_tokens")

    existing_finding_cols = {c["name"] for c in inspector.get_columns("findings")}
    for col in ("triaged_at", "triaged_by_user_id", "triage_note"):
        if col in existing_finding_cols:
            op.drop_column("findings", col)
