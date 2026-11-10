from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.adapters.cloud_phase2_stub import PHASE2_CONNECTORS
from app.core.errors import ValidationAppError
from app.core.permissions import Permission, require_permission
from app.core.security import encrypt_secret
from app.db.models import DataSource
from app.services.audit_service import record_audit_event
from app.services.context import ActorContext

MVP_SOURCE_TYPES = frozenset(
    {
        "nmap_xml",
        "nessus_xml",
        "sarif_json",
        "bloodhound_json",
        "aws_iam_export_json",
        "network_topology",
        "network_topology_json",
        "identity_export",
        "identity_json",
        "vulnerability_export",
        "vulnerability_json",
        "relationship_json",
        "manual",
    }
)


def list_integrations(db: Session, ctx: ActorContext) -> dict[str, Any]:
    require_permission(ctx.role, Permission.INTEGRATION_READ)
    sources = list(
        db.execute(
            select(DataSource)
            .where(DataSource.tenant_id == ctx.tenant_id)
            .order_by(desc(DataSource.created_at))
        ).scalars()
    )
    return {
        "configured_sources": [
            {
                "id": str(s.id),
                "name": s.name,
                "source_type": s.source_type,
                "mode": s.mode,
                "enabled": s.enabled,
                "config_metadata": s.config_metadata,
                "has_secret_configured": bool(s.encrypted_secret_ref),
                "last_sync_at": s.last_sync_at.isoformat() if s.last_sync_at else None,
            }
            for s in sources
        ],
        "phase2_roadmap_connectors": [
            {
                "source_type": c.source_type,
                "display_name": c.display_name,
                "phase": c.phase,
                "enabled_in_mvp": c.enabled_in_mvp,
                "required_auth_model": c.required_auth_model,
                "read_only_scopes": c.read_only_scopes,
                "threat_notes": c.threat_notes,
            }
            for c in PHASE2_CONNECTORS
        ],
    }


def register_data_source(
    db: Session,
    ctx: ActorContext,
    *,
    name: str,
    source_type: str,
    config_metadata: dict[str, Any],
    secret_token: str | None = None,
) -> dict[str, Any]:
    require_permission(ctx.role, Permission.INTEGRATION_MANAGE)
    if source_type not in MVP_SOURCE_TYPES:
        raise ValidationAppError(
            code="PHASE2_CONNECTOR_DISABLED",
            message=(
                f"Connector type '{source_type}' is a Phase 2 capability and is not enabled in MVP. "
                "Use approved file export adapters in MVP."
            ),
        )

    encrypted = encrypt_secret(secret_token) if secret_token else None
    src = DataSource(
        tenant_id=ctx.tenant_id,
        name=name.strip(),
        source_type=source_type,
        mode="file_import",
        config_metadata=config_metadata,
        encrypted_secret_ref=encrypted,
        enabled=True,
    )
    db.add(src)
    db.flush()

    record_audit_event(
        db,
        tenant_id=ctx.tenant_id,
        actor_user_id=ctx.user_id,
        actor_email=ctx.email,
        action="integration.setup",
        object_type="data_source",
        object_id=str(src.id),
        outcome="success",
        request_id=ctx.request_id,
        details={"source_type": source_type, "has_secret": bool(encrypted)},
    )
    db.commit()
    return {
        "id": str(src.id),
        "name": src.name,
        "source_type": src.source_type,
        "mode": src.mode,
        "enabled": src.enabled,
        "has_secret_configured": bool(src.encrypted_secret_ref),
    }
