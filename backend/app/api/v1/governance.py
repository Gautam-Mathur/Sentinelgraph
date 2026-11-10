import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, Query, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.api.deps import get_actor_context
from app.db.session import get_db_session
from app.services.audit_service import export_audit_events, list_audit_events
from app.services.context import ActorContext
from app.services.integration_service import list_integrations, register_data_source
from app.services.retention_service import (
    enforce_retention_policies,
    export_tenant_data_bundle,
    list_retention_policies,
    request_data_deletion,
    upsert_retention_policy,
)
from app.services.webhook_service import (
    create_webhook,
    delete_webhook,
    list_webhooks,
    test_webhook_delivery,
)
from app.workers.queue import cancel_job, enqueue_job, get_job, list_jobs

integrations_router = APIRouter(prefix="/integrations", tags=["integrations"])
audit_router = APIRouter(prefix="/audit", tags=["audit"])
jobs_router = APIRouter(prefix="/jobs", tags=["jobs"])
retention_router = APIRouter(prefix="/retention", tags=["retention"])
webhooks_router = APIRouter(prefix="/webhooks", tags=["webhooks"])


class RegisterIntegrationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=2, max_length=200)
    source_type: str = Field(min_length=2, max_length=64)
    config_metadata: dict[str, Any] = Field(default_factory=dict)
    secret_token: str | None = Field(default=None, max_length=1024)


class EnqueueJobRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    job_type: str
    payload: dict[str, Any]
    run_inline: bool | None = None


class RetentionPolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data_class: str
    retention_days: int = Field(ge=7, le=3650)
    lawful_basis: str = Field(default="authorised_assessment", max_length=255)


class DeletionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data_class: str


class EnforceRetentionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dry_run: bool = False


class CreateWebhookRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=2, max_length=200)
    target_url: str = Field(min_length=8, max_length=1024)
    event_types: list[str] = Field(default_factory=lambda: ["attack_path.high_risk"], min_length=1)
    signing_secret: str | None = Field(default=None, min_length=12, max_length=512)
    min_priority_score: float = Field(default=70.0, ge=0.0, le=100.0)
    enabled: bool = True


# --- Integrations ---
@integrations_router.get("")
def list_integrations_endpoint(
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return list_integrations(db, ctx)


@integrations_router.post("", status_code=201)
def register_integration_endpoint(
    body: RegisterIntegrationRequest,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return register_data_source(
        db,
        ctx,
        name=body.name,
        source_type=body.source_type,
        config_metadata=body.config_metadata,
        secret_token=body.secret_token,
    )


# --- Audit ---
@audit_router.get("")
def list_audit_endpoint(
    action: str | None = None,
    outcome: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    rows, total = list_audit_events(db, ctx, action=action, outcome=outcome, limit=limit, offset=offset)
    return {
        "items": [
            {
                "id": str(ev.id),
                "actor_email": ev.actor_email,
                "action": ev.action,
                "object_type": ev.object_type,
                "object_id": ev.object_id,
                "outcome": ev.outcome,
                "request_id": ev.request_id,
                "details": ev.details,
                "prev_hash": ev.prev_hash,
                "event_hash": ev.event_hash,
                "created_at": ev.created_at.isoformat(),
            }
            for ev in rows
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@audit_router.get("/export")
def export_audit_endpoint(
    format: str = Query(default="json", pattern="^(json|csv)$"),
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> Response:
    content, media_type = export_audit_events(db, ctx, export_format=format)
    ext = "csv" if format == "csv" else "json"
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="sentinelgraph-audit.{ext}"'},
    )


# --- Jobs ---
@jobs_router.get("")
def list_jobs_endpoint(
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return {"items": list_jobs(db, ctx)}


@jobs_router.post("", status_code=202)
def enqueue_job_endpoint(
    body: EnqueueJobRequest,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return enqueue_job(
        db,
        ctx,
        job_type=body.job_type,
        payload=body.payload,
        idempotency_key=idempotency_key,
        run_inline=body.run_inline,
    )


@jobs_router.get("/{job_id}")
def get_job_endpoint(
    job_id: uuid.UUID,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return get_job(db, ctx, job_id)


@jobs_router.post("/{job_id}/cancel")
def cancel_job_endpoint(
    job_id: uuid.UUID,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return cancel_job(db, ctx, job_id)


# --- Retention & Privacy ---
@retention_router.get("")
def list_retention_endpoint(
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return list_retention_policies(db, ctx)


@retention_router.put("/policies")
def upsert_retention_endpoint(
    body: RetentionPolicyRequest,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return upsert_retention_policy(
        db,
        ctx,
        data_class=body.data_class,
        retention_days=body.retention_days,
        lawful_basis=body.lawful_basis,
    )


@retention_router.post("/export")
def export_bundle_endpoint(
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return export_tenant_data_bundle(db, ctx)


@retention_router.post("/delete")
def deletion_request_endpoint(
    body: DeletionRequest,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return request_data_deletion(db, ctx, data_class=body.data_class)


@retention_router.post("/enforce")
def enforce_retention_endpoint(
    body: EnforceRetentionRequest | None = None,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return enforce_retention_policies(
        db,
        ctx,
        dry_run=bool(body.dry_run) if body else False,
    )


# --- Outbound Webhooks ---
@webhooks_router.get("")
def list_webhooks_endpoint(
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return {"items": list_webhooks(db, ctx)}


@webhooks_router.post("", status_code=201)
def create_webhook_endpoint(
    body: CreateWebhookRequest,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return create_webhook(
        db,
        ctx,
        name=body.name,
        target_url=body.target_url,
        event_types=body.event_types,
        signing_secret=body.signing_secret,
        min_priority_score=body.min_priority_score,
        enabled=body.enabled,
    )


@webhooks_router.delete("/{webhook_id}")
def delete_webhook_endpoint(
    webhook_id: uuid.UUID,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, str]:
    return delete_webhook(db, ctx, webhook_id=webhook_id)


@webhooks_router.post("/{webhook_id}/test")
def test_webhook_endpoint(
    webhook_id: uuid.UUID,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return test_webhook_delivery(db, ctx, webhook_id=webhook_id)
