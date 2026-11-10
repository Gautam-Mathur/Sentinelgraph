import time
import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict
from redis import Redis
from rq import Queue, Retry
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AuthorizationError, ConflictError, NotFoundError, ValidationAppError
from app.core.permissions import Permission, require_permission
from app.core.telemetry import metrics
from app.db.models import BackgroundJob, Membership, Tenant, User
from app.db.session import SessionLocal, set_rls_context
from app.services.assessment_service import build_assessment_graph
from app.services.context import ActorContext
from app.services.path_service import generate_paths_for_assessment
from app.services.report_service import generate_html_report
from app.services.retention_service import enforce_retention_policies


class BuildGraphJobPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    assessment_id: uuid.UUID


class GenerateReportJobPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    assessment_id: uuid.UUID
    title: str | None = None
    remediation_action_id: uuid.UUID | None = None


class GeneratePathsJobPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    assessment_id: uuid.UUID
    algorithm: Literal["bfs", "dijkstra"] = "dijkstra"
    max_hops: int = 6
    max_candidates: int = 200
    min_confidence: float = 0.2
    top_k: int = 10


class EnforceRetentionJobPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dry_run: bool = False


def _validate_job_payload(job_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    # Never allow shell strings or arbitrary unvalidated command fields
    for k, v in payload.items():
        if k.lower() in ("cmd", "command", "shell", "script", "exec"):
            raise ValidationAppError(
                code="UNSAFE_JOB_PAYLOAD",
                message=f"Job payload key '{k}' is prohibited.",
            )
        if isinstance(v, str) and any(ch in v for ch in ("`", "$(", "&&", ";")):
            raise ValidationAppError(
                code="UNSAFE_JOB_PAYLOAD",
                message="Job payload contains prohibited shell metacharacters.",
            )

    if job_type == "build_graph":
        return BuildGraphJobPayload.model_validate(payload).model_dump(mode="json")
    if job_type == "generate_paths":
        return GeneratePathsJobPayload.model_validate(payload).model_dump(mode="json")
    if job_type == "generate_report":
        return GenerateReportJobPayload.model_validate(payload).model_dump(mode="json")
    if job_type == "enforce_retention":
        return EnforceRetentionJobPayload.model_validate(payload).model_dump(mode="json")
    raise ValidationAppError(
        code="UNSUPPORTED_JOB_TYPE",
        message=f"Unsupported background job type '{job_type}'.",
    )


def execute_job_in_worker(job_id_str: str, tenant_id_str: str) -> dict[str, Any]:
    job_id = uuid.UUID(job_id_str)
    tenant_id = uuid.UUID(tenant_id_str)
    t0 = time.perf_counter()

    with SessionLocal() as db:
        set_rls_context(db, tenant_id=tenant_id)
        job = db.execute(
            select(BackgroundJob).where(
                BackgroundJob.id == job_id,
                BackgroundJob.tenant_id == tenant_id,
            )
        ).scalar_one_or_none()
        if job is None:
            raise NotFoundError(code="JOB_NOT_FOUND", message="Background job not found")
        if job.status == "cancelled":
            return {"status": "cancelled"}

        if not job.created_by_user_id:
            raise AuthorizationError("Job missing actor user identity.")

        # Re-check active tenant membership & permissions before running
        set_rls_context(db, tenant_id=tenant_id, user_id=job.created_by_user_id)
        membership = db.execute(
            select(Membership).where(
                Membership.tenant_id == tenant_id,
                Membership.user_id == job.created_by_user_id,
                Membership.status == "active",
            )
        ).scalar_one_or_none()
        user = db.get(User, job.created_by_user_id)
        tenant = db.get(Tenant, tenant_id)
        if membership is None or user is None or not user.is_active or tenant is None:
            job.status = "failed"
            job.error_message = "Actor membership revoked or inactive."
            db.commit()
            raise AuthorizationError("Actor membership revoked before job execution.")

        ctx = ActorContext(
            user_id=user.id,
            email=user.email,
            display_name=user.display_name,
            tenant_id=tenant.id,
            tenant_slug=tenant.slug,
            tenant_name=tenant.name,
            tenant_is_demo=tenant.is_demo,
            role=membership.role.name,
            request_id=f"job-{job.id}",
            auth_method="worker",
        )

        job.status = "running"
        job.attempts += 1
        job.started_at = datetime.now(UTC)
        job.progress = 25
        db.commit()

        try:
            validated_payload = _validate_job_payload(job.job_type, job.payload)
            if job.job_type == "build_graph":
                result = build_assessment_graph(
                    db, ctx, assessment_id=uuid.UUID(validated_payload["assessment_id"])
                )
                summary = {"stats": result["stats"]}
            elif job.job_type == "generate_paths":
                result = generate_paths_for_assessment(
                    db,
                    ctx,
                    assessment_id=uuid.UUID(validated_payload["assessment_id"]),
                    start_node_keys=None,
                    target_node_keys=None,
                    algorithm=validated_payload["algorithm"],
                    allowed_edge_types=None,
                    excluded_node_keys=None,
                    excluded_environments=None,
                    min_confidence=validated_payload["min_confidence"],
                    max_hops=validated_payload["max_hops"],
                    max_candidates=validated_payload["max_candidates"],
                    top_k=validated_payload["top_k"],
                    include_inferred=True,
                )
                summary = {"paths_count": result["paths_count"], "duration_ms": result["duration_ms"]}
            elif job.job_type == "generate_report":
                result = generate_html_report(
                    db,
                    ctx,
                    assessment_id=uuid.UUID(validated_payload["assessment_id"]),
                    title=validated_payload.get("title"),
                    remediation_action_id=(
                        uuid.UUID(validated_payload["remediation_action_id"])
                        if validated_payload.get("remediation_action_id")
                        else None
                    ),
                )
                summary = {"report_id": result["id"], "title": result["title"]}
            elif job.job_type == "enforce_retention":
                result = enforce_retention_policies(
                    db,
                    ctx,
                    dry_run=bool(validated_payload.get("dry_run", False)),
                )
                summary = {
                    "policies_evaluated": result["policies_evaluated"],
                    "total_affected": result["total_affected"],
                    "counts_by_class": result["counts_by_class"],
                }
            else:
                raise ValidationAppError(code="UNSUPPORTED_JOB_TYPE", message="Unknown job type")

            job.status = "succeeded"
            job.progress = 100
            job.result = summary
            job.completed_at = datetime.now(UTC)
            db.commit()
            metrics.observe_ms("job_duration_ms", (time.perf_counter() - t0) * 1000.0)
            return summary
        except Exception as exc:
            job.error_message = str(exc)[:1000]
            if job.attempts >= job.max_attempts:
                job.status = "dead_letter"
                metrics.inc("jobs_dead_letter_total")
            else:
                job.status = "failed"
            job.completed_at = datetime.now(UTC)
            db.commit()
            raise


def enqueue_job(
    db: Session,
    ctx: ActorContext,
    *,
    job_type: str,
    payload: dict[str, Any],
    idempotency_key: str | None = None,
    run_inline: bool | None = None,
) -> dict[str, Any]:
    if job_type == "build_graph":
        require_permission(ctx.role, Permission.GRAPH_BUILD)
    elif job_type == "generate_paths":
        require_permission(ctx.role, Permission.PATH_GENERATE)
    elif job_type == "generate_report":
        require_permission(ctx.role, Permission.REPORT_GENERATE)
    elif job_type == "enforce_retention":
        require_permission(ctx.role, Permission.RETENTION_MANAGE)
    else:
        raise ValidationAppError(code="UNSUPPORTED_JOB_TYPE", message=f"Unsupported job '{job_type}'")

    validated = _validate_job_payload(job_type, payload)

    if idempotency_key:
        existing = db.execute(
            select(BackgroundJob).where(
                BackgroundJob.tenant_id == ctx.tenant_id,
                BackgroundJob.idempotency_key == idempotency_key,
            )
        ).scalar_one_or_none()
        if existing is not None:
            return serialize_job(existing)

    job = BackgroundJob(
        tenant_id=ctx.tenant_id,
        job_type=job_type,
        status="queued",
        progress=0,
        idempotency_key=idempotency_key,
        payload=validated,
        created_by_user_id=ctx.user_id,
        max_attempts=3,
    )
    db.add(job)
    db.commit()

    settings = get_settings()
    should_inline = run_inline if run_inline is not None else settings.worker_inline_fallback

    if should_inline:
        execute_job_in_worker(str(job.id), str(ctx.tenant_id))
        db.refresh(job)
        return serialize_job(job)

    try:
        redis_conn = Redis.from_url(settings.redis_url, socket_connect_timeout=2)
        redis_conn.ping()
        q = Queue("sentinelgraph", connection=redis_conn, default_timeout=120)
        q.enqueue(
            execute_job_in_worker,
            str(job.id),
            str(ctx.tenant_id),
            job_id=str(job.id),
            retry=Retry(max=2, interval=[5, 15]),
        )
        metrics.set_gauge("worker_queue_depth", float(len(q)))
    except Exception:
        if settings.local_dev_auth_enabled:
            # Graceful local dev fallback if Redis worker isn't running
            execute_job_in_worker(str(job.id), str(ctx.tenant_id))
            db.refresh(job)
        else:
            job.status = "failed"
            job.error_message = "Unable to connect to Redis worker queue."
            db.commit()

    return serialize_job(job)


def list_jobs(db: Session, ctx: ActorContext) -> list[dict[str, Any]]:
    require_permission(ctx.role, Permission.JOB_READ)
    rows = list(
        db.execute(
            select(BackgroundJob)
            .where(BackgroundJob.tenant_id == ctx.tenant_id)
            .order_by(desc(BackgroundJob.created_at))
            .limit(50)
        ).scalars()
    )
    return [serialize_job(j) for j in rows]


def get_job(db: Session, ctx: ActorContext, job_id: uuid.UUID) -> dict[str, Any]:
    require_permission(ctx.role, Permission.JOB_READ)
    job = db.execute(
        select(BackgroundJob).where(
            BackgroundJob.id == job_id,
            BackgroundJob.tenant_id == ctx.tenant_id,
        )
    ).scalar_one_or_none()
    if job is None:
        raise NotFoundError(code="JOB_NOT_FOUND", message="Background job not found")
    return serialize_job(job)


def cancel_job(db: Session, ctx: ActorContext, job_id: uuid.UUID) -> dict[str, Any]:
    require_permission(ctx.role, Permission.JOB_CANCEL)
    job = db.execute(
        select(BackgroundJob).where(
            BackgroundJob.id == job_id,
            BackgroundJob.tenant_id == ctx.tenant_id,
        )
    ).scalar_one_or_none()
    if job is None:
        raise NotFoundError(code="JOB_NOT_FOUND", message="Background job not found")
    if job.status in ("succeeded", "dead_letter"):
        raise ConflictError(code="JOB_ALREADY_TERMINAL", message=f"Job already in state '{job.status}'")
    job.status = "cancelled"
    job.completed_at = datetime.now(UTC)
    db.commit()
    return serialize_job(job)


def serialize_job(job: BackgroundJob) -> dict[str, Any]:
    return {
        "id": str(job.id),
        "tenant_id": str(job.tenant_id),
        "job_type": job.job_type,
        "status": job.status,
        "progress": job.progress,
        "attempts": job.attempts,
        "max_attempts": job.max_attempts,
        "payload": job.payload,
        "result": job.result,
        "error_message": job.error_message,
        "created_at": job.created_at.isoformat(),
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
    }
