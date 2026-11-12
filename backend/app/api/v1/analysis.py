import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, File, Form, Header, Query, Response, UploadFile
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.api.deps import get_actor_context
from app.db.session import get_db_session
from app.services.assessment_service import (
    approve_assessment_scope,
    build_assessment_graph,
    create_assessment,
    get_assessment,
    get_assessment_graph_intelligence,
    get_assessment_graph_payload,
    list_assessments,
)
from app.services.context import ActorContext
from app.services.import_service import (
    approve_import,
    commit_import,
    get_import,
    list_imports,
    reject_import,
    upload_and_stage_import,
)
from app.services.path_service import (
    generate_paths_for_assessment,
    get_attack_path_detail,
    get_attack_path_intelligence,
    list_attack_paths,
)
from app.services.remediation_service import (
    list_remediations,
    simulate_remediation_plan,
    validate_remediation_against_assessment,
)
from app.services.report_service import (
    export_report_format,
    generate_html_report,
    get_report,
    list_reports,
)

imports_router = APIRouter(prefix="/imports", tags=["imports"])
assessments_router = APIRouter(prefix="/assessments", tags=["assessments"])
paths_router = APIRouter(prefix="/paths", tags=["paths"])
remediations_router = APIRouter(prefix="/remediations", tags=["remediations"])
reports_router = APIRouter(prefix="/reports", tags=["reports"])


class RejectImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=3, max_length=500)


class CreateAssessmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=2, max_length=200)
    description: str = Field(default="", max_length=2000)
    approved_scope_cidrs: list[str] = Field(min_length=1, max_length=100)
    time_window_start: datetime
    time_window_end: datetime
    is_synthetic: bool = False


class GeneratePathsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assessment_id: uuid.UUID
    start_node_keys: list[str] | None = None
    target_node_keys: list[str] | None = None
    algorithm: Literal["bfs", "dijkstra"] = "dijkstra"
    allowed_edge_types: list[str] | None = None
    excluded_node_keys: list[str] | None = None
    excluded_environments: list[str] | None = None
    min_confidence: float = Field(default=0.2, ge=0.05, le=1.0)
    max_hops: int = Field(default=6, ge=1, le=12)
    max_candidates: int = Field(default=200, ge=1, le=2000)
    top_k: int = Field(default=10, ge=1, le=100)
    include_inferred: bool = True
    target_criticalities: list[str] | None = None
    ranking_mode: Literal["structural", "evidence_weighted"] = "structural"


class TransformSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    transform_type: Literal[
        "remove_relationship",
        "downgrade_relationship",
        "patch_vulnerability",
        "disable_role",
        "segment_network",
        "rotate_service_identity",
    ]
    relationship_id: str | None = None
    source_node_key: str | None = None
    target_node_key: str | None = None
    identity_id: str | None = None
    asset_id: str | None = None
    cve_id: str | None = None
    new_confidence: float | None = Field(default=None, ge=0.05, le=1.0)
    ports: list[int] | None = None
    notes: str = Field(default="", max_length=500)


class SimulateRemediationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assessment_id: uuid.UUID
    name: str = Field(min_length=2, max_length=200)
    description: str = Field(default="", max_length=1000)
    transforms: list[TransformSpec] = Field(min_length=1, max_length=50)
    min_confidence: float = Field(default=0.2, ge=0.05, le=1.0)
    max_hops: int = Field(default=6, ge=1, le=12)


class ValidateRemediationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    later_assessment_id: uuid.UUID


class GenerateReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assessment_id: uuid.UUID
    title: str | None = Field(default=None, max_length=255)
    remediation_action_id: uuid.UUID | None = None
    report_format: str = "html"


# --- Imports ---
@imports_router.get("")
def list_imports_endpoint(
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return {"items": list_imports(db, ctx)}


@imports_router.post("", status_code=201)
async def upload_import_endpoint(
    assessment_id: Annotated[uuid.UUID, Form(...)],
    source_format: Annotated[str, Form(...)],
    file: Annotated[UploadFile, File(...)],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    raw_bytes = await file.read()
    return upload_and_stage_import(
        db,
        ctx,
        assessment_id=assessment_id,
        source_format=source_format,
        filename=file.filename or "upload.bin",
        raw_bytes=raw_bytes,
        idempotency_key=idempotency_key,
    )


@imports_router.get("/{import_id}")
def get_import_endpoint(
    import_id: uuid.UUID,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return get_import(db, ctx, import_id)


@imports_router.post("/{import_id}/approve")
def approve_import_endpoint(
    import_id: uuid.UUID,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return approve_import(db, ctx, import_id=import_id)


@imports_router.post("/{import_id}/reject")
def reject_import_endpoint(
    import_id: uuid.UUID,
    body: RejectImportRequest,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return reject_import(db, ctx, import_id=import_id, reason=body.reason)


@imports_router.post("/{import_id}/commit")
def commit_import_endpoint(
    import_id: uuid.UUID,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return commit_import(db, ctx, import_id=import_id)


# --- Assessments ---
@assessments_router.get("")
def list_assessments_endpoint(
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return {"items": list_assessments(db, ctx)}


@assessments_router.post("", status_code=201)
def create_assessment_endpoint(
    body: CreateAssessmentRequest,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return create_assessment(
        db,
        ctx,
        name=body.name,
        description=body.description,
        approved_scope_cidrs=body.approved_scope_cidrs,
        time_window_start=body.time_window_start,
        time_window_end=body.time_window_end,
        is_synthetic=body.is_synthetic,
    )


@assessments_router.get("/{assessment_id}")
def get_assessment_endpoint(
    assessment_id: uuid.UUID,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return get_assessment(db, ctx, assessment_id)


@assessments_router.post("/{assessment_id}/approve-scope")
def approve_scope_endpoint(
    assessment_id: uuid.UUID,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return approve_assessment_scope(db, ctx, assessment_id=assessment_id)


@assessments_router.post("/{assessment_id}/build-graph")
def build_graph_endpoint(
    assessment_id: uuid.UUID,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return build_assessment_graph(db, ctx, assessment_id=assessment_id)


@assessments_router.get("/{assessment_id}/graph")
def get_graph_endpoint(
    assessment_id: uuid.UUID,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return get_assessment_graph_payload(db, ctx, assessment_id=assessment_id)


@assessments_router.get("/{assessment_id}/intelligence")
def get_graph_intelligence_endpoint(
    assessment_id: uuid.UUID,
    min_confidence: float = Query(default=0.2, ge=0.05, le=1.0),
    max_hops: int = Query(default=6, ge=1, le=12),
    include_inferred: bool = Query(default=True),
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return get_assessment_graph_intelligence(
        db,
        ctx,
        assessment_id=assessment_id,
        min_confidence=min_confidence,
        max_hops=max_hops,
        include_inferred=include_inferred,
    )


# --- Paths ---
@paths_router.post("/generate")
def generate_paths_endpoint(
    body: GeneratePathsRequest,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return generate_paths_for_assessment(
        db,
        ctx,
        assessment_id=body.assessment_id,
        start_node_keys=body.start_node_keys,
        target_node_keys=body.target_node_keys,
        algorithm=body.algorithm,
        allowed_edge_types=body.allowed_edge_types,
        excluded_node_keys=body.excluded_node_keys,
        excluded_environments=body.excluded_environments,
        min_confidence=body.min_confidence,
        max_hops=body.max_hops,
        max_candidates=body.max_candidates,
        top_k=body.top_k,
        include_inferred=body.include_inferred,
        target_criticalities=body.target_criticalities,
        ranking_mode=body.ranking_mode,
    )


@paths_router.get("")
def list_paths_endpoint(
    assessment_id: uuid.UUID | None = None,
    min_score: float | None = Query(default=None, ge=0.0, le=100.0),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    items = list_attack_paths(
        db, ctx, assessment_id=assessment_id, min_score=min_score, limit=limit, offset=offset
    )
    return {"items": items}


@paths_router.get("/{path_id}")
def get_path_detail_endpoint(
    path_id: uuid.UUID,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return get_attack_path_detail(db, ctx, path_id)


@paths_router.get("/{path_id}/intelligence")
def get_path_intelligence_endpoint(
    path_id: uuid.UUID,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return get_attack_path_intelligence(db, ctx, path_id)


# --- Remediations ---
@remediations_router.get("")
def list_remediations_endpoint(
    assessment_id: uuid.UUID | None = None,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return {"items": list_remediations(db, ctx, assessment_id=assessment_id)}


@remediations_router.post("/simulate", status_code=201)
def simulate_remediation_endpoint(
    body: SimulateRemediationRequest,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return simulate_remediation_plan(
        db,
        ctx,
        assessment_id=body.assessment_id,
        name=body.name,
        description=body.description,
        transforms_in=[t.model_dump() for t in body.transforms],
        min_confidence=body.min_confidence,
        max_hops=body.max_hops,
    )


@remediations_router.post("/{remediation_id}/validate")
def validate_remediation_endpoint(
    remediation_id: uuid.UUID,
    body: ValidateRemediationRequest,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return validate_remediation_against_assessment(
        db,
        ctx,
        remediation_id=remediation_id,
        later_assessment_id=body.later_assessment_id,
    )


# --- Reports ---
@reports_router.get("")
def list_reports_endpoint(
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return {"items": list_reports(db, ctx)}


@reports_router.post("", status_code=201)
def generate_report_endpoint(
    body: GenerateReportRequest,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return generate_html_report(
        db,
        ctx,
        assessment_id=body.assessment_id,
        title=body.title,
        remediation_action_id=body.remediation_action_id,
        report_format=body.report_format,
    )


@reports_router.get("/{report_id}")
def get_report_endpoint(
    report_id: uuid.UUID,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return get_report(db, ctx, report_id)


@reports_router.get("/{report_id}/download")
def download_report_endpoint(
    report_id: uuid.UUID,
    format: str = Query(default="html", pattern="^(html|json|csv|sarif)$"),
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> Response:
    content, media_type, ext = export_report_format(
        db, ctx, report_id=report_id, export_format=format
    )
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="sentinelgraph-report-{report_id}.{ext}"',
            "X-Content-Type-Options": "nosniff",
        },
    )
