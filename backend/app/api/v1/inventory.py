import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.api.deps import get_actor_context
from app.db.session import get_db_session
from app.services.asset_service import (
    correct_service_banner,
    create_asset,
    get_asset_detail,
    list_assets,
    update_asset,
)
from app.services.context import ActorContext
from app.services.finding_service import list_findings, triage_finding
from app.services.identity_service import (
    create_identity,
    get_identity_detail,
    list_groups,
    list_identities,
    update_identity,
)
from app.services.relationship_service import (
    create_relationship,
    list_relationships,
    suppress_observation,
    suppress_relationship,
)

assets_router = APIRouter(prefix="/assets", tags=["assets"])
identities_router = APIRouter(prefix="/identities", tags=["identities"])
relationships_router = APIRouter(prefix="/relationships", tags=["relationships"])
findings_router = APIRouter(prefix="/findings", tags=["findings"])


class AddressIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    address_type: str = Field(pattern="^(ipv4|ipv6|mac|hostname|fqdn|cidr)$")
    value: str = Field(min_length=1, max_length=255)
    is_primary: bool = False


class CreateAssetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    canonical_key: str = Field(min_length=2, max_length=255)
    display_name: str = Field(min_length=1, max_length=255)
    asset_type: str
    environment: str = "prod"
    criticality: str = "medium"
    owner: str = "unassigned"
    business_unit: str = "general"
    lifecycle_state: str = "active"
    confidence: float = Field(default=0.85, gt=0.0, le=1.0)
    is_external_entry: bool = False
    is_crown_jewel: bool = False
    addresses: list[AddressIn] = Field(default_factory=list)


class UpdateAssetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    display_name: str | None = Field(default=None, min_length=1, max_length=255)
    asset_type: str | None = None
    environment: str | None = None
    criticality: str | None = None
    owner: str | None = Field(default=None, max_length=200)
    business_unit: str | None = Field(default=None, max_length=200)
    lifecycle_state: str | None = None
    is_external_entry: bool | None = None
    is_crown_jewel: bool | None = None
    retire: bool = False


class CorrectBannerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    corrected_product: str | None = Field(default=None, max_length=255)
    corrected_version: str | None = Field(default=None, max_length=128)
    confidence: float = Field(default=0.9, gt=0.0, le=1.0)


class CreateIdentityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identity_type: str
    external_id: str = Field(min_length=1, max_length=255)
    provider: str = Field(min_length=1, max_length=64)
    display_name: str = Field(min_length=1, max_length=255)
    principal_name: str = Field(min_length=1, max_length=255)
    enabled: bool = True
    privilege_level: str = "standard"
    privilege_indicators: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.85, gt=0.0, le=1.0)


class UpdateIdentityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    display_name: str | None = Field(default=None, min_length=1, max_length=255)
    enabled: bool | None = None
    privilege_level: str | None = None
    privilege_indicators: list[str] | None = None
    retire: bool = False


class TriageFindingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str | None = None
    triage_note: str | None = Field(default=None, max_length=2000)


class CreateRelationshipRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assessment_id: uuid.UUID | None = None
    source_kind: str
    source_id: uuid.UUID
    target_kind: str
    target_id: uuid.UUID
    relation_type: str
    fact_kind: str = "analyst_assertion"
    confidence: float = Field(default=0.8, gt=0.0, le=1.0)
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    edge_metadata: dict[str, Any] = Field(default_factory=dict)


class SuppressRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    suppressed: bool = True
    reason: str = Field(min_length=3, max_length=500)


@assets_router.get("")
def list_assets_endpoint(
    asset_type: str | None = None,
    environment: str | None = None,
    criticality: str | None = None,
    search: str | None = None,
    is_external_entry: bool | None = None,
    is_crown_jewel: bool | None = None,
    sort_by: str = "created_at",
    sort_dir: str = Query(default="desc", pattern="^(asc|desc)$"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    items, total = list_assets(
        db,
        ctx,
        asset_type=asset_type,
        environment=environment,
        criticality=criticality,
        search=search,
        is_external_entry=is_external_entry,
        is_crown_jewel=is_crown_jewel,
        sort_by=sort_by,
        sort_dir=sort_dir,
        limit=limit,
        offset=offset,
    )
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@assets_router.post("", status_code=201)
def create_asset_endpoint(
    body: CreateAssetRequest,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return create_asset(
        db,
        ctx,
        canonical_key=body.canonical_key,
        display_name=body.display_name,
        asset_type=body.asset_type,
        environment=body.environment,
        criticality=body.criticality,
        owner=body.owner,
        business_unit=body.business_unit,
        lifecycle_state=body.lifecycle_state,
        confidence=body.confidence,
        is_external_entry=body.is_external_entry,
        is_crown_jewel=body.is_crown_jewel,
        addresses=[a.model_dump() for a in body.addresses],
    )


@assets_router.get("/{asset_id}")
def get_asset_endpoint(
    asset_id: uuid.UUID,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return get_asset_detail(db, ctx, asset_id)


@assets_router.patch("/{asset_id}")
def update_asset_endpoint(
    asset_id: uuid.UUID,
    body: UpdateAssetRequest,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return update_asset(
        db,
        ctx,
        asset_id=asset_id,
        display_name=body.display_name,
        asset_type=body.asset_type,
        environment=body.environment,
        criticality=body.criticality,
        owner=body.owner,
        business_unit=body.business_unit,
        lifecycle_state=body.lifecycle_state,
        is_external_entry=body.is_external_entry,
        is_crown_jewel=body.is_crown_jewel,
        retire=body.retire,
    )


@assets_router.patch("/services/{service_id}/correct")
def correct_service_endpoint(
    service_id: uuid.UUID,
    body: CorrectBannerRequest,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return correct_service_banner(
        db,
        ctx,
        service_id=service_id,
        corrected_product=body.corrected_product,
        corrected_version=body.corrected_version,
        confidence=body.confidence,
    )


@identities_router.get("")
def list_identities_endpoint(
    identity_type: str | None = None,
    privilege_level: str | None = None,
    search: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    items, total = list_identities(
        db,
        ctx,
        identity_type=identity_type,
        privilege_level=privilege_level,
        search=search,
        limit=limit,
        offset=offset,
    )
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@identities_router.get("/groups")
def list_groups_endpoint(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    items, total = list_groups(db, ctx, limit=limit, offset=offset)
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@identities_router.post("", status_code=201)
def create_identity_endpoint(
    body: CreateIdentityRequest,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return create_identity(
        db,
        ctx,
        identity_type=body.identity_type,
        external_id=body.external_id,
        provider=body.provider,
        display_name=body.display_name,
        principal_name=body.principal_name,
        enabled=body.enabled,
        privilege_level=body.privilege_level,
        privilege_indicators=body.privilege_indicators,
        confidence=body.confidence,
    )


@identities_router.get("/{identity_id}")
def get_identity_endpoint(
    identity_id: uuid.UUID,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return get_identity_detail(db, ctx, identity_id)


@identities_router.patch("/{identity_id}")
def update_identity_endpoint(
    identity_id: uuid.UUID,
    body: UpdateIdentityRequest,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return update_identity(
        db,
        ctx,
        identity_id=identity_id,
        display_name=body.display_name,
        enabled=body.enabled,
        privilege_level=body.privilege_level,
        privilege_indicators=body.privilege_indicators,
        retire=body.retire,
    )


@findings_router.get("")
def list_findings_endpoint(
    assessment_id: uuid.UUID | None = None,
    asset_id: uuid.UUID | None = None,
    severity: str | None = None,
    status: str | None = None,
    cve_id: str | None = None,
    search: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    items, total = list_findings(
        db,
        ctx,
        assessment_id=assessment_id,
        asset_id=asset_id,
        severity=severity,
        status=status,
        cve_id=cve_id,
        search=search,
        limit=limit,
        offset=offset,
    )
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@findings_router.patch("/{finding_id}")
def triage_finding_endpoint(
    finding_id: uuid.UUID,
    body: TriageFindingRequest,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return triage_finding(
        db,
        ctx,
        finding_id=finding_id,
        status=body.status,
        triage_note=body.triage_note,
    )


@relationships_router.get("")
def list_relationships_endpoint(
    relation_type: str | None = None,
    fact_kind: str | None = None,
    include_suppressed: bool = True,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    items, total = list_relationships(
        db,
        ctx,
        relation_type=relation_type,
        fact_kind=fact_kind,
        include_suppressed=include_suppressed,
        limit=limit,
        offset=offset,
    )
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@relationships_router.post("", status_code=201)
def create_relationship_endpoint(
    body: CreateRelationshipRequest,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return create_relationship(
        db,
        ctx,
        assessment_id=body.assessment_id,
        source_kind=body.source_kind,
        source_id=body.source_id,
        target_kind=body.target_kind,
        target_id=body.target_id,
        relation_type=body.relation_type,
        fact_kind=body.fact_kind,
        confidence=body.confidence,
        valid_from=body.valid_from,
        valid_to=body.valid_to,
        edge_metadata=body.edge_metadata,
    )


@relationships_router.post("/{relationship_id}/suppress")
def suppress_relationship_endpoint(
    relationship_id: uuid.UUID,
    body: SuppressRequest,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return suppress_relationship(
        db,
        ctx,
        relationship_id=relationship_id,
        suppressed=body.suppressed,
        reason=body.reason,
    )


@relationships_router.post("/observations/{observation_id}/suppress")
def suppress_observation_endpoint(
    observation_id: uuid.UUID,
    body: SuppressRequest,
    ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    return suppress_observation(
        db,
        ctx,
        observation_id=observation_id,
        suppressed=body.suppressed,
        reason=body.reason,
    )
