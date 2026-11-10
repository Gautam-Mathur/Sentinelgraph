import hashlib
import json
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.core.errors import FieldError, PayloadTooLargeError, ValidationAppError
from app.domain.relationship_rules import validate_relationship

REL_PARSER_VERSION = "relationship_export_v1.0.0"


class RelationshipRecordIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_kind: str
    source_key: str = Field(min_length=1, max_length=255)
    target_kind: str
    target_key: str = Field(min_length=1, max_length=255)
    relation_type: str
    fact_kind: str = "observed_fact"
    confidence: float = Field(gt=0.0, le=1.0)
    valid_from: datetime
    valid_to: datetime | None = None
    source_product: str = Field(default="manual_evidence_export", max_length=128)
    source_record_id: str = Field(min_length=1, max_length=255)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RelationshipExportPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    relationships: list[RelationshipRecordIn] = Field(default_factory=list)


def parse_relationship_export(
    *,
    raw_bytes: bytes,
    filename: str,
    max_bytes: int = 10 * 1024 * 1024,
) -> dict[str, Any]:
    if not filename.lower().endswith(".json"):
        raise ValidationAppError(
            code="INVALID_FILE_EXTENSION",
            message="Relationship exports require a .json file.",
        )
    if len(raw_bytes) == 0:
        raise ValidationAppError(code="EMPTY_FILE", message="Uploaded relationship file is empty.")
    if len(raw_bytes) > max_bytes:
        raise PayloadTooLargeError(f"Uploaded file exceeds {max_bytes} bytes.")

    try:
        raw_obj = json.loads(raw_bytes.decode("utf-8"))
    except Exception as exc:
        raise ValidationAppError(
            code="MALFORMED_JSON",
            message=f"Invalid JSON relationship export: {exc}",
        ) from exc

    try:
        parsed = RelationshipExportPayload.model_validate(raw_obj)
    except ValidationError as exc:
        raise ValidationAppError(
            code="INVALID_RELATIONSHIP_EXPORT",
            message="Relationship export failed schema validation.",
            field_errors=[
                FieldError(field=".".join(str(p) for p in e["loc"]), message=e["msg"])
                for e in exc.errors()[:10]
            ],
        ) from exc

    validated_edges: list[dict[str, Any]] = []
    for item in parsed.relationships:
        validate_relationship(
            source_kind=item.source_kind,
            target_kind=item.target_kind,
            relation_type=item.relation_type,
            fact_kind=item.fact_kind,
            confidence=item.confidence,
            source_id=item.source_key,
            target_id=item.target_key,
        )
        if item.valid_to is not None and item.valid_to < item.valid_from:
            raise ValidationAppError(
                code="INVALID_TEMPORAL_WINDOW",
                message=f"Relationship '{item.source_record_id}' has valid_to earlier than valid_from.",
            )
        validated_edges.append(item.model_dump(mode="json"))

    return {
        "parser_version": REL_PARSER_VERSION,
        "file_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "relationships": validated_edges,
    }
