import hashlib
import json
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.core.errors import FieldError, PayloadTooLargeError, ValidationAppError

IDENTITY_PARSER_VERSION = "identity_export_v1.0.0"

FORBIDDEN_CREDENTIAL_FIELDS: frozenset[str] = frozenset(
    {
        "password",
        "password_hash",
        "ntlm_hash",
        "lm_hash",
        "krbtgt",
        "secret",
        "client_secret",
        "session_token",
        "refresh_token",
        "access_token",
        "private_key",
        "tgt_ticket",
    }
)


class IdentityRecordIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    external_id: str = Field(min_length=1, max_length=255)
    provider: str = Field(min_length=1, max_length=64)
    identity_type: Literal[
        "human_user",
        "service_account",
        "machine_identity",
        "workload_identity",
        "role_identity",
    ]
    display_name: str = Field(min_length=1, max_length=255)
    principal_name: str = Field(min_length=1, max_length=255)
    enabled: bool = True
    privilege_level: Literal["standard", "elevated", "privileged", "domain_admin"] = "standard"
    privilege_indicators: list[str] = Field(default_factory=list)
    auth_metadata: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=0.85, gt=0.0, le=1.0)
    observed_at: datetime


class GroupRecordIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    external_id: str = Field(min_length=1, max_length=255)
    provider: str = Field(min_length=1, max_length=64)
    display_name: str = Field(min_length=1, max_length=255)
    group_type: Literal["security_group", "directory_role", "admin_group", "service_role"] = (
        "security_group"
    )
    privilege_indicators: list[str] = Field(default_factory=list)
    enabled: bool = True
    confidence: float = Field(default=0.9, gt=0.0, le=1.0)
    observed_at: datetime


class MembershipEdgeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identity_external_id: str = Field(min_length=1, max_length=255)
    group_external_id: str = Field(min_length=1, max_length=255)
    provider: str = Field(min_length=1, max_length=64)
    valid_from: datetime
    valid_to: datetime | None = None
    confidence: float = Field(default=0.9, gt=0.0, le=1.0)
    source_record_id: str = Field(min_length=1, max_length=255)


class IdentityExportPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_product: str = Field(default="approved_directory_export", max_length=128)
    identities: list[IdentityRecordIn] = Field(default_factory=list)
    groups: list[GroupRecordIn] = Field(default_factory=list)
    memberships: list[MembershipEdgeIn] = Field(default_factory=list)


def _scan_forbidden_keys(obj: Any, path: str = "") -> list[str]:
    hits: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            lowered = str(k).lower()
            curr_path = f"{path}.{k}" if path else str(k)
            if lowered in FORBIDDEN_CREDENTIAL_FIELDS:
                hits.append(curr_path)
            hits.extend(_scan_forbidden_keys(v, curr_path))
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            hits.extend(_scan_forbidden_keys(item, f"{path}[{idx}]"))
    return hits


def parse_identity_export(
    *,
    raw_bytes: bytes,
    filename: str,
    max_bytes: int = 10 * 1024 * 1024,
) -> dict[str, Any]:
    if not filename.lower().endswith(".json"):
        raise ValidationAppError(
            code="INVALID_FILE_EXTENSION",
            message="Identity export imports require a .json file.",
        )
    if len(raw_bytes) == 0:
        raise ValidationAppError(code="EMPTY_FILE", message="Uploaded identity export is empty.")
    if len(raw_bytes) > max_bytes:
        raise PayloadTooLargeError(f"Uploaded file exceeds {max_bytes} bytes.")

    try:
        raw_obj = json.loads(raw_bytes.decode("utf-8"))
    except Exception as exc:
        raise ValidationAppError(
            code="MALFORMED_JSON",
            message=f"Invalid JSON in identity export: {exc}",
        ) from exc

    forbidden_hits = _scan_forbidden_keys(raw_obj)
    if forbidden_hits:
        raise ValidationAppError(
            code="FORBIDDEN_CREDENTIAL_FIELD",
            message=(
                "Identity import rejected: password hashes, secrets, or session tokens "
                "must never be ingested into SentinelGraph."
            ),
            field_errors=[
                FieldError(field=p, message="Forbidden credential field", code="forbidden_secret")
                for p in forbidden_hits[:10]
            ],
        )

    try:
        parsed = IdentityExportPayload.model_validate(raw_obj)
    except ValidationError as exc:
        raise ValidationAppError(
            code="INVALID_IDENTITY_SCHEMA",
            message="Identity export failed schema validation.",
            field_errors=[
                FieldError(field=".".join(str(p) for p in e["loc"]), message=e["msg"])
                for e in exc.errors()[:10]
            ],
        ) from exc

    return {
        "parser_version": IDENTITY_PARSER_VERSION,
        "file_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "source_product": parsed.source_product,
        "identities": [i.model_dump(mode="json") for i in parsed.identities],
        "groups": [g.model_dump(mode="json") for g in parsed.groups],
        "memberships": [m.model_dump(mode="json") for m in parsed.memberships],
    }
