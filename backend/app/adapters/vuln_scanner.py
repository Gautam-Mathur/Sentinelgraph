import hashlib
import json
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.core.errors import FieldError, PayloadTooLargeError, ValidationAppError

VULN_PARSER_VERSION = "vuln_export_v1.0.0"


class VulnerabilityRecordIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_key: str = Field(min_length=1, max_length=255)
    port: int | None = Field(default=None, ge=1, le=65535)
    protocol: Literal["tcp", "udp"] | None = None
    cve_id: str | None = Field(default=None, pattern=r"^CVE-\d{4}-\d{4,}$")
    cvss_version: str = Field(default="3.1", max_length=16)
    cvss_vector: str | None = Field(default=None, max_length=128)
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    severity: Literal["critical", "high", "medium", "low", "info"]
    affected_component: str = Field(min_length=1, max_length=255)
    status: Literal["open", "mitigated", "accepted_risk", "false_positive"] = "open"
    scanner_name: str = Field(min_length=1, max_length=128)
    scanner_context: str = Field(min_length=1, max_length=255)
    observed_at: datetime
    confidence: float = Field(default=0.8, gt=0.0, le=1.0)
    evidence: dict[str, Any] = Field(default_factory=dict)


class VulnerabilityExportPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    findings: list[VulnerabilityRecordIn] = Field(default_factory=list)


def parse_vulnerability_export(
    *,
    raw_bytes: bytes,
    filename: str,
    max_bytes: int = 10 * 1024 * 1024,
) -> dict[str, Any]:
    if not filename.lower().endswith(".json"):
        raise ValidationAppError(
            code="INVALID_FILE_EXTENSION",
            message="Vulnerability export imports require a .json file.",
        )
    if len(raw_bytes) == 0:
        raise ValidationAppError(code="EMPTY_FILE", message="Uploaded vulnerability file is empty.")
    if len(raw_bytes) > max_bytes:
        raise PayloadTooLargeError(f"Uploaded file exceeds {max_bytes} bytes.")

    try:
        raw_obj = json.loads(raw_bytes.decode("utf-8"))
    except Exception as exc:
        raise ValidationAppError(
            code="MALFORMED_JSON",
            message=f"Invalid JSON vulnerability export: {exc}",
        ) from exc

    try:
        parsed = VulnerabilityExportPayload.model_validate(raw_obj)
    except ValidationError as exc:
        raise ValidationAppError(
            code="INVALID_VULNERABILITY_SCHEMA",
            message="Vulnerability export failed schema validation.",
            field_errors=[
                FieldError(field=".".join(str(p) for p in e["loc"]), message=e["msg"])
                for e in exc.errors()[:10]
            ],
        ) from exc

    deduped: dict[str, dict[str, Any]] = {}
    duplicates_removed = 0
    for item in parsed.findings:
        vuln_id = item.cve_id or item.affected_component
        raw_key = f"{item.asset_key.lower()}|{item.affected_component.lower()}|{vuln_id.lower()}|{item.scanner_context.lower()}"
        dedup_key = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:48]
        if dedup_key in deduped:
            duplicates_removed += 1
            continue
        rec = item.model_dump(mode="json")
        rec["dedup_key"] = dedup_key
        rec["evidence"] = {
            **item.evidence,
            "exploitability_proven": False,
            "note": "CVE presence is not proof of exploitability.",
        }
        deduped[dedup_key] = rec

    return {
        "parser_version": VULN_PARSER_VERSION,
        "file_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "findings": list(deduped.values()),
        "duplicates_removed": duplicates_removed,
    }
