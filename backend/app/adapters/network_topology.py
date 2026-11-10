import csv
import hashlib
import io
import ipaddress
import json
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.core.errors import FieldError, PayloadTooLargeError, ValidationAppError

TOPOLOGY_PARSER_VERSION = "topology_v1.0.0"


class SubnetItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    cidr: str
    vlan_id: int | None = Field(default=None, ge=1, le=4094)
    zone: str = Field(default="internal", max_length=64)

    @field_validator("cidr")
    @classmethod
    def normalize_cidr(cls, v: str) -> str:
        return str(ipaddress.ip_network(v.strip(), strict=False))


class FirewallRuleItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(min_length=1, max_length=128)
    action: Literal["allow", "deny"]
    direction: Literal["inbound", "outbound", "lateral"] = "lateral"
    source_asset_key: str = Field(min_length=1, max_length=255)
    target_asset_key: str = Field(min_length=1, max_length=255)
    protocol: Literal["tcp", "udp", "icmp", "any"] = "tcp"
    ports: list[int] = Field(default_factory=list)
    source_product: str = Field(default="firewall_export", max_length=128)
    observed_at: datetime
    confidence: float = Field(default=0.85, gt=0.0, le=1.0)


class TopologyImportPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subnets: list[SubnetItem] = Field(default_factory=list)
    firewall_rules: list[FirewallRuleItem] = Field(default_factory=list)
    routes: list[dict[str, Any]] = Field(default_factory=list)


def parse_topology_import(
    *,
    raw_bytes: bytes,
    filename: str,
    max_bytes: int = 10 * 1024 * 1024,
) -> dict[str, Any]:
    if len(raw_bytes) == 0:
        raise ValidationAppError(code="EMPTY_FILE", message="Uploaded topology file is empty.")
    if len(raw_bytes) > max_bytes:
        raise PayloadTooLargeError(f"Uploaded file exceeds {max_bytes} bytes.")

    file_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    lower_name = filename.lower()

    if lower_name.endswith(".json"):
        try:
            raw_obj = json.loads(raw_bytes.decode("utf-8"))
        except Exception as exc:
            raise ValidationAppError(
                code="MALFORMED_JSON",
                message=f"Invalid JSON topology export: {exc}",
            ) from exc
        try:
            parsed = TopologyImportPayload.model_validate(raw_obj)
        except ValidationError as exc:
            raise ValidationAppError(
                code="INVALID_TOPOLOGY_SCHEMA",
                message="Topology export failed schema validation.",
                field_errors=[
                    FieldError(field=".".join(str(p) for p in e["loc"]), message=e["msg"])
                    for e in exc.errors()[:10]
                ],
            ) from exc
    elif lower_name.endswith(".csv"):
        text = raw_bytes.decode("utf-8", errors="strict")
        reader = csv.DictReader(io.StringIO(text))
        rules: list[FirewallRuleItem] = []
        for idx, row in enumerate(reader):
            try:
                ports_raw = [int(p.strip()) for p in (row.get("ports") or "").split(";") if p.strip()]
                rules.append(
                    FirewallRuleItem(
                        rule_id=row["rule_id"],
                        action=row["action"].lower(),  # type: ignore[arg-type]
                        direction=row.get("direction", "lateral").lower(),  # type: ignore[arg-type]
                        source_asset_key=row["source_asset_key"],
                        target_asset_key=row["target_asset_key"],
                        protocol=row.get("protocol", "tcp").lower(),  # type: ignore[arg-type]
                        ports=ports_raw,
                        source_product=row.get("source_product", "firewall_csv"),
                        observed_at=datetime.fromisoformat(row["observed_at"]),
                        confidence=float(row.get("confidence", "0.85")),
                    )
                )
            except Exception as exc:
                raise ValidationAppError(
                    code="INVALID_TOPOLOGY_CSV",
                    message=f"Invalid firewall rule row {idx + 1}: {exc}",
                ) from exc
        parsed = TopologyImportPayload(firewall_rules=rules)
    else:
        raise ValidationAppError(
            code="INVALID_FILE_EXTENSION",
            message="Topology imports accept .json or .csv files only.",
        )

    # IMPORTANT (Page 17): Never infer reachability solely from subnet overlap.
    # Emit reachability candidates ONLY from explicit allow firewall/ACL rules.
    reachability_candidates: list[dict[str, Any]] = []
    warnings: list[str] = []
    for rule in parsed.firewall_rules:
        if rule.action != "allow":
            continue
        is_wildcard = rule.protocol == "any" or len(rule.ports) == 0
        fact_kind = "inferred_relationship" if is_wildcard else "observed_fact"
        conf = min(rule.confidence, 0.65) if is_wildcard else rule.confidence
        if is_wildcard:
            warnings.append(
                f"Firewall rule '{rule.rule_id}' uses wildcard protocol/ports; downgraded to inferred_relationship."
            )
        reachability_candidates.append(
            {
                "rule_id": rule.rule_id,
                "source_asset_key": rule.source_asset_key,
                "target_asset_key": rule.target_asset_key,
                "relation_type": "CONNECTS_TO",
                "fact_kind": fact_kind,
                "confidence": conf,
                "metadata": {
                    "direction": rule.direction,
                    "protocol": rule.protocol,
                    "ports": rule.ports,
                    "acl_rule": rule.rule_id,
                    "timestamp": rule.observed_at.isoformat(),
                },
                "source_product": rule.source_product,
                "observed_at": rule.observed_at.isoformat(),
            }
        )

    return {
        "parser_version": TOPOLOGY_PARSER_VERSION,
        "file_sha256": file_sha256,
        "subnets": [s.model_dump(mode="json") for s in parsed.subnets],
        "firewall_rules_count": len(parsed.firewall_rules),
        "reachability_candidates": reachability_candidates,
        "warnings": warnings,
    }
