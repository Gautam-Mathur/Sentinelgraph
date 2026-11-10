import json

import pytest

from app.adapters.identity_export import parse_identity_export
from app.adapters.network_topology import parse_topology_import
from app.adapters.vuln_scanner import parse_vulnerability_export
from app.core.errors import ValidationAppError


def test_topology_does_not_infer_reachability_from_subnet_overlap() -> None:
    payload = {
        "subnets": [
            {"name": "prod-app", "cidr": "10.10.2.0/24", "zone": "internal"},
            {"name": "prod-db", "cidr": "10.10.2.0/24", "zone": "restricted"},
        ],
        "firewall_rules": [],
    }
    res = parse_topology_import(
        raw_bytes=json.dumps(payload).encode("utf-8"),
        filename="topo.json",
    )
    assert len(res["subnets"]) == 2
    # Must NEVER synthesize CONNECTS_TO purely from overlapping subnets
    assert res["reachability_candidates"] == []


def test_topology_wildcard_rule_downgraded_to_inferred() -> None:
    payload = {
        "subnets": [],
        "firewall_rules": [
            {
                "rule_id": "ACL-ANY-1",
                "action": "allow",
                "direction": "lateral",
                "source_asset_key": "host:10.10.1.10",
                "target_asset_key": "host:10.10.2.20",
                "protocol": "any",
                "ports": [],
                "observed_at": "2026-11-10T10:00:00Z",
                "confidence": 0.95,
            }
        ],
    }
    res = parse_topology_import(
        raw_bytes=json.dumps(payload).encode("utf-8"),
        filename="topo.json",
    )
    assert len(res["reachability_candidates"]) == 1
    cand = res["reachability_candidates"][0]
    assert cand["fact_kind"] == "inferred_relationship"
    assert cand["confidence"] <= 0.65
    assert len(res["warnings"]) == 1


@pytest.mark.parametrize(
    "forbidden_key",
    ["password_hash", "ntlm_hash", "session_token", "private_key", "krbtgt"],
)
def test_identity_export_rejects_forbidden_secrets(forbidden_key: str) -> None:
    payload = {
        "source_product": "ad_export",
        "identities": [
            {
                "external_id": "u-1",
                "provider": "ad",
                "identity_type": "human_user",
                "display_name": "Alice",
                "principal_name": "alice@example.invalid",
                "auth_metadata": {forbidden_key: "SENSITIVE_MATERIAL"},
                "observed_at": "2026-11-10T10:00:00Z",
            }
        ],
    }
    with pytest.raises(ValidationAppError) as exc_info:
        parse_identity_export(
            raw_bytes=json.dumps(payload).encode("utf-8"),
            filename="idents.json",
        )
    assert exc_info.value.code == "FORBIDDEN_CREDENTIAL_FIELD"


def test_vuln_export_deduplicates_and_marks_not_exploitable() -> None:
    finding = {
        "asset_key": "host:10.10.4.50",
        "cve_id": "CVE-2024-10979",
        "cvss_score": 8.8,
        "severity": "high",
        "affected_component": "postgresql-15",
        "scanner_name": "synthetic_vuln_scanner",
        "scanner_context": "pkg-audit",
        "observed_at": "2026-11-10T10:00:00Z",
    }
    payload = {"findings": [finding, finding]}
    res = parse_vulnerability_export(
        raw_bytes=json.dumps(payload).encode("utf-8"),
        filename="vulns.json",
    )
    assert len(res["findings"]) == 1
    assert res["duplicates_removed"] == 1
    assert res["findings"][0]["evidence"]["exploitability_proven"] is False
