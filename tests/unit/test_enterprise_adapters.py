from pathlib import Path

import pytest

from app.adapters.cloud_iam_export import (
    parse_aws_iam_export_json,
    parse_bloodhound_json,
)
from app.adapters.nessus_xml import parse_nessus_xml
from app.adapters.network_topology import parse_topology_import
from app.adapters.sarif_json import parse_sarif_or_trivy_json
from app.core.errors import PayloadTooLargeError, ValidationAppError

SAMPLE_DIR = Path(__file__).resolve().parents[2] / "sample-data"


def test_nessus_xml_parses_sample_and_enforces_scope() -> None:
    raw = (SAMPLE_DIR / "demo_nessus_scan.nessus").read_bytes()
    res = parse_nessus_xml(
        raw_bytes=raw,
        filename="demo_nessus_scan.nessus",
        approved_scope_cidrs=["10.10.0.0/16", "lab.sentinelgraph.invalid"],
    )
    assert len(res["hosts"]) == 2
    assert res["out_of_scope_hosts"] == []
    cves = {f["cve_id"] for f in res["findings"]}
    assert cves == {"CVE-2023-28709", "CVE-2024-10979"}
    for finding in res["findings"]:
        assert finding["scanner_name"] == "tenable_nessus"
        assert finding["evidence"]["exploitability_proven"] is False
        assert finding["cvss_version"] == "3.1"

    # Narrow scope flags 10.10.4.50 as out of scope while keeping 10.10.2.20 in scope
    narrow = parse_nessus_xml(
        raw_bytes=raw,
        filename="demo_nessus_scan.nessus",
        approved_scope_cidrs=["10.10.2.0/24"],
    )
    assert len(narrow["out_of_scope_hosts"]) == 1
    assert "db-crown-01.lab.sentinelgraph.invalid" in narrow["out_of_scope_hosts"]


def test_nessus_xml_rejects_xxe_dtd_and_bad_inputs() -> None:
    xxe_payload = b"""<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<NessusClientData_v2><Report name="x"><ReportHost name="10.10.1.1"/></Report></NessusClientData_v2>"""
    with pytest.raises(ValidationAppError) as xxe_err:
        parse_nessus_xml(
            raw_bytes=xxe_payload,
            filename="evil.nessus",
            approved_scope_cidrs=["10.10.0.0/16"],
        )
    assert xxe_err.value.code == "UNSAFE_XML_REJECTED"

    with pytest.raises(ValidationAppError) as schema_err:
        parse_nessus_xml(
            raw_bytes=b"<nmaprun/>",
            filename="wrong.xml",
            approved_scope_cidrs=["10.10.0.0/16"],
        )
    assert schema_err.value.code == "INVALID_NESSUS_SCHEMA"

    with pytest.raises(ValidationAppError) as ext_err:
        parse_nessus_xml(
            raw_bytes=b"<NessusClientData_v2/>",
            filename="bad.json",
            approved_scope_cidrs=["10.10.0.0/16"],
        )
    assert ext_err.value.code == "INVALID_FILE_EXTENSION"

    with pytest.raises(ValidationAppError) as empty_err:
        parse_nessus_xml(
            raw_bytes=b"",
            filename="empty.nessus",
            approved_scope_cidrs=["10.10.0.0/16"],
        )
    assert empty_err.value.code == "EMPTY_FILE"

    with pytest.raises(PayloadTooLargeError):
        parse_nessus_xml(
            raw_bytes=b"<NessusClientData_v2/>" * 5,
            filename="huge.nessus",
            approved_scope_cidrs=["10.10.0.0/16"],
            max_bytes=16,
        )


def test_sarif_and_trivy_adapter_parses_dedups_and_blocks_secrets() -> None:
    trivy_raw = (SAMPLE_DIR / "demo_trivy_sarif.json").read_bytes()
    trivy_res = parse_sarif_or_trivy_json(raw_bytes=trivy_raw, filename="demo_trivy_sarif.json")
    assert trivy_res["source_kind"] == "trivy"
    assert len(trivy_res["findings"]) == 2
    assert {f["cve_id"] for f in trivy_res["findings"]} == {"CVE-2024-38816", "CVE-2024-47554"}
    assert all(f["evidence"]["exploitability_proven"] is False for f in trivy_res["findings"])

    synthetic_sarif = b"""{
      "version": "2.1.0",
      "runs": [
        {
          "tool": {
            "driver": {
              "name": "Semgrep-Trivy-Bench",
              "rules": [
                {
                  "id": "RULE-CRIT-1",
                  "shortDescription": {"text": "Critical flaw CVE-2025-12345"},
                  "properties": {"security-severity": "9.4"}
                }
              ]
            }
          },
          "properties": {"asset_key": "app:billing-api"},
          "results": [
            {
              "ruleId": "RULE-CRIT-1",
              "level": "error",
              "message": {"text": "Detected vulnerable dependency CVE-2025-12345"},
              "locations": [{"physicalLocation": {"artifactLocation": {"uri": "pom.xml"}}}]
            },
            {
              "ruleId": "RULE-CRIT-1",
              "level": "error",
              "message": {"text": "Detected vulnerable dependency CVE-2025-12345"},
              "locations": [{"physicalLocation": {"artifactLocation": {"uri": "pom.xml"}}}]
            }
          ]
        }
      ]
    }"""
    sarif_res = parse_sarif_or_trivy_json(raw_bytes=synthetic_sarif, filename="report.sarif")
    assert sarif_res["source_kind"] == "sarif"
    assert sarif_res["duplicates_removed"] == 1
    assert len(sarif_res["findings"]) == 1
    f0 = sarif_res["findings"][0]
    assert f0["severity"] == "critical"
    assert f0["cve_id"] == "CVE-2025-12345"
    assert f0["evidence"]["exploitability_proven"] is False

    bad_sarif = b'{"runs": [], "credentials": {"session_token": "leak"}}'
    with pytest.raises(ValidationAppError) as exc_info:
        parse_sarif_or_trivy_json(raw_bytes=bad_sarif, filename="bad.sarif")
    assert exc_info.value.code == "FORBIDDEN_CREDENTIAL_FIELD"


def test_bloodhound_and_aws_iam_adapters_and_secret_rejection() -> None:
    bh_raw = (SAMPLE_DIR / "demo_bloodhound.json").read_bytes()
    bh = parse_bloodhound_json(
        raw_bytes=bh_raw,
        filename="demo_bloodhound.json",
        approved_scope_cidrs=["10.10.0.0/16"],
    )
    assert len(bh["identities"]) == 2
    assert len(bh["groups"]) == 1
    assert len(bh["assets"]) == 1
    assert bh["assets"][0]["is_crown_jewel"] is True
    assert bh["out_of_scope_hosts"] == []
    rel_types = {r["relation_type"] for r in bh["relationships"]}
    assert rel_types == {"MEMBER_OF", "CAN_ADMINISTER"}

    bh_narrow = parse_bloodhound_json(
        raw_bytes=bh_raw,
        filename="demo_bloodhound.json",
        approved_scope_cidrs=["10.10.1.0/24"],
    )
    assert "dir-dc-01.sentinelgraph.demo.local" in bh_narrow["out_of_scope_hosts"]

    bh_secret = b'{"users": [{"ObjectIdentifier": "S-1", "Properties": {"name": "a", "ntlm_hash": "aad3b435b51404ee"}}]}'
    with pytest.raises(ValidationAppError) as bh_err:
        parse_bloodhound_json(
            raw_bytes=bh_secret,
            filename="leak.json",
            approved_scope_cidrs=["10.10.0.0/16"],
        )
    assert bh_err.value.code == "FORBIDDEN_CREDENTIAL_FIELD"

    aws_raw = (SAMPLE_DIR / "demo_aws_iam_export.json").read_bytes()
    aws = parse_aws_iam_export_json(raw_bytes=aws_raw, filename="demo_aws_iam_export.json")
    assert aws["account_id"] == "111122223333"
    by_key = {a["canonical_key"]: a for a in aws["assets"]}
    assert by_key["aws:i-demoedge01"]["is_external_entry"] is True
    assert by_key["aws:rds-crown-demo-01"]["is_crown_jewel"] is True
    aws_rel_types = {r["relation_type"] for r in aws["relationships"]}
    assert {"HAS_ROLE", "MEMBER_OF", "CAN_ADMINISTER"} <= aws_rel_types

    aws_secret = b'{"roles": [{"role_name": "Bad", "private_key": "-----BEGIN"}]}'
    with pytest.raises(ValidationAppError) as aws_err:
        parse_aws_iam_export_json(raw_bytes=aws_secret, filename="aws_leak.json")
    assert aws_err.value.code == "FORBIDDEN_CREDENTIAL_FIELD"


def test_topology_csv_parses_explicit_allow_and_downgrades_wildcard() -> None:
    csv_bytes = (
        b"rule_id,action,direction,source_asset_key,target_asset_key,protocol,ports,source_product,observed_at,confidence\n"
        b"ACL-ALLOW-HTTPS,allow,lateral,host:10.10.1.10,host:10.10.2.20,tcp,443;8443,fw_csv,2026-11-10T10:00:00+00:00,0.92\n"
        b"ACL-DENY-DB,deny,lateral,host:10.10.1.10,host:10.10.4.50,tcp,5432,fw_csv,2026-11-10T10:00:00+00:00,0.99\n"
        b"ACL-ANY,allow,lateral,host:10.10.2.20,host:10.10.3.10,any,,fw_csv,2026-11-10T10:00:00+00:00,0.9\n"
    )
    res = parse_topology_import(raw_bytes=csv_bytes, filename="rules.csv")
    assert res["firewall_rules_count"] == 3
    # Only the two 'allow' rules become reachability candidates
    assert len(res["reachability_candidates"]) == 2
    by_rule = {c["rule_id"]: c for c in res["reachability_candidates"]}
    assert by_rule["ACL-ALLOW-HTTPS"]["fact_kind"] == "observed_fact"
    assert by_rule["ACL-ALLOW-HTTPS"]["metadata"]["ports"] == [443, 8443]
    assert by_rule["ACL-ANY"]["fact_kind"] == "inferred_relationship"
    assert by_rule["ACL-ANY"]["confidence"] <= 0.65
    assert len(res["warnings"]) == 1
