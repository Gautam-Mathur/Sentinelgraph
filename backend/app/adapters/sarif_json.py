import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any

from app.adapters.identity_export import _scan_forbidden_keys
from app.core.errors import FieldError, PayloadTooLargeError, ValidationAppError

SARIF_PARSER_VERSION = "sarif_trivy_v1.0.0"

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_SANITIZE_KEY_RE = re.compile(r"[^a-z0-9._:-]+")


def _sanitize_asset_key(raw: str) -> str:
    cleaned = _SANITIZE_KEY_RE.sub("-", raw.strip().lower()).strip("-")
    if not cleaned:
        return "app:scanned-artifact"
    if ":" in cleaned:
        return cleaned[:250]
    return f"app:{cleaned}"[:250]


def _severity_from_score(score: float | None, fallback_level: str) -> str:
    if score is not None:
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0.0:
            return "low"
        return "info"
    level_low = fallback_level.lower().strip()
    if level_low in ("critical", "crit"):
        return "critical"
    if level_low in ("high", "error"):
        return "high"
    if level_low in ("medium", "warning", "warn"):
        return "medium"
    if level_low in ("low", "note"):
        return "low"
    return "info"


def parse_sarif_or_trivy_json(
    *,
    raw_bytes: bytes,
    filename: str,
    max_bytes: int = 20 * 1024 * 1024,
) -> dict[str, Any]:
    lower_name = filename.lower()
    if not (lower_name.endswith(".json") or lower_name.endswith(".sarif")):
        raise ValidationAppError(
            code="INVALID_FILE_EXTENSION",
            message="SARIF/Trivy imports require a .sarif or .json file extension.",
        )
    if len(raw_bytes) == 0:
        raise ValidationAppError(code="EMPTY_FILE", message="Uploaded SARIF/Trivy file is empty.")
    if len(raw_bytes) > max_bytes:
        raise PayloadTooLargeError(f"Uploaded file exceeds {max_bytes} bytes.")

    try:
        raw_obj = json.loads(raw_bytes.decode("utf-8"))
    except Exception as exc:
        raise ValidationAppError(code="MALFORMED_JSON", message=f"Invalid JSON payload: {exc}") from exc

    if not isinstance(raw_obj, dict):
        raise ValidationAppError(code="INVALID_SARIF_SCHEMA", message="Expected top-level JSON object.")

    forbidden_hits = _scan_forbidden_keys(raw_obj)
    if forbidden_hits:
        raise ValidationAppError(
            code="FORBIDDEN_CREDENTIAL_FIELD",
            message="Scanner export rejected because it contains forbidden credential/secret fields.",
            field_errors=[
                FieldError(field=p, message="Forbidden credential field", code="forbidden_secret")
                for p in forbidden_hits[:10]
            ],
        )

    now_iso = datetime.now(UTC).isoformat()
    assets_map: dict[str, dict[str, Any]] = {}
    findings_map: dict[str, dict[str, Any]] = {}
    duplicates_removed = 0
    warnings: list[str] = []

    if isinstance(raw_obj.get("runs"), list):
        source_kind = "sarif"
        for run in raw_obj.get("runs", []):
            if not isinstance(run, dict):
                continue
            driver = (run.get("tool") or {}).get("driver") or {}
            tool_name = str(driver.get("name") or "sarif_scanner")[:128]
            rules_by_id: dict[str, dict[str, Any]] = {}
            for rule in driver.get("rules") or []:
                if isinstance(rule, dict) and rule.get("id"):
                    rules_by_id[str(rule["id"])] = rule

            run_props = run.get("properties") or {}
            default_asset = (
                run_props.get("asset_key")
                or (run.get("automationDetails") or {}).get("id")
                or filename
            )

            for res in run.get("results") or []:
                if not isinstance(res, dict):
                    continue
                rule_id = str(res.get("ruleId") or "finding")
                rule_meta = rules_by_id.get(rule_id, {})
                res_props = res.get("properties") or {}
                rule_props = rule_meta.get("properties") or {}

                locs = res.get("locations") or []
                artifact_uri = ""
                if locs and isinstance(locs[0], dict):
                    phys = locs[0].get("physicalLocation") or {}
                    artifact_uri = str((phys.get("artifactLocation") or {}).get("uri") or "")

                asset_hint = str(res_props.get("asset_key") or default_asset or artifact_uri or "container-app")
                asset_key = _sanitize_asset_key(asset_hint)
                if asset_key not in assets_map:
                    assets_map[asset_key] = {
                        "canonical_key": asset_key,
                        "display_name": asset_hint[:255],
                        "asset_type": "application",
                        "environment": str(res_props.get("environment") or "prod"),
                        "criticality": "medium",
                        "confidence": 0.78,
                    }

                text_blob = " ".join(
                    [
                        rule_id,
                        str((res.get("message") or {}).get("text") or ""),
                        str((rule_meta.get("shortDescription") or {}).get("text") or ""),
                        " ".join(str(t) for t in (rule_props.get("tags") or [])),
                    ]
                )
                cve_match = _CVE_RE.search(text_blob)
                cve_id = cve_match.group(0).upper() if cve_match else None

                raw_sec_sev = (
                    res_props.get("security-severity")
                    or rule_props.get("security-severity")
                    or res_props.get("cvss_score")
                )
                cvss_score: float | None = None
                if raw_sec_sev is not None:
                    try:
                        val = float(raw_sec_sev)
                        if 0.0 <= val <= 10.0:
                            cvss_score = val
                    except (TypeError, ValueError):
                        cvss_score = None

                level = str(
                    res.get("level")
                    or (rule_meta.get("defaultConfiguration") or {}).get("level")
                    or "warning"
                )
                severity = _severity_from_score(cvss_score, level)
                component = artifact_uri or str(res_props.get("package") or rule_id)
                scanner_ctx = f"{tool_name}:{rule_id}"[:255]

                raw_key = f"{asset_key}|{component.lower()}|{(cve_id or rule_id).lower()}|{scanner_ctx.lower()}"
                dedup_key = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:48]
                if dedup_key in findings_map:
                    duplicates_removed += 1
                    continue

                findings_map[dedup_key] = {
                    "asset_key": asset_key,
                    "cve_id": cve_id,
                    "cvss_version": "3.1" if cvss_score is not None else None,
                    "cvss_vector": None,
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "affected_component": component[:255],
                    "status": "open",
                    "scanner_name": tool_name,
                    "scanner_context": scanner_ctx,
                    "observed_at": now_iso,
                    "confidence": 0.82,
                    "dedup_key": dedup_key,
                    "evidence": {
                        "rule_id": rule_id,
                        "message": str((res.get("message") or {}).get("text") or "")[:1000],
                        "artifact_uri": artifact_uri or None,
                        "exploitability_proven": False,
                        "note": "SARIF observation; vulnerability presence is not proof of exploitability.",
                    },
                }

    elif isinstance(raw_obj.get("Results"), list):
        source_kind = "trivy"
        artifact_name = str(raw_obj.get("ArtifactName") or filename)
        default_asset_key = _sanitize_asset_key(
            str((raw_obj.get("Metadata") or {}).get("asset_key") or artifact_name)
        )
        assets_map[default_asset_key] = {
            "canonical_key": default_asset_key,
            "display_name": artifact_name[:255],
            "asset_type": "application",
            "environment": "prod",
            "criticality": "medium",
            "confidence": 0.82,
        }
        for target_block in raw_obj.get("Results", []):
            if not isinstance(target_block, dict):
                continue
            target_name = str(target_block.get("Target") or artifact_name)
            for vuln in target_block.get("Vulnerabilities") or []:
                if not isinstance(vuln, dict):
                    continue
                vid = str(vuln.get("VulnerabilityID") or "").strip()
                cve_id = vid.upper() if _CVE_RE.fullmatch(vid) else None
                pkg = str(vuln.get("PkgName") or "package")
                installed = str(vuln.get("InstalledVersion") or "")
                component = f"{pkg}@{installed}" if installed else pkg

                cvss_score: float | None = None
                cvss_vector: str | None = None
                cvss_dict = vuln.get("CVSS") or {}
                if isinstance(cvss_dict, dict):
                    for vendor_data in cvss_dict.values():
                        if isinstance(vendor_data, dict) and vendor_data.get("V3Score") is not None:
                            try:
                                cvss_score = float(vendor_data["V3Score"])
                                cvss_vector = str(vendor_data.get("V3Vector") or "") or None
                                break
                            except (TypeError, ValueError):
                                pass

                severity = _severity_from_score(
                    cvss_score, str(vuln.get("Severity") or "medium")
                )
                scanner_ctx = f"trivy:{target_name}:{vid or pkg}"[:255]
                raw_key = f"{default_asset_key}|{component.lower()}|{(vid or pkg).lower()}|{target_name.lower()}"
                dedup_key = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:48]
                if dedup_key in findings_map:
                    duplicates_removed += 1
                    continue

                findings_map[dedup_key] = {
                    "asset_key": default_asset_key,
                    "cve_id": cve_id,
                    "cvss_version": "3.1" if cvss_score is not None else None,
                    "cvss_vector": cvss_vector,
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "affected_component": component[:255],
                    "status": "open",
                    "scanner_name": "trivy",
                    "scanner_context": scanner_ctx,
                    "observed_at": now_iso,
                    "confidence": 0.84,
                    "dedup_key": dedup_key,
                    "evidence": {
                        "vulnerability_id": vid,
                        "fixed_version": vuln.get("FixedVersion"),
                        "title": str(vuln.get("Title") or "")[:400],
                        "target": target_name,
                        "exploitability_proven": False,
                        "note": "Trivy scan finding; presence of package CVE does not prove exploitability.",
                    },
                }
    else:
        raise ValidationAppError(
            code="INVALID_SARIF_SCHEMA",
            message="Expected SARIF v2.1.0 ('runs') or Trivy JSON ('Results') structure.",
        )

    if not findings_map:
        warnings.append("No findings extracted from SARIF/Trivy report.")

    return {
        "parser_version": SARIF_PARSER_VERSION,
        "file_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "source_kind": source_kind,
        "assets": list(assets_map.values()),
        "findings": list(findings_map.values()),
        "duplicates_removed": duplicates_removed,
        "warnings": warnings,
    }
