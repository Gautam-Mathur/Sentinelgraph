import hashlib
import re
from datetime import UTC, datetime
from typing import Any

import defusedxml.ElementTree as ET
from defusedxml.common import DefusedXmlException

from app.adapters.nmap_xml import _check_scope
from app.core.errors import FieldError, PayloadTooLargeError, ValidationAppError

NESSUS_PARSER_VERSION = "nessus_xml_v1.0.0"

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_SEVERITY_MAP = {
    "4": "critical",
    "3": "high",
    "2": "medium",
    "1": "low",
    "0": "info",
}


def parse_nessus_xml(
    *,
    raw_bytes: bytes,
    filename: str,
    approved_scope_cidrs: list[str],
    max_bytes: int = 20 * 1024 * 1024,
) -> dict[str, Any]:
    lower_name = filename.lower()
    if not (lower_name.endswith(".nessus") or lower_name.endswith(".xml")):
        raise ValidationAppError(
            code="INVALID_FILE_EXTENSION",
            message="Nessus imports require a .nessus or .xml file extension.",
        )
    if len(raw_bytes) == 0:
        raise ValidationAppError(code="EMPTY_FILE", message="Uploaded Nessus file is empty.")
    if len(raw_bytes) > max_bytes:
        raise PayloadTooLargeError(f"Uploaded file exceeds {max_bytes} bytes.")

    head_text = raw_bytes[:512].decode("utf-8", errors="replace").lstrip("\ufeff \t\r\n")
    if not head_text.startswith("<"):
        raise ValidationAppError(code="MALFORMED_XML", message="File does not appear to be valid XML.")

    try:
        root = ET.fromstring(
            raw_bytes,
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
    except DefusedXmlException as exc:
        raise ValidationAppError(
            code="UNSAFE_XML_REJECTED",
            message=f"XML parser blocked unsafe DTD/entity construct: {exc}",
            field_errors=[FieldError(field="file", message="Unsafe XML blocked", code="xxe_blocked")],
        ) from exc
    except Exception as exc:
        raise ValidationAppError(
            code="MALFORMED_XML",
            message=f"Unable to parse Nessus XML: {exc}",
        ) from exc

    if root.tag != "NessusClientData_v2":
        raise ValidationAppError(
            code="INVALID_NESSUS_SCHEMA",
            message=f"Expected <NessusClientData_v2> root element, got <{root.tag}>.",
        )

    now_iso = datetime.now(UTC).isoformat()
    hosts: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    out_of_scope_hosts: list[str] = []
    warnings: list[str] = []
    seen_finding_keys: set[str] = set()

    for report_host in root.findall(".//ReportHost"):
        raw_host_name = (report_host.attrib.get("name") or "").strip()
        props: dict[str, str] = {}
        for tag in report_host.findall("./HostProperties/tag"):
            tname = (tag.attrib.get("name") or "").strip()
            tval = (tag.text or "").strip()
            if tname and tval:
                props[tname] = tval

        host_ip = props.get("host-ip", "").strip()
        host_fqdn = props.get("host-fqdn", "").strip()
        mac_addr = props.get("mac-address", "").strip()
        os_name = props.get("operating-system", "").strip()

        addresses: list[dict[str, Any]] = []
        if host_ip:
            addr_type = "ipv6" if ":" in host_ip else "ipv4"
            addresses.append({"address_type": addr_type, "value": host_ip, "is_primary": True})
        elif raw_host_name and all(c.isdigit() or c in ".:" for c in raw_host_name):
            addr_type = "ipv6" if ":" in raw_host_name else "ipv4"
            host_ip = raw_host_name
            addresses.append({"address_type": addr_type, "value": raw_host_name, "is_primary": True})

        if mac_addr:
            addresses.append({"address_type": "mac", "value": mac_addr, "is_primary": False})

        hostnames: list[str] = []
        if host_fqdn:
            hostnames.append(host_fqdn)
        if raw_host_name and raw_host_name != host_ip and raw_host_name not in hostnames:
            hostnames.append(raw_host_name)

        if not addresses and not hostnames:
            warnings.append("Skipped Nessus <ReportHost> with no identifying address or hostname.")
            continue

        display_name = hostnames[0] if hostnames else (host_ip or raw_host_name)
        canonical_key = f"host:{(host_ip or hostnames[0]).lower()}"
        in_scope, scope_reason = _check_scope(addresses, hostnames, approved_scope_cidrs)
        if not in_scope:
            out_of_scope_hosts.append(display_name)

        seen_ports: set[tuple[int, str]] = set()
        services: list[dict[str, Any]] = []

        for item in report_host.findall("./ReportItem"):
            port_str = (item.attrib.get("port") or "0").strip()
            proto = (item.attrib.get("protocol") or "tcp").strip().lower()
            svc_name = (item.attrib.get("svc_name") or "general").strip()
            plugin_id = (item.attrib.get("pluginID") or "0").strip()
            plugin_name = (item.attrib.get("pluginName") or f"Plugin {plugin_id}").strip()
            sev_num = (item.attrib.get("severity") or "0").strip()
            severity = _SEVERITY_MAP.get(sev_num, "info")

            if port_str.isdigit():
                port_num = int(port_str)
                if 1 <= port_num <= 65535 and proto in ("tcp", "udp") and (port_num, proto) not in seen_ports:
                    seen_ports.add((port_num, proto))
                    services.append(
                        {
                            "port": port_num,
                            "protocol": proto,
                            "state": "open",
                            "service_name": svc_name or "unknown",
                            "product": None,
                            "version": None,
                            "banner_raw": f"nessus:{svc_name}",
                            "confidence": 0.72,
                        }
                    )

            cves: list[str] = []
            for cve_el in item.findall("./cve"):
                if cve_el.text:
                    for match in _CVE_RE.findall(cve_el.text):
                        norm_cve = match.upper()
                        if norm_cve not in cves:
                            cves.append(norm_cve)

            if not cves and sev_num == "0":
                continue

            cvss3_txt = (item.findtext("./cvss3_base_score") or "").strip()
            cvss2_txt = (item.findtext("./cvss_base_score") or "").strip()
            cvss3_vec = (item.findtext("./cvss3_vector") or "").strip() or None
            cvss2_vec = (item.findtext("./cvss_vector") or "").strip() or None
            cvss_score: float | None = None
            cvss_version = "3.1"
            cvss_vector: str | None = None
            if cvss3_txt:
                try:
                    cvss_score = float(cvss3_txt)
                    cvss_version = "3.1"
                    cvss_vector = cvss3_vec
                except ValueError:
                    cvss_score = None
            elif cvss2_txt:
                try:
                    cvss_score = float(cvss2_txt)
                    cvss_version = "2.0"
                    cvss_vector = cvss2_vec
                except ValueError:
                    cvss_score = None

            plugin_output = (item.findtext("./plugin_output") or "").strip()[:1200]
            solution = (item.findtext("./solution") or "").strip()[:800]
            description = (item.findtext("./description") or "").strip()[:1200]
            scanner_ctx = f"{svc_name}:{port_str}/{proto}:plugin:{plugin_id}"

            cve_targets = cves if cves else [None]
            for cve_val in cve_targets:
                raw_key = f"{canonical_key}|{plugin_id}|{cve_val or 'plugin'}|{scanner_ctx}"
                dedup_key = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:48]
                if dedup_key in seen_finding_keys:
                    continue
                seen_finding_keys.add(dedup_key)
                findings.append(
                    {
                        "asset_key": canonical_key,
                        "in_scope": in_scope,
                        "port": int(port_str) if port_str.isdigit() and int(port_str) > 0 else None,
                        "protocol": proto if proto in ("tcp", "udp") else None,
                        "cve_id": cve_val,
                        "cvss_version": cvss_version,
                        "cvss_vector": cvss_vector,
                        "cvss_score": cvss_score,
                        "severity": severity,
                        "affected_component": plugin_name[:255],
                        "status": "open",
                        "scanner_name": "tenable_nessus",
                        "scanner_context": scanner_ctx[:255],
                        "observed_at": now_iso,
                        "confidence": 0.85 if cve_val else 0.78,
                        "dedup_key": dedup_key,
                        "evidence": {
                            "plugin_id": plugin_id,
                            "plugin_name": plugin_name,
                            "plugin_output": plugin_output,
                            "solution": solution,
                            "description": description,
                            "exploitability_proven": False,
                            "note": "Nessus scanner observation; CVE presence is not proof of exploitability.",
                        },
                    }
                )

        hosts.append(
            {
                "canonical_key": canonical_key,
                "display_name": display_name,
                "addresses": addresses,
                "hostnames": hostnames,
                "status": "up",
                "in_scope": in_scope,
                "scope_reason": scope_reason,
                "confidence": 0.85,
                "raw_attributes": {
                    "operating_system": os_name or None,
                    "host_fqdn": host_fqdn or None,
                    "nessus_name": raw_host_name,
                },
                "services": services,
            }
        )

    return {
        "parser_version": NESSUS_PARSER_VERSION,
        "file_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "hosts": hosts,
        "findings": findings,
        "out_of_scope_hosts": out_of_scope_hosts,
        "warnings": warnings,
    }
