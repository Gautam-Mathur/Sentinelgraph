import hashlib
import ipaddress
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import defusedxml.ElementTree as ET
import magic
from defusedxml.common import DefusedXmlException

from app.core.errors import FieldError, PayloadTooLargeError, ValidationAppError

NMAP_PARSER_VERSION = "nmap_xml_v1.0.0"

ALLOWLISTED_NMAP_SCRIPTS: frozenset[str] = frozenset(
    {
        "http-title",
        "http-server-header",
        "ssl-cert",
        "ssh-hostkey",
        "banner",
    }
)

MAX_HOSTS_PER_IMPORT = 5000
MAX_PORTS_PER_HOST = 2000


@dataclass
class ParsedServiceCandidate:
    port: int
    protocol: str
    state: str
    service_name: str
    product: str | None
    version: str | None
    banner_raw: str | None
    confidence: float
    scripts: list[dict[str, str]] = field(default_factory=list)


@dataclass
class ParsedHostCandidate:
    canonical_key: str
    display_name: str
    addresses: list[dict[str, Any]]
    hostnames: list[str]
    status: str
    in_scope: bool
    scope_reason: str
    services: list[ParsedServiceCandidate] = field(default_factory=list)
    confidence: float = 0.75
    raw_attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class NmapParseResult:
    parser_version: str
    file_sha256: str
    scan_metadata: dict[str, Any]
    hosts: list[ParsedHostCandidate]
    ignored_scripts_count: int
    out_of_scope_hosts: list[str]
    warnings: list[str]


def _check_scope(
    addresses: list[dict[str, Any]],
    hostnames: list[str],
    approved_scope_cidrs: list[str],
) -> tuple[bool, str]:
    if not approved_scope_cidrs:
        return False, "Assessment has no approved scope CIDRs/domains configured."

    ip_nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    domain_suffixes: list[str] = []
    for entry in approved_scope_cidrs:
        cleaned = entry.strip().lower()
        if not cleaned:
            continue
        try:
            ip_nets.append(ipaddress.ip_network(cleaned, strict=False))
        except ValueError:
            domain_suffixes.append(cleaned)

    for addr in addresses:
        if addr.get("address_type") in ("ipv4", "ipv6"):
            try:
                ip_obj = ipaddress.ip_address(addr["value"])
                for net in ip_nets:
                    if ip_obj in net:
                        return True, f"IP {ip_obj} matched approved CIDR {net}"
            except ValueError:
                continue

    for hn in hostnames:
        low_hn = hn.lower()
        for suf in domain_suffixes:
            if low_hn == suf or low_hn.endswith(f".{suf}"):
                return True, f"Hostname {hn} matched approved scope {suf}"

    return False, "No host IP or hostname matched assessment approved scope."


def validate_xml_upload(
    *,
    raw_bytes: bytes,
    filename: str,
    max_bytes: int,
) -> str:
    if not filename.lower().endswith(".xml"):
        raise ValidationAppError(
            code="INVALID_FILE_EXTENSION",
            message="Nmap imports require a .xml file extension.",
            field_errors=[FieldError(field="file", message="Expected .xml file", code="invalid_ext")],
        )
    if len(raw_bytes) == 0:
        raise ValidationAppError(
            code="EMPTY_FILE",
            message="Uploaded XML file is empty.",
            field_errors=[FieldError(field="file", message="Empty file", code="empty")],
        )
    if len(raw_bytes) > max_bytes:
        raise PayloadTooLargeError(f"Uploaded file exceeds max size of {max_bytes} bytes.")

    try:
        mime = magic.from_buffer(raw_bytes[:4096], mime=True) or "application/octet-stream"
    except Exception:
        mime = "text/plain"

    allowed_mimes = {"text/xml", "application/xml", "text/plain", "application/xhtml+xml"}
    if mime not in allowed_mimes:
        raise ValidationAppError(
            code="INVALID_MIME_TYPE",
            message=f"Rejected file with unexpected MIME type '{mime}'.",
            field_errors=[FieldError(field="file", message=f"Disallowed MIME {mime}", code="mime")],
        )

    head_text = raw_bytes[:512].decode("utf-8", errors="replace").lstrip("\ufeff \t\r\n")
    if not head_text.startswith("<"):
        raise ValidationAppError(
            code="MALFORMED_XML",
            message="File content does not appear to be XML.",
            field_errors=[FieldError(field="file", message="Not valid XML header", code="not_xml")],
        )
    return mime


def parse_nmap_xml(
    *,
    raw_bytes: bytes,
    filename: str,
    approved_scope_cidrs: list[str],
    max_bytes: int = 10 * 1024 * 1024,
    timeout_seconds: float = 10.0,
) -> NmapParseResult:
    t0 = time.perf_counter()
    validate_xml_upload(raw_bytes=raw_bytes, filename=filename, max_bytes=max_bytes)
    file_sha256 = hashlib.sha256(raw_bytes).hexdigest()

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
            message=f"Unable to parse Nmap XML: {exc}",
            field_errors=[FieldError(field="file", message="Malformed XML", code="xml_syntax")],
        ) from exc

    if root.tag != "nmaprun":
        raise ValidationAppError(
            code="INVALID_NMAP_SCHEMA",
            message=f"Expected root element <nmaprun>, got <{root.tag}>.",
            field_errors=[FieldError(field="file", message="Missing <nmaprun> root", code="schema")],
        )

    start_epoch = root.attrib.get("start")
    end_epoch = None
    runstats = root.find("runstats/finished")
    if runstats is not None:
        end_epoch = runstats.attrib.get("time")

    scan_metadata: dict[str, Any] = {
        "scanner": root.attrib.get("scanner", "nmap"),
        "nmap_version": root.attrib.get("version", "unknown"),
        "args": root.attrib.get("args", ""),
        "start_time": (
            datetime.fromtimestamp(int(start_epoch), tz=UTC).isoformat()
            if start_epoch and start_epoch.isdigit()
            else None
        ),
        "end_time": (
            datetime.fromtimestamp(int(end_epoch), tz=UTC).isoformat()
            if end_epoch and end_epoch.isdigit()
            else None
        ),
    }

    hosts: list[ParsedHostCandidate] = []
    out_of_scope_hosts: list[str] = []
    warnings: list[str] = []
    ignored_scripts_count = 0

    host_elems = root.findall("host")
    if len(host_elems) > MAX_HOSTS_PER_IMPORT:
        raise ValidationAppError(
            code="IMPORT_LIMIT_EXCEEDED",
            message=f"Nmap XML contains {len(host_elems)} hosts; limit is {MAX_HOSTS_PER_IMPORT}.",
        )

    for host_el in host_elems:
        if time.perf_counter() - t0 > timeout_seconds:
            raise ValidationAppError(
                code="PARSER_TIMEOUT",
                message="Nmap XML parsing exceeded configured timeout.",
            )

        status_el = host_el.find("status")
        host_status = status_el.attrib.get("state", "unknown") if status_el is not None else "unknown"

        addresses: list[dict[str, Any]] = []
        primary_ip: str | None = None
        for addr_el in host_el.findall("address"):
            atype = addr_el.attrib.get("addrtype", "")
            aval = addr_el.attrib.get("addr", "").strip()
            if not aval or atype not in ("ipv4", "ipv6", "mac"):
                continue
            is_prim = atype in ("ipv4", "ipv6") and primary_ip is None
            if is_prim:
                primary_ip = aval
            addresses.append(
                {
                    "address_type": atype,
                    "value": aval,
                    "is_primary": is_prim,
                    "vendor": addr_el.attrib.get("vendor"),
                }
            )

        hostnames: list[str] = []
        for hn_el in host_el.findall("hostnames/hostname"):
            hname = hn_el.attrib.get("name", "").strip()
            if hname and hname not in hostnames:
                hostnames.append(hname)

        if not addresses and not hostnames:
            warnings.append("Skipped <host> entry with no addresses or hostnames.")
            continue

        display_name = hostnames[0] if hostnames else (primary_ip or addresses[0]["value"])
        canonical_key = f"host:{(primary_ip or hostnames[0]).lower()}"
        in_scope, scope_reason = _check_scope(addresses, hostnames, approved_scope_cidrs)
        if not in_scope:
            out_of_scope_hosts.append(display_name)

        seen_port_proto: set[tuple[int, str]] = set()
        services: list[ParsedServiceCandidate] = []
        port_elems = host_el.findall("ports/port")
        if len(port_elems) > MAX_PORTS_PER_HOST:
            raise ValidationAppError(
                code="IMPORT_LIMIT_EXCEEDED",
                message=f"Host '{display_name}' exceeds max {MAX_PORTS_PER_HOST} ports.",
            )

        for port_el in port_elems:
            proto = port_el.attrib.get("protocol", "tcp").lower()
            port_str = port_el.attrib.get("portid", "")
            if proto not in ("tcp", "udp") or not port_str.isdigit():
                continue
            port_num = int(port_str)
            if not (1 <= port_num <= 65535):
                continue

            key = (port_num, proto)
            if key in seen_port_proto:
                warnings.append(
                    f"Deduplicated duplicate {port_num}/{proto} port entry on host {display_name}."
                )
                continue
            seen_port_proto.add(key)

            pstate_el = port_el.find("state")
            pstate = pstate_el.attrib.get("state", "unknown") if pstate_el is not None else "unknown"
            if pstate != "open":
                continue

            svc_el = port_el.find("service")
            svc_name = "unknown"
            product = None
            version = None
            banner_parts: list[str] = []
            svc_conf = 0.55

            if svc_el is not None:
                svc_name = svc_el.attrib.get("name", "unknown")
                product = svc_el.attrib.get("product")
                version = svc_el.attrib.get("version")
                extrainfo = svc_el.attrib.get("extrainfo")
                raw_conf = svc_el.attrib.get("conf")
                if raw_conf and raw_conf.isdigit():
                    # Nmap conf is 0..10; cap below 0.92 because banners do not prove identity
                    svc_conf = round(min(0.92, max(0.25, int(raw_conf) / 11.0)), 2)
                for val in (product, version, extrainfo):
                    if val:
                        banner_parts.append(val)

            scripts: list[dict[str, str]] = []
            for sc_el in port_el.findall("script"):
                sid = sc_el.attrib.get("id", "")
                if sid in ALLOWLISTED_NMAP_SCRIPTS:
                    scripts.append({"id": sid, "output": sc_el.attrib.get("output", "")[:1000]})
                else:
                    ignored_scripts_count += 1

            services.append(
                ParsedServiceCandidate(
                    port=port_num,
                    protocol=proto,
                    state=pstate,
                    service_name=svc_name,
                    product=product,
                    version=version,
                    banner_raw=" ".join(banner_parts) if banner_parts else None,
                    confidence=svc_conf,
                    scripts=scripts,
                )
            )

        hosts.append(
            ParsedHostCandidate(
                canonical_key=canonical_key,
                display_name=display_name,
                addresses=addresses,
                hostnames=hostnames,
                status=host_status,
                in_scope=in_scope,
                scope_reason=scope_reason,
                services=services,
                confidence=0.8 if host_status == "up" else 0.45,
                raw_attributes={
                    "nmap_status": host_status,
                    "hostnames": hostnames,
                    "addresses": addresses,
                },
            )
        )

    if ignored_scripts_count > 0:
        warnings.append(
            f"Ignored {ignored_scripts_count} non-allowlisted NSE script output(s) per security policy."
        )

    return NmapParseResult(
        parser_version=NMAP_PARSER_VERSION,
        file_sha256=file_sha256,
        scan_metadata=scan_metadata,
        hosts=hosts,
        ignored_scripts_count=ignored_scripts_count,
        out_of_scope_hosts=out_of_scope_hosts,
        warnings=warnings,
    )
