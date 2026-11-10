from pathlib import Path

import pytest

from app.adapters.nmap_xml import ALLOWLISTED_NMAP_SCRIPTS, parse_nmap_xml
from app.core.errors import PayloadTooLargeError, ValidationAppError

SAMPLE_DIR = Path(__file__).resolve().parents[2] / "sample-data"


def test_parse_valid_demo_nmap_xml() -> None:
    raw = (SAMPLE_DIR / "demo_nmap_scan.xml").read_bytes()
    res = parse_nmap_xml(
        raw_bytes=raw,
        filename="demo_nmap_scan.xml",
        approved_scope_cidrs=["10.10.0.0/16", "lab.sentinelgraph.invalid"],
    )
    assert len(res.hosts) == 5
    assert res.out_of_scope_hosts == []
    web = next(h for h in res.hosts if h.canonical_key == "host:10.10.1.10")
    assert web.in_scope is True
    assert any(s.port == 443 and s.protocol == "tcp" for s in web.services)
    # Non-allowlisted script ids must never appear in service.scripts
    for host in res.hosts:
        for svc in host.services:
            for sc in svc.scripts:
                assert sc["id"] in ALLOWLISTED_NMAP_SCRIPTS


def test_out_of_scope_hosts_flagged() -> None:
    raw = (SAMPLE_DIR / "demo_nmap_scan.xml").read_bytes()
    res = parse_nmap_xml(
        raw_bytes=raw,
        filename="demo_nmap_scan.xml",
        approved_scope_cidrs=["10.10.1.0/24"],  # excludes 10.10.2.x, 10.10.3.x, 10.10.4.x
    )
    assert len(res.out_of_scope_hosts) > 0
    in_scope_hosts = [h for h in res.hosts if h.in_scope]
    assert len(in_scope_hosts) >= 1


def test_reject_xxe_and_dtd() -> None:
    xxe_payload = b"""<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<nmaprun scanner="nmap"><host><address addr="10.10.1.1" addrtype="ipv4"/></host></nmaprun>"""
    with pytest.raises(ValidationAppError) as exc_info:
        parse_nmap_xml(
            raw_bytes=xxe_payload,
            filename="evil.xml",
            approved_scope_cidrs=["10.10.0.0/16"],
        )
    assert exc_info.value.code == "UNSAFE_XML_REJECTED"


def test_reject_billion_laughs_entity_expansion() -> None:
    laughs = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<nmaprun scanner="nmap">&lol1;</nmaprun>"""
    with pytest.raises(ValidationAppError) as exc_info:
        parse_nmap_xml(
            raw_bytes=laughs,
            filename="bombs.xml",
            approved_scope_cidrs=["10.10.0.0/16"],
        )
    assert exc_info.value.code == "UNSAFE_XML_REJECTED"


def test_reject_non_xml_extension_empty_and_oversized() -> None:
    with pytest.raises(ValidationAppError) as ext_err:
        parse_nmap_xml(raw_bytes=b"<nmaprun/>", filename="scan.txt", approved_scope_cidrs=["10.0.0.0/8"])
    assert ext_err.value.code == "INVALID_FILE_EXTENSION"

    with pytest.raises(ValidationAppError) as empty_err:
        parse_nmap_xml(raw_bytes=b"", filename="empty.xml", approved_scope_cidrs=["10.0.0.0/8"])
    assert empty_err.value.code == "EMPTY_FILE"

    with pytest.raises(PayloadTooLargeError):
        parse_nmap_xml(
            raw_bytes=b"<nmaprun/>" * 50,
            filename="big.xml",
            approved_scope_cidrs=["10.0.0.0/8"],
            max_bytes=64,
        )


def test_dedup_ports_and_ignore_non_allowlisted_scripts() -> None:
    xml = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="10.10.1.99" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24" conf="10"/>
        <script id="http-title" output="Welcome"/>
        <script id="arbitrary-rce-script" output="ignored"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24" conf="10"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
    res = parse_nmap_xml(raw_bytes=xml, filename="test.xml", approved_scope_cidrs=["10.10.0.0/16"])
    assert len(res.hosts) == 1
    assert len(res.hosts[0].services) == 1
    assert [s["id"] for s in res.hosts[0].services[0].scripts] == ["http-title"]
    assert res.ignored_scripts_count == 1
