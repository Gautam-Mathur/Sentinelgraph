import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from app.adapters.identity_export import _scan_forbidden_keys
from app.adapters.nmap_xml import _check_scope
from app.core.errors import FieldError, PayloadTooLargeError, ValidationAppError

BLOODHOUND_PARSER_VERSION = "bloodhound_json_v1.0.0"
AWS_IAM_EXPORT_PARSER_VERSION = "aws_iam_export_v1.0.0"

_ADMIN_RIGHTS = frozenset(
    {
        "adminto",
        "genericall",
        "writedacl",
        "writeowner",
        "forcechangepassword",
        "allextendedrights",
        "dcsync",
        "getchangesall",
        "genericwrite",
    }
)


def _load_clean_json(raw_bytes: bytes, filename: str, max_bytes: int) -> dict[str, Any]:
    if not filename.lower().endswith(".json"):
        raise ValidationAppError(
            code="INVALID_FILE_EXTENSION",
            message="Directory/cloud IAM export requires a .json file extension.",
        )
    if len(raw_bytes) == 0:
        raise ValidationAppError(code="EMPTY_FILE", message="Uploaded JSON export is empty.")
    if len(raw_bytes) > max_bytes:
        raise PayloadTooLargeError(f"Uploaded file exceeds {max_bytes} bytes.")

    try:
        raw_obj = json.loads(raw_bytes.decode("utf-8"))
    except Exception as exc:
        raise ValidationAppError(code="MALFORMED_JSON", message=f"Invalid JSON payload: {exc}") from exc

    if not isinstance(raw_obj, dict):
        raise ValidationAppError(code="INVALID_EXPORT_SCHEMA", message="Expected top-level JSON object.")

    forbidden_hits = _scan_forbidden_keys(raw_obj)
    if forbidden_hits:
        raise ValidationAppError(
            code="FORBIDDEN_CREDENTIAL_FIELD",
            message=(
                "Export rejected: password hashes, NTLM hashes, secrets, or session tokens "
                "must never be ingested into SentinelGraph."
            ),
            field_errors=[
                FieldError(field=p, message="Forbidden credential field", code="forbidden_secret")
                for p in forbidden_hits[:10]
            ],
        )
    return raw_obj


def parse_bloodhound_json(
    *,
    raw_bytes: bytes,
    filename: str,
    approved_scope_cidrs: list[str],
    max_bytes: int = 20 * 1024 * 1024,
) -> dict[str, Any]:
    raw_obj = _load_clean_json(raw_bytes, filename, max_bytes)
    now_iso = datetime.now(UTC).isoformat()

    users_raw: list[dict[str, Any]] = []
    groups_raw: list[dict[str, Any]] = []
    computers_raw: list[dict[str, Any]] = []

    if isinstance(raw_obj.get("meta"), dict) and isinstance(raw_obj.get("data"), list):
        mtype = str(raw_obj["meta"].get("type") or "").lower()
        entries = [x for x in raw_obj["data"] if isinstance(x, dict)]
        if mtype == "users":
            users_raw = entries
        elif mtype == "groups":
            groups_raw = entries
        elif mtype == "computers":
            computers_raw = entries
        else:
            raise ValidationAppError(
                code="INVALID_BLOODHOUND_SCHEMA",
                message=f"Unsupported BloodHound meta.type '{mtype}'.",
            )
    else:
        bundle = raw_obj.get("data") if isinstance(raw_obj.get("data"), dict) else raw_obj
        if not any(isinstance(bundle.get(k), list) for k in ("users", "groups", "computers")):
            raise ValidationAppError(
                code="INVALID_BLOODHOUND_SCHEMA",
                message="Expected BloodHound JSON with 'meta/data' or 'users'/'groups'/'computers' arrays.",
            )
        users_raw = [x for x in (bundle.get("users") or []) if isinstance(x, dict)]
        groups_raw = [x for x in (bundle.get("groups") or []) if isinstance(x, dict)]
        computers_raw = [x for x in (bundle.get("computers") or []) if isinstance(x, dict)]

    identities: list[dict[str, Any]] = []
    groups: list[dict[str, Any]] = []
    assets: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    out_of_scope_hosts: list[str] = []
    warnings: list[str] = []

    id_to_kind_key: dict[str, tuple[str, str]] = {}

    for u in users_raw:
        props = u.get("Properties") or {}
        oid = str(u.get("ObjectIdentifier") or props.get("objectid") or props.get("name") or "").strip()
        if not oid:
            continue
        pname = str(props.get("name") or props.get("samaccountname") or oid)
        dname = str(props.get("displayname") or props.get("samaccountname") or pname)
        admincount = bool(props.get("admincount") or props.get("highvalue"))
        priv_lvl = "privileged" if admincount or "admin" in pname.lower() else "standard"
        ident_key = oid
        id_to_kind_key[oid] = ("identity", ident_key)
        id_to_kind_key[pname.lower()] = ("identity", ident_key)
        identities.append(
            {
                "external_id": ident_key[:255],
                "provider": "active_directory",
                "identity_type": "service_account" if props.get("hasspn") or "svc" in pname.lower() else "human_user",
                "display_name": dname[:255],
                "principal_name": pname[:255],
                "enabled": bool(props.get("enabled", True)),
                "privilege_level": priv_lvl,
                "privilege_indicators": ["ad_admincount"] if admincount else [],
                "auth_metadata": {
                    "hasspn": bool(props.get("hasspn", False)),
                    "dontreqpreauth": bool(props.get("dontreqpreauth", False)),
                    "domain": props.get("domain"),
                },
                "confidence": 0.9,
                "observed_at": now_iso,
            }
        )

    for g in groups_raw:
        props = g.get("Properties") or {}
        oid = str(g.get("ObjectIdentifier") or props.get("name") or "").strip()
        if not oid:
            continue
        gname = str(props.get("name") or oid)
        is_high = bool(props.get("highvalue") or props.get("admincount") or "admin" in gname.lower())
        id_to_kind_key[oid] = ("group", oid)
        id_to_kind_key[gname.lower()] = ("group", oid)
        groups.append(
            {
                "external_id": oid[:255],
                "provider": "active_directory",
                "display_name": gname[:255],
                "group_type": "admin_group" if is_high else "security_group",
                "privilege_indicators": ["highvalue"] if is_high else [],
                "enabled": True,
                "confidence": 0.92,
                "observed_at": now_iso,
            }
        )

    for c in computers_raw:
        props = c.get("Properties") or {}
        oid = str(c.get("ObjectIdentifier") or props.get("name") or "").strip()
        cname = str(props.get("name") or props.get("dnshostname") or oid).strip()
        if not cname:
            continue
        ips = [str(ip) for ip in (props.get("ip_addresses") or []) if ip]
        addresses = [{"address_type": "ipv6" if ":" in ip else "ipv4", "value": ip, "is_primary": idx == 0} for idx, ip in enumerate(ips)]
        hostnames = [cname]
        canon = f"host:{(ips[0] if ips else cname).lower()}"
        in_scope, _ = _check_scope(addresses, hostnames, approved_scope_cidrs)
        if not in_scope and (addresses or any("." in e and "/" not in e for e in approved_scope_cidrs)):
            out_of_scope_hosts.append(cname)
        elif not in_scope:
            in_scope = True
            warnings.append(f"Directory computer '{cname}' imported without IP address match (CIDR-only scope).")

        if oid:
            id_to_kind_key[oid] = ("asset", canon)
        id_to_kind_key[cname.lower()] = ("asset", canon)
        assets.append(
            {
                "canonical_key": canon[:255],
                "display_name": cname[:255],
                "asset_type": "server",
                "environment": "prod",
                "criticality": "high" if bool(props.get("unconstraineddelegation") or "dc" in cname.lower()) else "medium",
                "is_crown_jewel": "dc" in cname.lower(),
                "is_external_entry": False,
                "addresses": addresses,
                "in_scope": in_scope,
                "confidence": 0.88,
                "raw_attributes": {
                    "operating_system": props.get("operatingsystem"),
                    "unconstrained_delegation": bool(props.get("unconstraineddelegation", False)),
                },
            }
        )

    # Extract Members and Aces
    for g in groups_raw:
        g_oid = str(g.get("ObjectIdentifier") or (g.get("Properties") or {}).get("name") or "").strip()
        if not g_oid:
            continue
        for m in g.get("Members") or []:
            if not isinstance(m, dict):
                continue
            moid = str(m.get("ObjectIdentifier") or "").strip()
            mtype = str(m.get("ObjectType") or m.get("MemberType") or "User").lower()
            src_kind = "group" if mtype == "group" else "identity"
            if moid:
                relationships.append(
                    {
                        "source_kind": src_kind,
                        "source_key": moid,
                        "target_kind": "group",
                        "target_key": g_oid,
                        "relation_type": "MEMBER_OF",
                        "fact_kind": "observed_fact",
                        "confidence": 0.92,
                        "valid_from": now_iso,
                        "source_product": "bloodhound",
                        "source_record_id": f"bh:member:{moid}->{g_oid}",
                        "metadata": {"object_type": mtype},
                    }
                )
        for ace in g.get("Aces") or []:
            if not isinstance(ace, dict):
                continue
            rname = str(ace.get("RightName") or "").lower()
            p_oid = str(ace.get("PrincipalSID") or ace.get("PrincipalIdentifier") or "").strip()
            ptype = str(ace.get("PrincipalType") or "Group").lower()
            if p_oid and rname in _ADMIN_RIGHTS:
                src_kind = "identity" if ptype == "user" else ("group" if ptype == "group" else "asset")
                relationships.append(
                    {
                        "source_kind": src_kind,
                        "source_key": p_oid,
                        "target_kind": "group",
                        "target_key": g_oid,
                        "relation_type": "CAN_ADMINISTER",
                        "fact_kind": "observed_fact",
                        "confidence": 0.88,
                        "valid_from": now_iso,
                        "source_product": "bloodhound",
                        "source_record_id": f"bh:ace:{p_oid}->{g_oid}:{rname}",
                        "metadata": {"right_name": ace.get("RightName")},
                    }
                )

    for c in computers_raw:
        c_oid = str(c.get("ObjectIdentifier") or (c.get("Properties") or {}).get("name") or "").strip()
        target_pair = id_to_kind_key.get(c_oid)
        if not target_pair:
            continue
        target_key = target_pair[1]
        for ace in c.get("Aces") or []:
            if not isinstance(ace, dict):
                continue
            rname = str(ace.get("RightName") or "").lower()
            p_oid = str(ace.get("PrincipalSID") or ace.get("PrincipalIdentifier") or "").strip()
            ptype = str(ace.get("PrincipalType") or "Group").lower()
            if p_oid and rname in _ADMIN_RIGHTS:
                src_kind = "identity" if ptype == "user" else ("group" if ptype == "group" else "asset")
                relationships.append(
                    {
                        "source_kind": src_kind,
                        "source_key": p_oid,
                        "target_kind": "asset",
                        "target_key": target_key,
                        "relation_type": "CAN_ADMINISTER",
                        "fact_kind": "observed_fact",
                        "confidence": 0.88,
                        "valid_from": now_iso,
                        "source_product": "bloodhound",
                        "source_record_id": f"bh:comp_ace:{p_oid}->{target_key}:{rname}",
                        "metadata": {"right_name": ace.get("RightName")},
                    }
                )
        for la in c.get("LocalAdmins") or []:
            if not isinstance(la, dict):
                continue
            p_oid = str(la.get("ObjectIdentifier") or la.get("PrincipalSID") or "").strip()
            ptype = str(la.get("ObjectType") or "Group").lower()
            if p_oid:
                src_kind = "identity" if ptype == "user" else "group"
                relationships.append(
                    {
                        "source_kind": src_kind,
                        "source_key": p_oid,
                        "target_kind": "asset",
                        "target_key": target_key,
                        "relation_type": "CAN_ADMINISTER",
                        "fact_kind": "observed_fact",
                        "confidence": 0.9,
                        "valid_from": now_iso,
                        "source_product": "bloodhound",
                        "source_record_id": f"bh:localadmin:{p_oid}->{target_key}",
                        "metadata": {"right_name": "AdminTo"},
                    }
                )

    return {
        "parser_version": BLOODHOUND_PARSER_VERSION,
        "file_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "identities": identities,
        "groups": groups,
        "assets": assets,
        "relationships": relationships,
        "out_of_scope_hosts": out_of_scope_hosts,
        "warnings": warnings,
    }


def parse_aws_iam_export_json(
    *,
    raw_bytes: bytes,
    filename: str,
    max_bytes: int = 20 * 1024 * 1024,
) -> dict[str, Any]:
    raw_obj = _load_clean_json(raw_bytes, filename, max_bytes)
    now_iso = str(raw_obj.get("observed_at") or datetime.now(UTC).isoformat())
    account_id = str(raw_obj.get("account_id") or "000000000000")

    roles_raw = raw_obj.get("roles") or raw_obj.get("Roles") or []
    users_raw = raw_obj.get("users") or raw_obj.get("Users") or []
    groups_raw = raw_obj.get("groups") or raw_obj.get("Groups") or []
    resources_raw = raw_obj.get("resources") or raw_obj.get("instances") or raw_obj.get("Instances") or []
    sgs_raw = raw_obj.get("security_groups") or raw_obj.get("SecurityGroups") or []

    if not any(isinstance(x, list) and len(x) > 0 for x in (roles_raw, users_raw, groups_raw, resources_raw, sgs_raw)):
        raise ValidationAppError(
            code="INVALID_AWS_EXPORT_SCHEMA",
            message="Expected AWS offline IAM/resource snapshot with 'roles', 'users', 'groups', 'resources', or 'security_groups'.",
        )

    identities: list[dict[str, Any]] = []
    groups: list[dict[str, Any]] = []
    assets: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []

    public_sg_ids: set[str] = set()
    for sg in sgs_raw:
        if not isinstance(sg, dict):
            continue
        sg_id = str(sg.get("group_id") or sg.get("GroupId") or "")
        if not sg_id:
            continue
        ingress = sg.get("ingress_rules") or sg.get("IpPermissions") or []
        allows_public = bool(sg.get("allows_public_ingress", False))
        for rule in ingress:
            if not isinstance(rule, dict):
                continue
            cidr = str(rule.get("cidr_ip") or rule.get("CidrIp") or "")
            if cidr in ("0.0.0.0/0", "::/0"):
                allows_public = True
            for r in rule.get("IpRanges") or []:
                if isinstance(r, dict) and r.get("CidrIp") in ("0.0.0.0/0", "::/0"):
                    allows_public = True
        if allows_public:
            public_sg_ids.add(sg_id)

    for g in groups_raw:
        if not isinstance(g, dict):
            continue
        gname = str(g.get("group_name") or g.get("GroupName") or "")
        arn = str(g.get("arn") or g.get("Arn") or f"arn:aws:iam::{account_id}:group/{gname}")
        if not gname and not arn:
            continue
        is_admin = bool(g.get("is_admin")) or "admin" in gname.lower()
        groups.append(
            {
                "external_id": arn[:255],
                "provider": "aws_iam",
                "display_name": (gname or arn)[:255],
                "group_type": "admin_group" if is_admin else "security_group",
                "privilege_indicators": ["aws_admin_group"] if is_admin else [],
                "enabled": True,
                "confidence": 0.9,
                "observed_at": now_iso,
            }
        )

    role_arns: dict[str, str] = {}
    for r in roles_raw:
        if not isinstance(r, dict):
            continue
        rname = str(r.get("role_name") or r.get("RoleName") or "")
        arn = str(r.get("arn") or r.get("Arn") or f"arn:aws:iam::{account_id}:role/{rname}")
        if not rname and not arn:
            continue
        policies = [str(p) for p in (r.get("attached_policies") or [])]
        is_priv = (
            bool(r.get("is_privileged"))
            or bool(r.get("inline_admin"))
            or any("administrator" in p.lower() or p == "*" for p in policies)
            or "admin" in rname.lower()
        )
        role_arns[arn] = arn
        if rname:
            role_arns[rname] = arn
        identities.append(
            {
                "external_id": arn[:255],
                "provider": "aws_iam",
                "identity_type": "role_identity",
                "display_name": (rname or arn)[:255],
                "principal_name": arn[:255],
                "enabled": True,
                "privilege_level": "privileged" if is_priv else "standard",
                "privilege_indicators": policies[:10],
                "auth_metadata": {"account_id": account_id, "policies": policies[:20]},
                "confidence": 0.92,
                "observed_at": now_iso,
            }
        )

    for u in users_raw:
        if not isinstance(u, dict):
            continue
        uname = str(u.get("user_name") or u.get("UserName") or "")
        arn = str(u.get("arn") or u.get("Arn") or f"arn:aws:iam::{account_id}:user/{uname}")
        if not uname and not arn:
            continue
        is_admin = bool(u.get("is_admin")) or "admin" in uname.lower()
        identities.append(
            {
                "external_id": arn[:255],
                "provider": "aws_iam",
                "identity_type": "human_user",
                "display_name": (uname or arn)[:255],
                "principal_name": arn[:255],
                "enabled": True,
                "privilege_level": "privileged" if is_admin else "standard",
                "privilege_indicators": ["aws_iam_admin"] if is_admin else [],
                "auth_metadata": {"account_id": account_id},
                "confidence": 0.9,
                "observed_at": now_iso,
            }
        )
        for g_ref in u.get("groups") or []:
            g_arn = str(g_ref)
            if not g_arn.startswith("arn:"):
                g_arn = f"arn:aws:iam::{account_id}:group/{g_arn}"
            relationships.append(
                {
                    "source_kind": "identity",
                    "source_key": arn,
                    "target_kind": "group",
                    "target_key": g_arn,
                    "relation_type": "MEMBER_OF",
                    "fact_kind": "observed_fact",
                    "confidence": 0.92,
                    "valid_from": now_iso,
                    "source_product": "aws_iam_export",
                    "source_record_id": f"aws:mem:{arn}->{g_arn}",
                    "metadata": {},
                }
            )

    for res in resources_raw:
        if not isinstance(res, dict):
            continue
        rid = str(res.get("resource_id") or res.get("InstanceId") or res.get("arn") or "")
        name = str(res.get("name") or rid)
        if not rid:
            continue
        canon = f"aws:{rid.lower()}"[:255]
        sg_ids = [str(s) for s in (res.get("security_group_ids") or [])]
        is_ext = bool(res.get("is_external_entry")) or any(s in public_sg_ids for s in sg_ids)
        ip = str(res.get("ip_address") or res.get("PrivateIpAddress") or "").strip()
        addresses = (
            [{"address_type": "ipv6" if ":" in ip else "ipv4", "value": ip, "is_primary": True}]
            if ip
            else []
        )
        assets.append(
            {
                "canonical_key": canon,
                "display_name": name[:255],
                "asset_type": str(res.get("asset_type") or "cloud_resource"),
                "environment": str(res.get("environment") or "prod"),
                "criticality": str(res.get("criticality") or ("critical" if res.get("is_crown_jewel") else "high")),
                "is_external_entry": is_ext,
                "is_crown_jewel": bool(res.get("is_crown_jewel", False)),
                "addresses": addresses,
                "confidence": 0.9,
                "raw_attributes": {"account_id": account_id, "arn": res.get("arn"), "security_groups": sg_ids},
            }
        )
        role_ref = res.get("role_arn")
        if role_ref and str(role_ref) in role_arns:
            relationships.append(
                {
                    "source_kind": "asset",
                    "source_key": canon,
                    "target_kind": "identity",
                    "target_key": role_arns[str(role_ref)],
                    "relation_type": "HAS_ROLE",
                    "fact_kind": "observed_fact",
                    "confidence": 0.9,
                    "valid_from": now_iso,
                    "source_product": "aws_iam_export",
                    "source_record_id": f"aws:instance_role:{canon}->{role_ref}",
                    "metadata": {"account_id": account_id},
                }
            )
        for admin_target in res.get("administers_assets") or []:
            relationships.append(
                {
                    "source_kind": "asset",
                    "source_key": canon,
                    "target_kind": "asset",
                    "target_key": str(admin_target).lower(),
                    "relation_type": "CAN_ADMINISTER",
                    "fact_kind": "observed_fact",
                    "confidence": 0.85,
                    "valid_from": now_iso,
                    "source_product": "aws_iam_export",
                    "source_record_id": f"aws:admin:{canon}->{admin_target}",
                    "metadata": {},
                }
            )

    for r in roles_raw:
        if not isinstance(r, dict):
            continue
        rname = str(r.get("role_name") or r.get("RoleName") or "")
        arn = str(r.get("arn") or r.get("Arn") or f"arn:aws:iam::{account_id}:role/{rname}")
        for target_asset_key in r.get("can_administer_assets") or []:
            relationships.append(
                {
                    "source_kind": "identity",
                    "source_key": arn,
                    "target_kind": "asset",
                    "target_key": str(target_asset_key).lower(),
                    "relation_type": "CAN_ADMINISTER",
                    "fact_kind": "observed_fact",
                    "confidence": 0.9,
                    "valid_from": now_iso,
                    "source_product": "aws_iam_export",
                    "source_record_id": f"aws:role_admin:{arn}->{target_asset_key}",
                    "metadata": {"account_id": account_id},
                }
            )

    return {
        "parser_version": AWS_IAM_EXPORT_PARSER_VERSION,
        "file_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "account_id": account_id,
        "identities": identities,
        "groups": groups,
        "assets": assets,
        "relationships": relationships,
        "warnings": [],
    }
