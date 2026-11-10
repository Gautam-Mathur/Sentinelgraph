import contextlib
import os
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.adapters.cloud_iam_export import (
    parse_aws_iam_export_json,
    parse_bloodhound_json,
)
from app.adapters.identity_export import parse_identity_export
from app.adapters.nessus_xml import parse_nessus_xml
from app.adapters.network_topology import parse_topology_import
from app.adapters.nmap_xml import parse_nmap_xml
from app.adapters.relationship_export import parse_relationship_export
from app.adapters.sarif_json import parse_sarif_or_trivy_json
from app.adapters.vuln_scanner import parse_vulnerability_export
from app.core.config import get_settings
from app.core.errors import AppError, ConflictError, NotFoundError, ValidationAppError
from app.core.permissions import Permission, require_permission
from app.core.storage import get_staging_storage
from app.core.telemetry import metrics
from app.db.models import (
    Assessment,
    Asset,
    AssetAddress,
    Finding,
    Group,
    Identity,
    ImportJob,
    Observation,
    Relationship,
    Service,
)
from app.services.audit_service import record_audit_event
from app.services.context import ActorContext


def _cleanup_staged_object(object_key: str | None) -> None:
    if not object_key:
        return
    with contextlib.suppress(Exception):
        get_staging_storage().delete_object(object_key)


def upload_and_stage_import(
    db: Session,
    ctx: ActorContext,
    *,
    assessment_id: uuid.UUID,
    source_format: str,
    filename: str,
    raw_bytes: bytes,
    idempotency_key: str | None,
) -> dict[str, Any]:
    require_permission(ctx.role, Permission.IMPORT_UPLOAD)
    settings = get_settings()

    assessment = db.execute(
        select(Assessment).where(
            Assessment.id == assessment_id, Assessment.tenant_id == ctx.tenant_id
        )
    ).scalar_one_or_none()
    if assessment is None:
        raise NotFoundError(code="ASSESSMENT_NOT_FOUND", message="Assessment not found")
    if assessment.status == "draft":
        raise ValidationAppError(
            code="SCOPE_NOT_APPROVED",
            message="Assessment scope must be approved before uploading imports.",
        )

    idem_key = (idempotency_key or str(uuid.uuid4())).strip()
    existing_idem = db.execute(
        select(ImportJob).where(
            ImportJob.tenant_id == ctx.tenant_id,
            ImportJob.idempotency_key == idem_key,
        )
    ).scalar_one_or_none()
    if existing_idem is not None:
        return _serialize_import(existing_idem)

    safe_name = os.path.basename(filename or "upload.bin")
    storage = get_staging_storage()
    staging_key = f"{ctx.tenant_id}/{uuid.uuid4()}_{safe_name}"

    try:
        storage.put_bytes(staging_key, raw_bytes)
        if source_format == "nmap_xml":
            parsed = parse_nmap_xml(
                raw_bytes=raw_bytes,
                filename=safe_name,
                approved_scope_cidrs=assessment.approved_scope_cidrs,
                max_bytes=settings.max_import_bytes,
                timeout_seconds=settings.parser_timeout_seconds,
            )
            parser_version = parsed.parser_version
            file_sha256 = parsed.file_sha256
            raw_metadata = {
                "scan_metadata": parsed.scan_metadata,
                "ignored_scripts_count": parsed.ignored_scripts_count,
            }
            hosts_payload = [
                {
                    "canonical_key": h.canonical_key,
                    "display_name": h.display_name,
                    "addresses": h.addresses,
                    "hostnames": h.hostnames,
                    "status": h.status,
                    "in_scope": h.in_scope,
                    "scope_reason": h.scope_reason,
                    "confidence": h.confidence,
                    "raw_attributes": h.raw_attributes,
                    "services": [
                        {
                            "port": s.port,
                            "protocol": s.protocol,
                            "state": s.state,
                            "service_name": s.service_name,
                            "product": s.product,
                            "version": s.version,
                            "banner_raw": s.banner_raw,
                            "confidence": s.confidence,
                            "scripts": s.scripts,
                        }
                        for s in h.services
                    ],
                }
                for h in parsed.hosts
            ]
            staged_payload = {
                "format": "nmap_xml",
                "hosts": hosts_payload,
                "out_of_scope_hosts": parsed.out_of_scope_hosts,
            }
            preview_summary = {
                "hosts_detected": len(parsed.hosts),
                "services_detected": sum(len(h.services) for h in parsed.hosts),
                "out_of_scope_count": len(parsed.out_of_scope_hosts),
                "out_of_scope_hosts": parsed.out_of_scope_hosts,
                "ignored_scripts_count": parsed.ignored_scripts_count,
                "warnings": parsed.warnings,
                "scope_valid": len(parsed.out_of_scope_hosts) == 0,
            }
            mime_type = "application/xml"

        elif source_format == "nessus_xml":
            nessus = parse_nessus_xml(
                raw_bytes=raw_bytes,
                filename=safe_name,
                approved_scope_cidrs=assessment.approved_scope_cidrs,
                max_bytes=settings.max_import_bytes,
            )
            parser_version = nessus["parser_version"]
            file_sha256 = nessus["file_sha256"]
            raw_metadata = {"hosts_count": len(nessus["hosts"]), "findings_count": len(nessus["findings"])}
            staged_payload = {"format": "nessus_xml", **nessus}
            preview_summary = {
                "hosts_detected": len(nessus["hosts"]),
                "services_detected": sum(len(h["services"]) for h in nessus["hosts"]),
                "findings_count": len(nessus["findings"]),
                "out_of_scope_count": len(nessus["out_of_scope_hosts"]),
                "out_of_scope_hosts": nessus["out_of_scope_hosts"],
                "warnings": nessus["warnings"],
                "scope_valid": len(nessus["out_of_scope_hosts"]) == 0,
            }
            mime_type = "application/xml"

        elif source_format == "sarif_json":
            sarif = parse_sarif_or_trivy_json(
                raw_bytes=raw_bytes,
                filename=safe_name,
                max_bytes=settings.max_import_bytes,
            )
            parser_version = sarif["parser_version"]
            file_sha256 = sarif["file_sha256"]
            raw_metadata = {
                "source_kind": sarif["source_kind"],
                "duplicates_removed": sarif["duplicates_removed"],
            }
            staged_payload = {"format": "sarif_json", **sarif}
            preview_summary = {
                "source_kind": sarif["source_kind"],
                "assets_detected": len(sarif["assets"]),
                "findings_count": len(sarif["findings"]),
                "duplicates_removed": sarif["duplicates_removed"],
                "warnings": sarif["warnings"],
                "scope_valid": True,
            }
            mime_type = "application/json"

        elif source_format == "bloodhound_json":
            bh = parse_bloodhound_json(
                raw_bytes=raw_bytes,
                filename=safe_name,
                approved_scope_cidrs=assessment.approved_scope_cidrs,
                max_bytes=settings.max_import_bytes,
            )
            parser_version = bh["parser_version"]
            file_sha256 = bh["file_sha256"]
            raw_metadata = {
                "identities_count": len(bh["identities"]),
                "groups_count": len(bh["groups"]),
                "assets_count": len(bh["assets"]),
                "relationships_count": len(bh["relationships"]),
            }
            staged_payload = {"format": "bloodhound_json", **bh}
            preview_summary = {
                "identities_count": len(bh["identities"]),
                "groups_count": len(bh["groups"]),
                "assets_detected": len(bh["assets"]),
                "relationships_count": len(bh["relationships"]),
                "out_of_scope_count": len(bh["out_of_scope_hosts"]),
                "out_of_scope_hosts": bh["out_of_scope_hosts"],
                "warnings": bh["warnings"],
                "scope_valid": len(bh["out_of_scope_hosts"]) == 0,
            }
            mime_type = "application/json"

        elif source_format == "aws_iam_export_json":
            aws_exp = parse_aws_iam_export_json(
                raw_bytes=raw_bytes,
                filename=safe_name,
                max_bytes=settings.max_import_bytes,
            )
            parser_version = aws_exp["parser_version"]
            file_sha256 = aws_exp["file_sha256"]
            raw_metadata = {
                "account_id": aws_exp["account_id"],
                "identities_count": len(aws_exp["identities"]),
                "groups_count": len(aws_exp["groups"]),
                "assets_count": len(aws_exp["assets"]),
            }
            staged_payload = {"format": "aws_iam_export_json", **aws_exp}
            preview_summary = {
                "account_id": aws_exp["account_id"],
                "identities_count": len(aws_exp["identities"]),
                "groups_count": len(aws_exp["groups"]),
                "assets_detected": len(aws_exp["assets"]),
                "relationships_count": len(aws_exp["relationships"]),
                "warnings": aws_exp["warnings"],
                "scope_valid": True,
            }
            mime_type = "application/json"

        elif source_format in ("network_topology_json", "network_topology_csv"):
            topo = parse_topology_import(
                raw_bytes=raw_bytes,
                filename=safe_name,
                max_bytes=settings.max_import_bytes,
            )
            parser_version = topo["parser_version"]
            file_sha256 = topo["file_sha256"]
            raw_metadata = {"subnets_count": len(topo["subnets"])}
            staged_payload = {"format": "network_topology", **topo}
            preview_summary = {
                "subnets_count": len(topo["subnets"]),
                "firewall_rules_count": topo["firewall_rules_count"],
                "reachability_edges_count": len(topo["reachability_candidates"]),
                "warnings": topo["warnings"],
                "scope_valid": True,
            }
            mime_type = "application/json" if source_format.endswith("json") else "text/csv"

        elif source_format == "identity_json":
            ident_data = parse_identity_export(
                raw_bytes=raw_bytes,
                filename=safe_name,
                max_bytes=settings.max_import_bytes,
            )
            parser_version = ident_data["parser_version"]
            file_sha256 = ident_data["file_sha256"]
            raw_metadata = {"source_product": ident_data["source_product"]}
            staged_payload = {"format": "identity_json", **ident_data}
            preview_summary = {
                "identities_count": len(ident_data["identities"]),
                "groups_count": len(ident_data["groups"]),
                "memberships_count": len(ident_data["memberships"]),
                "warnings": [],
                "scope_valid": True,
            }
            mime_type = "application/json"

        elif source_format == "vulnerability_json":
            vuln_data = parse_vulnerability_export(
                raw_bytes=raw_bytes,
                filename=safe_name,
                max_bytes=settings.max_import_bytes,
            )
            parser_version = vuln_data["parser_version"]
            file_sha256 = vuln_data["file_sha256"]
            raw_metadata = {"duplicates_removed": vuln_data["duplicates_removed"]}
            staged_payload = {"format": "vulnerability_json", **vuln_data}
            preview_summary = {
                "findings_count": len(vuln_data["findings"]),
                "duplicates_removed": vuln_data["duplicates_removed"],
                "warnings": ["CVE presence is recorded as an observation, not proof of exploitability."],
                "scope_valid": True,
            }
            mime_type = "application/json"

        elif source_format == "relationship_json":
            rel_data = parse_relationship_export(
                raw_bytes=raw_bytes,
                filename=safe_name,
                max_bytes=settings.max_import_bytes,
            )
            parser_version = rel_data["parser_version"]
            file_sha256 = rel_data["file_sha256"]
            raw_metadata = {}
            staged_payload = {"format": "relationship_json", **rel_data}
            preview_summary = {
                "relationships_count": len(rel_data["relationships"]),
                "warnings": [],
                "scope_valid": True,
            }
            mime_type = "application/json"
        else:
            raise ValidationAppError(
                code="UNSUPPORTED_SOURCE_FORMAT",
                message=f"Unsupported source_format '{source_format}'.",
            )
    except AppError:
        metrics.inc("parse_failures_total")
        _cleanup_staged_object(staging_key)
        raise
    except Exception:
        metrics.inc("parse_failures_total")
        _cleanup_staged_object(staging_key)
        raise

    imp = ImportJob(
        tenant_id=ctx.tenant_id,
        assessment_id=assessment.id,
        uploaded_by_user_id=ctx.user_id,
        filename=safe_name,
        source_format=source_format,
        parser_version=parser_version,
        file_sha256=file_sha256,
        file_size_bytes=len(raw_bytes),
        mime_type=mime_type,
        status="preview_ready",
        idempotency_key=idem_key,
        temp_storage_path=staging_key,
        raw_metadata=raw_metadata,
        preview_summary=preview_summary,
        staged_payload=staged_payload,
    )
    db.add(imp)
    db.flush()

    record_audit_event(
        db,
        tenant_id=ctx.tenant_id,
        actor_user_id=ctx.user_id,
        actor_email=ctx.email,
        action="import.upload",
        object_type="import",
        object_id=str(imp.id),
        outcome="success",
        request_id=ctx.request_id,
        details={
            "filename": safe_name,
            "source_format": source_format,
            "file_sha256": file_sha256,
            "preview_summary": preview_summary,
        },
    )
    db.commit()
    return _serialize_import(imp)


def approve_import(db: Session, ctx: ActorContext, *, import_id: uuid.UUID) -> dict[str, Any]:
    require_permission(ctx.role, Permission.IMPORT_APPROVE)
    imp = db.execute(
        select(ImportJob).where(ImportJob.id == import_id, ImportJob.tenant_id == ctx.tenant_id)
    ).scalar_one_or_none()
    if imp is None:
        raise NotFoundError(code="IMPORT_NOT_FOUND", message="Import not found")
    if imp.status not in ("preview_ready", "approved"):
        raise ConflictError(
            code="INVALID_IMPORT_STATE",
            message=f"Cannot approve import in state '{imp.status}'.",
        )
    if not imp.preview_summary.get("scope_valid", True):
        raise ValidationAppError(
            code="OUT_OF_SCOPE_HOSTS",
            message="Import contains hosts outside assessment approved scope; reject or update scope first.",
        )

    imp.status = "approved"
    imp.approved_by_user_id = ctx.user_id
    db.flush()

    record_audit_event(
        db,
        tenant_id=ctx.tenant_id,
        actor_user_id=ctx.user_id,
        actor_email=ctx.email,
        action="import.approve",
        object_type="import",
        object_id=str(imp.id),
        outcome="success",
        request_id=ctx.request_id,
        details={"source_format": imp.source_format},
    )
    db.commit()
    return _serialize_import(imp)


def reject_import(db: Session, ctx: ActorContext, *, import_id: uuid.UUID, reason: str) -> dict[str, Any]:
    require_permission(ctx.role, Permission.IMPORT_APPROVE)
    imp = db.execute(
        select(ImportJob).where(ImportJob.id == import_id, ImportJob.tenant_id == ctx.tenant_id)
    ).scalar_one_or_none()
    if imp is None:
        raise NotFoundError(code="IMPORT_NOT_FOUND", message="Import not found")
    if imp.status == "committed":
        raise ConflictError(code="ALREADY_COMMITTED", message="Cannot reject an already committed import.")

    _cleanup_staged_object(imp.temp_storage_path)
    imp.status = "rejected"
    imp.temp_storage_path = None
    imp.error_detail = {"rejected_reason": reason}
    db.flush()

    record_audit_event(
        db,
        tenant_id=ctx.tenant_id,
        actor_user_id=ctx.user_id,
        actor_email=ctx.email,
        action="import.reject",
        object_type="import",
        object_id=str(imp.id),
        outcome="success",
        request_id=ctx.request_id,
        details={"reason": reason},
    )
    db.commit()
    return _serialize_import(imp)


def _commit_hosts_and_services(
    db: Session,
    ctx: ActorContext,
    imp: ImportJob,
    *,
    hosts: list[dict[str, Any]],
    source_product: str,
    collection_time: str,
    now: datetime,
    counts: dict[str, int],
    require_in_scope: bool = True,
) -> dict[str, Asset]:
    asset_map: dict[str, Asset] = {}
    for h in hosts:
        if require_in_scope and not h.get("in_scope", False):
            continue
        asset = db.execute(
            select(Asset).where(
                Asset.tenant_id == ctx.tenant_id,
                Asset.canonical_key == h["canonical_key"],
            )
        ).scalar_one_or_none()
        prov_ref = {
            "source_product": source_product,
            "source_record_id": h["canonical_key"],
            "import_id": str(imp.id),
            "collection_time": collection_time,
            "parser_version": imp.parser_version,
            "confidence": h.get("confidence", 0.8),
            "evidence_hash": imp.file_sha256,
        }
        if asset is None:
            asset = Asset(
                tenant_id=ctx.tenant_id,
                canonical_key=h["canonical_key"],
                display_name=h["display_name"],
                asset_type=h.get("asset_type", "server"),
                environment=h.get("environment", "prod"),
                criticality=h.get("criticality", "medium"),
                is_external_entry=bool(h.get("is_external_entry", False)),
                is_crown_jewel=bool(h.get("is_crown_jewel", False)),
                first_seen=now,
                last_seen=now,
                confidence=h.get("confidence", 0.8),
                raw_attributes=h.get("raw_attributes", {}),
                source_refs=[prov_ref],
            )
            db.add(asset)
            db.flush()
        else:
            asset.last_seen = now
            if h.get("is_external_entry"):
                asset.is_external_entry = True
            if h.get("is_crown_jewel"):
                asset.is_crown_jewel = True
            asset.source_refs = [*asset.source_refs, prov_ref]
        asset_map[asset.canonical_key] = asset
        counts["assets"] += 1

        for addr in h.get("addresses", []):
            exists_addr = db.execute(
                select(AssetAddress).where(
                    AssetAddress.tenant_id == ctx.tenant_id,
                    AssetAddress.asset_id == asset.id,
                    AssetAddress.address_type == addr["address_type"],
                    AssetAddress.value == addr["value"],
                )
            ).scalar_one_or_none()
            if exists_addr is None:
                db.add(
                    AssetAddress(
                        tenant_id=ctx.tenant_id,
                        asset_id=asset.id,
                        address_type=addr["address_type"],
                        value=addr["value"],
                        is_primary=bool(addr.get("is_primary", False)),
                        first_seen=now,
                        last_seen=now,
                        provenance=prov_ref,
                    )
                )

        for svc in h.get("services", []):
            svc_row = db.execute(
                select(Service).where(
                    Service.tenant_id == ctx.tenant_id,
                    Service.asset_id == asset.id,
                    Service.assessment_id == imp.assessment_id,
                    Service.port == svc["port"],
                    Service.protocol == svc["protocol"],
                )
            ).scalar_one_or_none()
            svc_prov = {**prov_ref, "source_record_id": f"{h['canonical_key']}:{svc['port']}/{svc['protocol']}"}
            if svc_row is None:
                svc_row = Service(
                    tenant_id=ctx.tenant_id,
                    asset_id=asset.id,
                    assessment_id=imp.assessment_id,
                    port=svc["port"],
                    protocol=svc["protocol"],
                    state=svc["state"],
                    service_name=svc["service_name"],
                    product=svc.get("product"),
                    version=svc.get("version"),
                    banner_raw=svc.get("banner_raw"),
                    confidence=svc["confidence"],
                    provenance=svc_prov,
                )
                db.add(svc_row)
                db.flush()
            else:
                svc_row.state = svc["state"]
                svc_row.service_name = svc["service_name"]
                svc_row.product = svc.get("product")
                svc_row.version = svc.get("version")
                svc_row.banner_raw = svc.get("banner_raw")
                svc_row.confidence = svc["confidence"]
            counts["services"] += 1

            obs = Observation(
                tenant_id=ctx.tenant_id,
                assessment_id=imp.assessment_id,
                import_id=imp.id,
                subject_kind="service",
                subject_id=svc_row.id,
                observation_type="port_service",
                fact_kind="observed_fact",
                source_product=source_product,
                source_record_id=svc_prov["source_record_id"],
                collection_time=now,
                parser_version=imp.parser_version,
                confidence=svc["confidence"],
                evidence_hash=imp.file_sha256,
                raw_payload={"banner_raw": svc.get("banner_raw"), "scripts": svc.get("scripts", [])},
                normalized_payload={
                    "port": svc["port"],
                    "protocol": svc["protocol"],
                    "service_name": svc["service_name"],
                    "product": svc.get("product"),
                    "version": svc.get("version"),
                },
            )
            db.add(obs)
            db.flush()

            rel_exists = db.execute(
                select(Relationship).where(
                    Relationship.tenant_id == ctx.tenant_id,
                    Relationship.assessment_id == imp.assessment_id,
                    Relationship.source_kind == "asset",
                    Relationship.source_id == asset.id,
                    Relationship.target_kind == "service",
                    Relationship.target_id == svc_row.id,
                    Relationship.relation_type == "RUNS_SERVICE",
                )
            ).scalar_one_or_none()
            if rel_exists is None:
                db.add(
                    Relationship(
                        tenant_id=ctx.tenant_id,
                        assessment_id=imp.assessment_id,
                        source_kind="asset",
                        source_id=asset.id,
                        target_kind="service",
                        target_id=svc_row.id,
                        relation_type="RUNS_SERVICE",
                        fact_kind="observed_fact",
                        confidence=svc["confidence"],
                        valid_from=now,
                        provenance=svc_prov,
                        evidence_id=obs.id,
                        edge_metadata={"port": svc["port"], "protocol": svc["protocol"]},
                    )
                )
                counts["relationships"] += 1
    return asset_map


def _commit_identities_and_groups(
    db: Session,
    ctx: ActorContext,
    imp: ImportJob,
    *,
    identities: list[dict[str, Any]],
    groups: list[dict[str, Any]],
    source_product: str,
    now: datetime,
    counts: dict[str, int],
) -> tuple[dict[str, uuid.UUID], dict[str, uuid.UUID]]:
    ident_ids_by_ext: dict[str, uuid.UUID] = {}
    group_ids_by_ext: dict[str, uuid.UUID] = {}

    for i in identities:
        row_i = db.execute(
            select(Identity).where(
                Identity.tenant_id == ctx.tenant_id,
                Identity.provider == i["provider"],
                Identity.external_id == i["external_id"],
            )
        ).scalar_one_or_none()
        prov = {
            "source_product": source_product,
            "source_record_id": i["external_id"],
            "import_id": str(imp.id),
            "collection_time": i["observed_at"],
            "parser_version": imp.parser_version,
            "confidence": i["confidence"],
            "evidence_hash": imp.file_sha256,
        }
        if row_i is None:
            row_i = Identity(
                tenant_id=ctx.tenant_id,
                identity_type=i["identity_type"],
                external_id=i["external_id"],
                provider=i["provider"],
                display_name=i["display_name"],
                principal_name=i["principal_name"],
                enabled=i["enabled"],
                privilege_level=i["privilege_level"],
                privilege_indicators=i["privilege_indicators"],
                auth_metadata=i.get("auth_metadata", {}),
                first_seen=now,
                last_seen=now,
                confidence=i["confidence"],
                source_refs=[prov],
            )
            db.add(row_i)
            db.flush()
        else:
            row_i.last_seen = now
            row_i.source_refs = [*row_i.source_refs, prov]
        ident_ids_by_ext[i["external_id"]] = row_i.id
        counts["identities"] += 1

    for g in groups:
        row_g = db.execute(
            select(Group).where(
                Group.tenant_id == ctx.tenant_id,
                Group.provider == g["provider"],
                Group.external_id == g["external_id"],
            )
        ).scalar_one_or_none()
        prov = {
            "source_product": source_product,
            "source_record_id": g["external_id"],
            "import_id": str(imp.id),
            "collection_time": g["observed_at"],
            "parser_version": imp.parser_version,
            "confidence": g["confidence"],
            "evidence_hash": imp.file_sha256,
        }
        if row_g is None:
            row_g = Group(
                tenant_id=ctx.tenant_id,
                external_id=g["external_id"],
                provider=g["provider"],
                display_name=g["display_name"],
                group_type=g["group_type"],
                privilege_indicators=g["privilege_indicators"],
                enabled=g["enabled"],
                first_seen=now,
                last_seen=now,
                confidence=g["confidence"],
                source_refs=[prov],
            )
            db.add(row_g)
            db.flush()
        else:
            row_g.last_seen = now
            row_g.source_refs = [*row_g.source_refs, prov]
        group_ids_by_ext[g["external_id"]] = row_g.id
        counts["groups"] += 1

    return ident_ids_by_ext, group_ids_by_ext


def _commit_findings(
    db: Session,
    ctx: ActorContext,
    imp: ImportJob,
    *,
    findings: list[dict[str, Any]],
    asset_by_key: dict[str, Asset],
    counts: dict[str, int],
) -> None:
    for f in findings:
        asset_obj = asset_by_key.get(f["asset_key"].lower())
        if asset_obj is None:
            continue
        existing_f = db.execute(
            select(Finding).where(
                Finding.tenant_id == ctx.tenant_id,
                Finding.assessment_id == imp.assessment_id,
                Finding.dedup_key == f["dedup_key"],
            )
        ).scalar_one_or_none()
        if existing_f is not None:
            continue
        prov = {
            "source_product": f["scanner_name"],
            "source_record_id": f["dedup_key"],
            "import_id": str(imp.id),
            "collection_time": f["observed_at"],
            "parser_version": imp.parser_version,
            "confidence": f["confidence"],
            "evidence_hash": imp.file_sha256,
        }
        db.add(
            Finding(
                tenant_id=ctx.tenant_id,
                assessment_id=imp.assessment_id,
                asset_id=asset_obj.id,
                cve_id=f.get("cve_id"),
                cvss_version=f.get("cvss_version"),
                cvss_vector=f.get("cvss_vector"),
                cvss_score=f.get("cvss_score"),
                severity=f["severity"],
                affected_component=f["affected_component"],
                status=f["status"],
                scanner_name=f["scanner_name"],
                scanner_context=f["scanner_context"],
                evidence=f["evidence"],
                observed_at=datetime.fromisoformat(f["observed_at"]),
                confidence=f["confidence"],
                provenance=prov,
                dedup_key=f["dedup_key"],
            )
        )
        counts["findings"] += 1


def _commit_relationships_list(
    db: Session,
    ctx: ActorContext,
    imp: ImportJob,
    *,
    relationships: list[dict[str, Any]],
    lookup: dict[str, dict[str, uuid.UUID]],
    counts: dict[str, int],
) -> None:
    for rel in relationships:
        src_id = lookup.get(rel["source_kind"], {}).get(rel["source_key"])
        tgt_id = lookup.get(rel["target_kind"], {}).get(rel["target_key"])
        if not src_id or not tgt_id:
            continue
        db.add(
            Relationship(
                tenant_id=ctx.tenant_id,
                assessment_id=imp.assessment_id,
                source_kind=rel["source_kind"],
                source_id=src_id,
                target_kind=rel["target_kind"],
                target_id=tgt_id,
                relation_type=rel["relation_type"],
                fact_kind=rel["fact_kind"],
                confidence=rel["confidence"],
                valid_from=datetime.fromisoformat(rel["valid_from"]),
                valid_to=datetime.fromisoformat(rel["valid_to"]) if rel.get("valid_to") else None,
                provenance={
                    "source_product": rel["source_product"],
                    "source_record_id": rel["source_record_id"],
                    "import_id": str(imp.id),
                    "collection_time": rel["valid_from"],
                    "parser_version": imp.parser_version,
                    "confidence": rel["confidence"],
                    "evidence_hash": imp.file_sha256,
                },
                edge_metadata=rel.get("metadata", {}),
            )
        )
        counts["relationships"] += 1


def commit_import(
    db: Session,
    ctx: ActorContext,
    *,
    import_id: uuid.UUID,
) -> dict[str, Any]:
    require_permission(ctx.role, Permission.IMPORT_COMMIT)
    imp = db.execute(
        select(ImportJob).where(ImportJob.id == import_id, ImportJob.tenant_id == ctx.tenant_id)
    ).scalar_one_or_none()
    if imp is None:
        raise NotFoundError(code="IMPORT_NOT_FOUND", message="Import not found")
    if imp.status == "committed":
        return _serialize_import(imp)
    if imp.status != "approved":
        raise ConflictError(
            code="IMPORT_NOT_APPROVED",
            message=f"Import must be approved before commit (current state: '{imp.status}').",
        )
    if not imp.preview_summary.get("scope_valid", True):
        raise ValidationAppError(
            code="OUT_OF_SCOPE_HOSTS",
            message="Out-of-scope hosts detected; commit blocked.",
        )

    now = datetime.now(UTC)
    fmt = imp.staged_payload.get("format")
    committed_counts: dict[str, int] = {
        "assets": 0,
        "services": 0,
        "identities": 0,
        "groups": 0,
        "relationships": 0,
        "findings": 0,
    }

    if fmt == "nmap_xml":
        scan_meta = imp.raw_metadata.get("scan_metadata", {})
        _commit_hosts_and_services(
            db,
            ctx,
            imp,
            hosts=imp.staged_payload.get("hosts", []),
            source_product="nmap",
            collection_time=scan_meta.get("end_time") or now.isoformat(),
            now=now,
            counts=committed_counts,
            require_in_scope=True,
        )

    elif fmt == "nessus_xml":
        committed_assets = _commit_hosts_and_services(
            db,
            ctx,
            imp,
            hosts=imp.staged_payload.get("hosts", []),
            source_product="tenable_nessus",
            collection_time=now.isoformat(),
            now=now,
            counts=committed_counts,
            require_in_scope=True,
        )
        all_assets = {
            a.canonical_key: a
            for a in db.execute(select(Asset).where(Asset.tenant_id == ctx.tenant_id)).scalars()
        }
        all_assets.update(committed_assets)
        scoped_findings = [f for f in imp.staged_payload.get("findings", []) if f.get("in_scope", True)]
        _commit_findings(
            db,
            ctx,
            imp,
            findings=scoped_findings,
            asset_by_key=all_assets,
            counts=committed_counts,
        )

    elif fmt == "sarif_json":
        src_kind = imp.staged_payload.get("source_kind", "sarif")
        committed_assets = _commit_hosts_and_services(
            db,
            ctx,
            imp,
            hosts=imp.staged_payload.get("assets", []),
            source_product=src_kind,
            collection_time=now.isoformat(),
            now=now,
            counts=committed_counts,
            require_in_scope=False,
        )
        all_assets = {
            a.canonical_key: a
            for a in db.execute(select(Asset).where(Asset.tenant_id == ctx.tenant_id)).scalars()
        }
        all_assets.update(committed_assets)
        _commit_findings(
            db,
            ctx,
            imp,
            findings=imp.staged_payload.get("findings", []),
            asset_by_key=all_assets,
            counts=committed_counts,
        )

    elif fmt == "bloodhound_json":
        committed_assets = _commit_hosts_and_services(
            db,
            ctx,
            imp,
            hosts=imp.staged_payload.get("assets", []),
            source_product="bloodhound",
            collection_time=now.isoformat(),
            now=now,
            counts=committed_counts,
            require_in_scope=True,
        )
        ident_ids, group_ids = _commit_identities_and_groups(
            db,
            ctx,
            imp,
            identities=imp.staged_payload.get("identities", []),
            groups=imp.staged_payload.get("groups", []),
            source_product="bloodhound",
            now=now,
            counts=committed_counts,
        )
        asset_by_key = {
            a.canonical_key: a.id
            for a in db.execute(select(Asset).where(Asset.tenant_id == ctx.tenant_id)).scalars()
        }
        for k, a_obj in committed_assets.items():
            asset_by_key[k] = a_obj.id
        all_ident = {
            i.external_id: i.id
            for i in db.execute(select(Identity).where(Identity.tenant_id == ctx.tenant_id)).scalars()
        }
        all_ident.update(ident_ids)
        all_grp = {
            g.external_id: g.id
            for g in db.execute(select(Group).where(Group.tenant_id == ctx.tenant_id)).scalars()
        }
        all_grp.update(group_ids)
        _commit_relationships_list(
            db,
            ctx,
            imp,
            relationships=imp.staged_payload.get("relationships", []),
            lookup={"asset": asset_by_key, "identity": all_ident, "group": all_grp},
            counts=committed_counts,
        )

    elif fmt == "aws_iam_export_json":
        committed_assets = _commit_hosts_and_services(
            db,
            ctx,
            imp,
            hosts=imp.staged_payload.get("assets", []),
            source_product="aws_iam_export",
            collection_time=now.isoformat(),
            now=now,
            counts=committed_counts,
            require_in_scope=False,
        )
        ident_ids, group_ids = _commit_identities_and_groups(
            db,
            ctx,
            imp,
            identities=imp.staged_payload.get("identities", []),
            groups=imp.staged_payload.get("groups", []),
            source_product="aws_iam_export",
            now=now,
            counts=committed_counts,
        )
        asset_by_key = {
            a.canonical_key: a.id
            for a in db.execute(select(Asset).where(Asset.tenant_id == ctx.tenant_id)).scalars()
        }
        for k, a_obj in committed_assets.items():
            asset_by_key[k] = a_obj.id
        all_ident = {
            i.external_id: i.id
            for i in db.execute(select(Identity).where(Identity.tenant_id == ctx.tenant_id)).scalars()
        }
        all_ident.update(ident_ids)
        all_grp = {
            g.external_id: g.id
            for g in db.execute(select(Group).where(Group.tenant_id == ctx.tenant_id)).scalars()
        }
        all_grp.update(group_ids)
        _commit_relationships_list(
            db,
            ctx,
            imp,
            relationships=imp.staged_payload.get("relationships", []),
            lookup={"asset": asset_by_key, "identity": all_ident, "group": all_grp},
            counts=committed_counts,
        )

    elif fmt == "network_topology":
        asset_by_key = {
            a.canonical_key: a
            for a in db.execute(select(Asset).where(Asset.tenant_id == ctx.tenant_id)).scalars()
        }
        for edge in imp.staged_payload.get("reachability_candidates", []):
            src_a = asset_by_key.get(edge["source_asset_key"].lower())
            tgt_a = asset_by_key.get(edge["target_asset_key"].lower())
            if src_a is None or tgt_a is None:
                continue
            prov = {
                "source_product": edge["source_product"],
                "source_record_id": edge["rule_id"],
                "import_id": str(imp.id),
                "collection_time": edge["observed_at"],
                "parser_version": imp.parser_version,
                "confidence": edge["confidence"],
                "evidence_hash": imp.file_sha256,
            }
            db.add(
                Relationship(
                    tenant_id=ctx.tenant_id,
                    assessment_id=imp.assessment_id,
                    source_kind="asset",
                    source_id=src_a.id,
                    target_kind="asset",
                    target_id=tgt_a.id,
                    relation_type="CONNECTS_TO",
                    fact_kind=edge["fact_kind"],
                    confidence=edge["confidence"],
                    valid_from=now,
                    provenance=prov,
                    edge_metadata=edge["metadata"],
                )
            )
            committed_counts["relationships"] += 1

    elif fmt == "identity_json":
        src_prod = imp.staged_payload.get("source_product", "approved_directory_export")
        ident_map: dict[tuple[str, str], uuid.UUID] = {}
        group_map: dict[tuple[str, str], uuid.UUID] = {}
        ident_by_ext, group_by_ext = _commit_identities_and_groups(
            db,
            ctx,
            imp,
            identities=imp.staged_payload.get("identities", []),
            groups=imp.staged_payload.get("groups", []),
            source_product=src_prod,
            now=now,
            counts=committed_counts,
        )
        for i in imp.staged_payload.get("identities", []):
            if i["external_id"] in ident_by_ext:
                ident_map[(i["provider"], i["external_id"])] = ident_by_ext[i["external_id"]]
        for g in imp.staged_payload.get("groups", []):
            if g["external_id"] in group_by_ext:
                group_map[(g["provider"], g["external_id"])] = group_by_ext[g["external_id"]]

        for m in imp.staged_payload.get("memberships", []):
            ident_id = ident_map.get((m["provider"], m["identity_external_id"]))
            if ident_id is None:
                obj = db.execute(
                    select(Identity).where(
                        Identity.tenant_id == ctx.tenant_id,
                        Identity.provider == m["provider"],
                        Identity.external_id == m["identity_external_id"],
                    )
                ).scalar_one_or_none()
                ident_id = obj.id if obj else None
            grp_id = group_map.get((m["provider"], m["group_external_id"]))
            if grp_id is None:
                obj_g = db.execute(
                    select(Group).where(
                        Group.tenant_id == ctx.tenant_id,
                        Group.provider == m["provider"],
                        Group.external_id == m["group_external_id"],
                    )
                ).scalar_one_or_none()
                grp_id = obj_g.id if obj_g else None
            if ident_id and grp_id:
                db.add(
                    Relationship(
                        tenant_id=ctx.tenant_id,
                        assessment_id=imp.assessment_id,
                        source_kind="identity",
                        source_id=ident_id,
                        target_kind="group",
                        target_id=grp_id,
                        relation_type="MEMBER_OF",
                        fact_kind="observed_fact",
                        confidence=m["confidence"],
                        valid_from=datetime.fromisoformat(m["valid_from"]),
                        valid_to=datetime.fromisoformat(m["valid_to"]) if m.get("valid_to") else None,
                        provenance={
                            "source_product": src_prod,
                            "source_record_id": m["source_record_id"],
                            "import_id": str(imp.id),
                            "collection_time": m["valid_from"],
                            "parser_version": imp.parser_version,
                            "confidence": m["confidence"],
                            "evidence_hash": imp.file_sha256,
                        },
                    )
                )
                committed_counts["relationships"] += 1

    elif fmt == "vulnerability_json":
        asset_by_key = {
            a.canonical_key: a
            for a in db.execute(select(Asset).where(Asset.tenant_id == ctx.tenant_id)).scalars()
        }
        _commit_findings(
            db,
            ctx,
            imp,
            findings=imp.staged_payload.get("findings", []),
            asset_by_key=asset_by_key,
            counts=committed_counts,
        )

    elif fmt == "relationship_json":
        asset_by_key = {
            a.canonical_key: a.id
            for a in db.execute(select(Asset).where(Asset.tenant_id == ctx.tenant_id)).scalars()
        }
        ident_by_key = {
            i.external_id: i.id
            for i in db.execute(select(Identity).where(Identity.tenant_id == ctx.tenant_id)).scalars()
        }
        grp_by_key = {
            g.external_id: g.id
            for g in db.execute(select(Group).where(Group.tenant_id == ctx.tenant_id)).scalars()
        }
        _commit_relationships_list(
            db,
            ctx,
            imp,
            relationships=imp.staged_payload.get("relationships", []),
            lookup={"asset": asset_by_key, "identity": ident_by_key, "group": grp_by_key},
            counts=committed_counts,
        )

    _cleanup_staged_object(imp.temp_storage_path)
    imp.temp_storage_path = None
    imp.status = "committed"
    imp.committed_at = now
    db.flush()

    record_audit_event(
        db,
        tenant_id=ctx.tenant_id,
        actor_user_id=ctx.user_id,
        actor_email=ctx.email,
        action="import.commit",
        object_type="import",
        object_id=str(imp.id),
        outcome="success",
        request_id=ctx.request_id,
        details={"committed_counts": committed_counts},
    )
    db.commit()
    return _serialize_import(imp)


def list_imports(db: Session, ctx: ActorContext) -> list[dict[str, Any]]:
    require_permission(ctx.role, Permission.IMPORT_READ)
    rows = list(
        db.execute(
            select(ImportJob)
            .where(ImportJob.tenant_id == ctx.tenant_id)
            .order_by(desc(ImportJob.created_at))
        ).scalars()
    )
    return [_serialize_import(i) for i in rows]


def get_import(db: Session, ctx: ActorContext, import_id: uuid.UUID) -> dict[str, Any]:
    require_permission(ctx.role, Permission.IMPORT_READ)
    imp = db.execute(
        select(ImportJob).where(ImportJob.id == import_id, ImportJob.tenant_id == ctx.tenant_id)
    ).scalar_one_or_none()
    if imp is None:
        raise NotFoundError(code="IMPORT_NOT_FOUND", message="Import not found")
    return _serialize_import(imp)


def _serialize_import(imp: ImportJob) -> dict[str, Any]:
    return {
        "id": str(imp.id),
        "tenant_id": str(imp.tenant_id),
        "assessment_id": str(imp.assessment_id),
        "filename": imp.filename,
        "source_format": imp.source_format,
        "parser_version": imp.parser_version,
        "file_sha256": imp.file_sha256,
        "file_size_bytes": imp.file_size_bytes,
        "mime_type": imp.mime_type,
        "status": imp.status,
        "idempotency_key": imp.idempotency_key,
        "raw_metadata": imp.raw_metadata,
        "preview_summary": imp.preview_summary,
        "error_detail": imp.error_detail,
        "created_at": imp.created_at.isoformat(),
        "committed_at": imp.committed_at.isoformat() if imp.committed_at else None,
    }
