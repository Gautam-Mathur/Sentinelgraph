import csv
import io
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from jinja2 import Environment, select_autoescape
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.core.errors import NotFoundError, ValidationAppError
from app.core.permissions import Permission, require_permission
from app.db.models import (
    Assessment,
    Asset,
    AttackPath,
    Finding,
    ImportJob,
    RemediationAction,
    Report,
)
from app.domain.scoring import SCORING_DISCLAIMER, SCORING_FORMULA, SCORING_VERSION
from app.services.audit_service import record_audit_event
from app.services.context import ActorContext

_JINJA_ENV = Environment(autoescape=select_autoescape(["html", "xml"]))

_HTML_REPORT_TEMPLATE = _JINJA_ENV.from_string(
    """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>{{ title }}</title>
<style>
  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; color: #0f172a; background: #f8fafc; margin: 0; padding: 32px; line-height: 1.5; }
  .container { max-width: 1024px; margin: 0 auto; background: #ffffff; border: 1px solid #cbd5e1; border-radius: 10px; padding: 32px; }
  .watermark { background: #fef3c7; border: 2px dashed #d97706; color: #92400e; padding: 12px 16px; border-radius: 8px; font-weight: 700; text-align: center; margin-bottom: 24px; letter-spacing: 0.04em; }
  h1, h2, h3 { color: #0f172a; margin-top: 24px; }
  .meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; margin: 16px 0; }
  .card { background: #f1f5f9; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px 16px; }
  .label { font-size: 12px; text-transform: uppercase; color: #475569; font-weight: 600; }
  .value { font-size: 15px; font-weight: 600; margin-top: 4px; }
  table { width: 100%; border-collapse: collapse; margin: 12px 0 24px 0; font-size: 14px; }
  th, td { border: 1px solid #cbd5e1; padding: 8px 10px; text-align: left; vertical-align: top; }
  th { background: #e2e8f0; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 12px; font-weight: 600; background: #e2e8f0; }
  .badge-observed { background: #dcfce7; color: #166534; }
  .badge-inferred { background: #fef3c7; color: #92400e; }
  .badge-assertion { background: #e0e7ff; color: #3730a3; }
  .path-box { border: 1px solid #cbd5e1; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
  .limitations { background: #f8fafc; border-left: 4px solid #64748b; padding: 12px 16px; margin-top: 24px; }
</style>
</head>
<body>
<div class="container">
  {% if watermarked %}
  <div class="watermark">SYNTHETIC / DEMO DATA WATERMARK — AUTHORISED LAB SIMULATION ONLY</div>
  {% endif %}

  <h1>{{ title }}</h1>
  <p>Generated at {{ generated_at }} by {{ actor_email }} for tenant <strong>{{ tenant_name }}</strong>.</p>

  <h2>1. Assessment Scope &amp; Governance</h2>
  <div class="meta-grid">
    <div class="card"><div class="label">Assessment</div><div class="value">{{ assessment.name }}</div></div>
    <div class="card"><div class="label">Status</div><div class="value">{{ assessment.status }}</div></div>
    <div class="card"><div class="label">Approved Scope</div><div class="value">{{ assessment.approved_scope_cidrs | join(', ') }}</div></div>
    <div class="card"><div class="label">Time Window</div><div class="value">{{ assessment.time_window_start }} to {{ assessment.time_window_end }}</div></div>
  </div>

  <h2>2. Methodology &amp; Published Scoring Model</h2>
  <p><strong>Scoring Version:</strong> {{ scoring_version }}<br />
     <strong>Formula:</strong> <code>{{ scoring_formula }}</code><br />
     <strong>Disclaimer:</strong> {{ scoring_disclaimer }}</p>

  <h2>3. Source Coverage &amp; Inventory Summary</h2>
  <div class="meta-grid">
    <div class="card"><div class="label">Committed Imports</div><div class="value">{{ imports_count }}</div></div>
    <div class="card"><div class="label">Assets Observed</div><div class="value">{{ assets_count }}</div></div>
    <div class="card"><div class="label">Vulnerability Findings</div><div class="value">{{ findings_count }}</div></div>
    <div class="card"><div class="label">Attack Paths Ranked</div><div class="value">{{ paths | length }}</div></div>
  </div>
  {% if imports %}
  <table>
    <thead><tr><th>Filename</th><th>Format</th><th>Parser Version</th><th>SHA-256</th><th>Committed At</th></tr></thead>
    <tbody>
      {% for imp in imports %}
      <tr>
        <td>{{ imp.filename }}</td>
        <td>{{ imp.source_format }}</td>
        <td>{{ imp.parser_version }}</td>
        <td><code>{{ imp.file_sha256[:16] }}...</code></td>
        <td>{{ imp.committed_at or '-' }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% endif %}

  <h2>4. Ranked Plausible Attack Paths</h2>
  {% if not paths %}
    <p>No attack paths were generated under the selected assessment constraints.</p>
  {% endif %}
  {% for p in paths %}
  <div class="path-box">
    <h3>#{{ loop.index }} {{ p.title }} — Priority Score: {{ p.priority_score }}/100</h3>
    <p>
      <strong>Algorithm:</strong> {{ p.algorithm }} |
      <strong>Hops:</strong> {{ p.hop_count }} |
      <strong>Impact:</strong> {{ p.impact_weight }} |
      <strong>Exposure:</strong> {{ p.exposure_factor }} |
      <strong>Privilege:</strong> {{ p.privilege_factor }} |
      <strong>Evidence Confidence:</strong> {{ p.evidence_confidence }} |
      <strong>Missing Data Penalty:</strong> {{ p.missing_data_penalty }}
    </p>
    <table>
      <thead><tr><th>Step</th><th>Transition</th><th>Relation</th><th>Fact Kind</th><th>Confidence</th><th>Preconditions &amp; Provenance</th></tr></thead>
      <tbody>
        {% for st in p.steps %}
        <tr>
          <td>{{ st.step_order }}</td>
          <td>{{ st.from_node_label }} &rarr; {{ st.to_node_label }}</td>
          <td>{{ st.relation_type }}</td>
          <td>
            {% if st.fact_kind == 'observed_fact' %}
              <span class="badge badge-observed">observed_fact</span>
            {% elif st.fact_kind == 'inferred_relationship' %}
              <span class="badge badge-inferred">inferred_relationship</span>
            {% else %}
              <span class="badge badge-assertion">{{ st.fact_kind }}</span>
            {% endif %}
          </td>
          <td>{{ st.confidence }}</td>
          <td>
            {{ st.preconditions | join('; ') }}
            {% if st.evidence_refs %}
              <br /><small>Source: {{ st.evidence_refs[0].source_product }} ({{ st.evidence_refs[0].source_record_id }})</small>
            {% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    <p><strong>Assumptions:</strong> {{ p.assumptions | join(' | ') }}</p>
  </div>
  {% endfor %}

  <h2>5. Remediation Modelling (Sandbox Simulation)</h2>
  {% if not remediations %}
    <p>No remediation simulations recorded for this assessment.</p>
  {% else %}
  <table>
    <thead><tr><th>Scenario</th><th>Status</th><th>Baseline Paths</th><th>Modelled Paths</th><th>Max Score Delta</th><th>Modelled Notice</th></tr></thead>
    <tbody>
      {% for rem in remediations %}
      <tr>
        <td>{{ rem.name }}</td>
        <td>{{ rem.status }}</td>
        <td>{{ rem.baseline_metrics.get('total_paths', 0) }}</td>
        <td>{{ rem.modelled_metrics.get('total_paths', 0) }}</td>
        <td>-{{ rem.delta_summary.get('highest_score_reduction', 0) }}</td>
        <td>Modelled impact only (not verified remediation)</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% endif %}

  <div class="limitations">
    <h2>6. Known Limitations &amp; Evidence Caveats</h2>
    <ul>
      <li>Attack paths represent plausible hypotheses derived from ingested evidence, not confirmed exploitation.</li>
      <li>Presence of a CVE or open service banner is not proof of exploitability.</li>
      <li>Partial source coverage or missing firewall/ACL exports lowers confidence and may miss or overstate reachability.</li>
      <li>Remediation simulations operate strictly on an isolated sandbox graph copy and never modify live infrastructure.</li>
    </ul>
  </div>
</div>
</body>
</html>"""
)


def generate_html_report(
    db: Session,
    ctx: ActorContext,
    *,
    assessment_id: uuid.UUID,
    title: str | None = None,
    remediation_action_id: uuid.UUID | None = None,
    report_format: str = "html",
) -> dict[str, Any]:
    require_permission(ctx.role, Permission.REPORT_GENERATE)
    if report_format != "html":
        raise ValidationAppError(
            code="UNSUPPORTED_REPORT_FORMAT",
            message="MVP reporting engine generates HTML reports only (PDF and XLSX are planned for a later phase).",
        )

    assessment = db.execute(
        select(Assessment).where(
            Assessment.id == assessment_id, Assessment.tenant_id == ctx.tenant_id
        )
    ).scalar_one_or_none()
    if assessment is None:
        raise NotFoundError(code="ASSESSMENT_NOT_FOUND", message="Assessment not found")

    imports = list(
        db.execute(
            select(ImportJob).where(
                ImportJob.tenant_id == ctx.tenant_id,
                ImportJob.assessment_id == assessment.id,
                ImportJob.status == "committed",
            )
        ).scalars()
    )
    assets_count = len(
        list(
            db.execute(
                select(Asset.id).where(Asset.tenant_id == ctx.tenant_id, Asset.deleted_at.is_(None))
            ).scalars()
        )
    )
    findings_count = len(
        list(
            db.execute(
                select(Finding.id).where(
                    Finding.tenant_id == ctx.tenant_id,
                    Finding.assessment_id == assessment.id,
                )
            ).scalars()
        )
    )
    paths = list(
        db.execute(
            select(AttackPath)
            .where(
                AttackPath.tenant_id == ctx.tenant_id,
                AttackPath.assessment_id == assessment.id,
            )
            .order_by(desc(AttackPath.priority_score))
        ).scalars()
    )
    rem_stmt = select(RemediationAction).where(
        RemediationAction.tenant_id == ctx.tenant_id,
        RemediationAction.assessment_id == assessment.id,
    )
    if remediation_action_id:
        rem_stmt = rem_stmt.where(RemediationAction.id == remediation_action_id)
    remediations = list(db.execute(rem_stmt.order_by(desc(RemediationAction.created_at))).scalars())

    watermarked = bool(ctx.tenant_is_demo or assessment.is_synthetic)
    report_title = (title or f"SentinelGraph Attack-Path Report — {assessment.name}").strip()
    now_iso = datetime.now(UTC).isoformat()

    html_content = _HTML_REPORT_TEMPLATE.render(
        title=report_title,
        generated_at=now_iso,
        actor_email=ctx.email,
        tenant_name=ctx.tenant_name,
        watermarked=watermarked,
        assessment=assessment,
        scoring_version=SCORING_VERSION,
        scoring_formula=SCORING_FORMULA,
        scoring_disclaimer=SCORING_DISCLAIMER,
        imports=imports,
        imports_count=len(imports),
        assets_count=assets_count,
        findings_count=findings_count,
        paths=paths,
        remediations=remediations,
    )

    rep = Report(
        tenant_id=ctx.tenant_id,
        assessment_id=assessment.id,
        remediation_action_id=remediation_action_id,
        title=report_title,
        report_format="html",
        is_synthetic_watermarked=watermarked,
        scoring_version=SCORING_VERSION,
        html_content=html_content,
        created_by_user_id=ctx.user_id,
    )
    db.add(rep)
    db.flush()

    record_audit_event(
        db,
        tenant_id=ctx.tenant_id,
        actor_user_id=ctx.user_id,
        actor_email=ctx.email,
        action="report.export",
        object_type="report",
        object_id=str(rep.id),
        outcome="success",
        request_id=ctx.request_id,
        details={"assessment_id": str(assessment.id), "format": "html", "watermarked": watermarked},
    )
    db.commit()
    return _serialize_report(rep, include_html=True)


def list_reports(db: Session, ctx: ActorContext) -> list[dict[str, Any]]:
    require_permission(ctx.role, Permission.REPORT_READ)
    rows = list(
        db.execute(
            select(Report)
            .where(Report.tenant_id == ctx.tenant_id)
            .order_by(desc(Report.created_at))
        ).scalars()
    )
    return [_serialize_report(r, include_html=False) for r in rows]


def get_report(db: Session, ctx: ActorContext, report_id: uuid.UUID) -> dict[str, Any]:
    require_permission(ctx.role, Permission.REPORT_READ)
    rep = db.execute(
        select(Report).where(Report.id == report_id, Report.tenant_id == ctx.tenant_id)
    ).scalar_one_or_none()
    if rep is None:
        raise NotFoundError(code="REPORT_NOT_FOUND", message="Report not found")
    return _serialize_report(rep, include_html=True)


def _sanitize_csv_cell(val: Any) -> str:
    s = "" if val is None else str(val)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{s}"
    return s


def export_report_format(
    db: Session,
    ctx: ActorContext,
    *,
    report_id: uuid.UUID,
    export_format: str = "html",
) -> tuple[str, str, str]:
    require_permission(ctx.role, Permission.REPORT_READ)
    rep = db.execute(
        select(Report).where(Report.id == report_id, Report.tenant_id == ctx.tenant_id)
    ).scalar_one_or_none()
    if rep is None:
        raise NotFoundError(code="REPORT_NOT_FOUND", message="Report not found")

    fmt = export_format.strip().lower()
    if fmt == "html":
        return rep.html_content, "text/html; charset=utf-8", "html"

    assessment = db.execute(
        select(Assessment).where(
            Assessment.id == rep.assessment_id, Assessment.tenant_id == ctx.tenant_id
        )
    ).scalar_one_or_none()
    paths = list(
        db.execute(
            select(AttackPath)
            .where(AttackPath.tenant_id == ctx.tenant_id, AttackPath.assessment_id == rep.assessment_id)
            .order_by(desc(AttackPath.priority_score))
        ).scalars()
    )
    findings = list(
        db.execute(
            select(Finding)
            .where(Finding.tenant_id == ctx.tenant_id, Finding.assessment_id == rep.assessment_id)
            .order_by(desc(Finding.cvss_score))
        ).scalars()
    )

    if fmt == "json":
        bundle = {
            "report": _serialize_report(rep, include_html=False),
            "methodology": {
                "scoring_version": rep.scoring_version,
                "formula": SCORING_FORMULA,
                "disclaimer": SCORING_DISCLAIMER,
            },
            "assessment": {
                "id": str(assessment.id),
                "name": assessment.name,
                "status": assessment.status,
                "approved_scope_cidrs": assessment.approved_scope_cidrs,
                "is_synthetic": assessment.is_synthetic,
            }
            if assessment
            else None,
            "attack_paths": [
                {
                    "id": str(p.id),
                    "title": p.title,
                    "priority_score": p.priority_score,
                    "hop_count": p.hop_count,
                    "algorithm": p.algorithm,
                    "start_node_label": p.start_node_label,
                    "target_node_label": p.target_node_label,
                    "assumptions": p.assumptions,
                    "steps": [
                        {
                            "step_order": s.step_order,
                            "from_node_label": s.from_node_label,
                            "to_node_label": s.to_node_label,
                            "relation_type": s.relation_type,
                            "fact_kind": s.fact_kind,
                            "confidence": s.confidence,
                            "preconditions": s.preconditions,
                        }
                        for s in p.steps
                    ],
                }
                for p in paths
            ],
            "findings": [
                {
                    "id": str(f.id),
                    "cve_id": f.cve_id,
                    "cvss_score": f.cvss_score,
                    "severity": f.severity,
                    "status": f.status,
                    "affected_component": f.affected_component,
                    "scanner_name": f.scanner_name,
                    "triage_note": f.triage_note,
                }
                for f in findings
            ],
        }
        return json.dumps(bundle, indent=2), "application/json; charset=utf-8", "json"

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(
            [
                "record_type",
                "rank_or_severity",
                "title_or_cve",
                "priority_or_cvss",
                "hop_or_status",
                "step_order",
                "from_or_component",
                "to_or_scanner",
                "relation_or_context",
                "fact_kind",
                "confidence",
            ]
        )
        for idx, p in enumerate(paths, start=1):
            if not p.steps:
                writer.writerow(
                    [
                        "attack_path",
                        idx,
                        _sanitize_csv_cell(p.title),
                        p.priority_score,
                        p.hop_count,
                        "",
                        _sanitize_csv_cell(p.start_node_label),
                        _sanitize_csv_cell(p.target_node_label),
                        "",
                        "",
                        p.evidence_confidence,
                    ]
                )
            for st in p.steps:
                writer.writerow(
                    [
                        "attack_path_step",
                        idx,
                        _sanitize_csv_cell(p.title),
                        p.priority_score,
                        p.hop_count,
                        st.step_order,
                        _sanitize_csv_cell(st.from_node_label),
                        _sanitize_csv_cell(st.to_node_label),
                        _sanitize_csv_cell(st.relation_type),
                        _sanitize_csv_cell(st.fact_kind),
                        st.confidence,
                    ]
                )
        for f in findings:
            writer.writerow(
                [
                    "finding",
                    _sanitize_csv_cell(f.severity),
                    _sanitize_csv_cell(f.cve_id or f.affected_component),
                    f.cvss_score if f.cvss_score is not None else "",
                    _sanitize_csv_cell(f.status),
                    "",
                    _sanitize_csv_cell(f.affected_component),
                    _sanitize_csv_cell(f.scanner_name),
                    _sanitize_csv_cell(f.scanner_context),
                    "observed_fact",
                    f.confidence,
                ]
            )
        return buf.getvalue(), "text/csv; charset=utf-8", "csv"

    if fmt == "sarif":
        sarif_results: list[dict[str, Any]] = []
        for p in paths:
            level = "error" if p.priority_score >= 70.0 else ("warning" if p.priority_score >= 40.0 else "note")
            sarif_results.append(
                {
                    "ruleId": "SG-ATTACK-PATH",
                    "level": level,
                    "message": {
                        "text": f"{p.title} (Priority Score {p.priority_score}/100, {p.hop_count} hops): {p.explanation_narrative[:300]}"
                    },
                    "properties": {
                        "priority_score": p.priority_score,
                        "hop_count": p.hop_count,
                        "determinism_hash": p.determinism_hash,
                        "watermarked": rep.is_synthetic_watermarked,
                    },
                }
            )
        for f in findings:
            level = "error" if f.severity in ("critical", "high") else ("warning" if f.severity == "medium" else "note")
            sarif_results.append(
                {
                    "ruleId": f.cve_id or "SG-FINDING",
                    "level": level,
                    "message": {
                        "text": f"[{f.severity.upper()}] {f.affected_component} via {f.scanner_name} (status: {f.status})"
                    },
                    "properties": {
                        "cvss_score": f.cvss_score,
                        "status": f.status,
                        "scanner_context": f.scanner_context,
                        "exploitability_proven": False,
                    },
                }
            )

        sarif_doc = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SentinelGraph",
                            "informationUri": "https://sentinelgraph.local",
                            "version": rep.scoring_version,
                            "rules": [
                                {
                                    "id": "SG-ATTACK-PATH",
                                    "shortDescription": {"text": "Evidence-backed attack path hypothesis"},
                                },
                                {
                                    "id": "SG-FINDING",
                                    "shortDescription": {"text": "Ingested vulnerability finding"},
                                },
                            ],
                        }
                    },
                    "automationDetails": {"id": f"report/{rep.id}"},
                    "results": sarif_results,
                }
            ],
        }
        return json.dumps(sarif_doc, indent=2), "application/sarif+json; charset=utf-8", "sarif"

    raise ValidationAppError(
        code="UNSUPPORTED_REPORT_FORMAT",
        message="Supported download formats: html, json, csv, sarif.",
    )


def _serialize_report(rep: Report, *, include_html: bool) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": str(rep.id),
        "assessment_id": str(rep.assessment_id),
        "title": rep.title,
        "report_format": rep.report_format,
        "is_synthetic_watermarked": rep.is_synthetic_watermarked,
        "scoring_version": rep.scoring_version,
        "created_at": rep.created_at.isoformat(),
    }
    if include_html:
        data["html_content"] = rep.html_content
    return data
