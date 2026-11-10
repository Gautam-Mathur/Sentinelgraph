from typing import Any

from app.domain.models import (
    FactKind,
    GraphEdge,
    GraphNode,
    PathStepData,
    RelationType,
)
from app.domain.scoring import ScoreBreakdown

_CAPABILITY_STAGE_MAP: dict[str, tuple[str, str]] = {
    RelationType.EXPOSES.value: (
        "External Exposure",
        "Ingress surface exposes target service port without perimeter isolation",
    ),
    RelationType.CONNECTS_TO.value: (
        "Network Lateral Movement",
        "Permitted firewall / ACL route allows network pivot across zones",
    ),
    RelationType.RUNS_SERVICE.value: (
        "Service Execution Surface",
        "Active host service daemon presents application or OS attack surface",
    ),
    RelationType.HAS_ROLE.value: (
        "Identity & Credential Acquisition",
        "Compromise of workload yields runtime identity token, key, or service principal",
    ),
    RelationType.MEMBER_OF.value: (
        "Group Privilege Inheritance",
        "Security group membership transitively grants elevated target permissions",
    ),
    RelationType.TRUSTS.value: (
        "Trust Boundary Delegation",
        "Cross-boundary delegation or session trust accepts credentials without isolation",
    ),
    RelationType.CAN_ADMINISTER.value: (
        "Administrative Control",
        "Standing administrative authority permits direct privileged control over target",
    ),
    RelationType.DEPENDS_ON.value: (
        "Supply / Runtime Dependency",
        "Upstream component dependency allows integrity or execution influence",
    ),
    RelationType.HOSTS.value: (
        "Substrate Co-Residency",
        "Host substrate execution provides control plane access over hosted resource",
    ),
    RelationType.OWNS.value: (
        "Ownership Control",
        "Resource ownership grants policy modification and ACL takeover capability",
    ),
}


def describe_capability_transition(
    *,
    step_order: int,
    edge: GraphEdge,
    src_node: GraphNode,
    tgt_node: GraphNode,
) -> dict[str, Any]:
    rel_val = edge.relation_type.value
    stage_name, base_mechanism = _CAPABILITY_STAGE_MAP.get(
        rel_val, ("Capability Transition", f"Traverses {rel_val} edge")
    )
    meta = dict(edge.edge_metadata) if edge.edge_metadata else {}
    requires_cve = meta.get("requires_cve")
    acl_rule = meta.get("acl_rule")
    ports = meta.get("ports")
    protocol = meta.get("protocol")
    mechanism_detail = meta.get("mechanism") or meta.get("note")

    causal_reasons: list[str] = [base_mechanism]
    if acl_rule:
        causal_reasons.append(f"Explicitly permitted by firewall/ACL rule '{acl_rule}'")
    if ports:
        causal_reasons.append(f"Reachable on {protocol or 'tcp'}/{ports}")
    if requires_cve:
        causal_reasons.append(f"Chained via unverified CVE condition ({requires_cve})")
    if mechanism_detail:
        causal_reasons.append(str(mechanism_detail))
    if tgt_node.is_crown_jewel:
        causal_reasons.append(f"Grants path termination on Crown Jewel '{tgt_node.label}'")

    return {
        "step_order": step_order,
        "relationship_id": edge.edge_id,
        "source_key": src_node.key,
        "source_label": src_node.label,
        "target_key": tgt_node.key,
        "target_label": tgt_node.label,
        "relation_type": rel_val,
        "fact_kind": edge.fact_kind.value,
        "confidence": edge.confidence,
        "stage_name": stage_name,
        "mechanism": "; ".join(causal_reasons),
        "requires_cve": requires_cve,
        "acl_rule": acl_rule,
        "protocol": protocol,
        "ports": ports,
        "source_product": (edge.provenance or {}).get("source_product", "unknown"),
    }


def extract_step_assumptions_structured(
    *,
    step_order: int,
    edge: GraphEdge,
    src_node: GraphNode,
    tgt_node: GraphNode,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    meta = dict(edge.edge_metadata) if edge.edge_metadata else {}
    src_meta = dict(src_node.metadata) if src_node.metadata else {}
    tgt_meta = dict(tgt_node.metadata) if tgt_node.metadata else {}

    if edge.relation_type in (RelationType.CONNECTS_TO, RelationType.EXPOSES) and not meta.get(
        "acl_rule"
    ):
        items.append(
            {
                "assumption_id": f"asm-acl-{step_order}-{edge.edge_id[:8]}",
                "category": "uncorroborated_acl",
                "fragility": "high",
                "step_order": step_order,
                "relationship_id": edge.edge_id,
                "node_key": None,
                "statement": (
                    f"No firewall/ACL rule ID recorded between '{src_node.label}' and "
                    f"'{tgt_node.label}'; intermediate host or L3 packet filtering is assumed permissive."
                ),
                "verification_action": (
                    "Inspect host firewall rules and subnet ACL exports to confirm whether traffic "
                    f"from {src_node.label} to {tgt_node.label} is actually permitted."
                ),
                "can_challenge_edge": True,
            }
        )

    if edge.fact_kind == FactKind.INFERRED_RELATIONSHIP:
        items.append(
            {
                "assumption_id": f"asm-inferred-{step_order}-{edge.edge_id[:8]}",
                "category": "inferred_heuristic",
                "fragility": "critical",
                "step_order": step_order,
                "relationship_id": edge.edge_id,
                "node_key": None,
                "statement": (
                    f"Step {step_order} ({src_node.label} --[{edge.relation_type.value}]--> "
                    f"{tgt_node.label}) is heuristic/inferred via "
                    f"'{(edge.provenance or {}).get('source_product', 'inference')}' rather than direct observation."
                ),
                "verification_action": (
                    "Verify trust/delegation policy directly on source telemetry; suppress edge if false positive."
                ),
                "can_challenge_edge": True,
            }
        )
    elif edge.fact_kind == FactKind.ANALYST_ASSERTION:
        items.append(
            {
                "assumption_id": f"asm-assert-{step_order}-{edge.edge_id[:8]}",
                "category": "analyst_assertion",
                "fragility": "high",
                "step_order": step_order,
                "relationship_id": edge.edge_id,
                "node_key": None,
                "statement": (
                    f"Step {step_order} relies on a manual analyst assertion rather than automated scanner telemetry."
                ),
                "verification_action": "Attach corroborating raw config or scan evidence.",
                "can_challenge_edge": True,
            }
        )

    if edge.confidence < 0.7:
        items.append(
            {
                "assumption_id": f"asm-conf-{step_order}-{edge.edge_id[:8]}",
                "category": "low_edge_confidence",
                "fragility": "high",
                "step_order": step_order,
                "relationship_id": edge.edge_id,
                "node_key": None,
                "statement": (
                    f"Step {step_order} carries sub-70% evidence confidence ({edge.confidence:.2f})."
                ),
                "verification_action": "Re-collect fresh telemetry to corroborate or refute this edge.",
                "can_challenge_edge": True,
            }
        )

    requires_cve = meta.get("requires_cve")
    if requires_cve or tgt_node.open_cve_count > 0:
        cve_txt = f"CVE {requires_cve}" if requires_cve else f"{tgt_node.open_cve_count} open CVE(s)"
        items.append(
            {
                "assumption_id": f"asm-cve-{step_order}-{edge.edge_id[:8]}",
                "category": "cve_exploitability_unproven",
                "fragility": "moderate",
                "step_order": step_order,
                "relationship_id": edge.edge_id,
                "node_key": tgt_node.key if tgt_node.open_cve_count > 0 else src_node.key,
                "statement": (
                    f"Step {step_order} assumes {cve_txt} enables runtime foothold/pivot, "
                    "but CVE presence alone does not prove live exploitability."
                ),
                "verification_action": (
                    "Check patch status, runtime compensating controls (WAF/EDR/ASLR), or exploit pre-requisites."
                ),
                "can_challenge_edge": False,
            }
        )

    if edge.relation_type == RelationType.CAN_ADMINISTER:
        auth_meta = src_meta.get("auth_metadata") or {}
        if auth_meta.get("mfa_enforced") is False or not meta.get("pam_enforced"):
            items.append(
                {
                    "assumption_id": f"asm-pam-{step_order}-{edge.edge_id[:8]}",
                    "category": "standing_privilege_unscoped",
                    "fragility": "moderate",
                    "step_order": step_order,
                    "relationship_id": edge.edge_id,
                    "node_key": src_node.key,
                    "statement": (
                        f"Administrative access from '{src_node.label}' to '{tgt_node.label}' assumes "
                        "no blocking PAM/JIT break-glass workflow or MFA gate."
                    ),
                    "verification_action": (
                        "Verify PAM/JIT elevation approval policies and enforce MFA or short-lived tokens."
                    ),
                    "can_challenge_edge": False,
                }
            )

    if src_node.stale_observation or tgt_node.stale_observation:
        stale_node = src_node if src_node.stale_observation else tgt_node
        items.append(
            {
                "assumption_id": f"asm-stale-{step_order}-{edge.edge_id[:8]}",
                "category": "stale_telemetry",
                "fragility": "moderate",
                "step_order": step_order,
                "relationship_id": edge.edge_id,
                "node_key": stale_node.key,
                "statement": (
                    f"Endpoint '{stale_node.label}' has stale observation telemetry (>30 days old)."
                ),
                "verification_action": "Ingest a fresh inventory/scanner export for this host/identity.",
                "can_challenge_edge": False,
            }
        )

    src_auth = src_meta.get("auth_metadata") or tgt_meta.get("auth_metadata") or {}
    if (
        isinstance(src_auth, dict)
        and src_auth.get("mfa_enforced") is False
        and edge.relation_type in (RelationType.HAS_ROLE, RelationType.MEMBER_OF)
    ):
        items.append(
            {
                "assumption_id": f"asm-nomfa-{step_order}-{edge.edge_id[:8]}",
                "category": "standing_privilege_unscoped",
                "fragility": "high",
                "step_order": step_order,
                "relationship_id": edge.edge_id,
                "node_key": tgt_node.key if tgt_node.node_kind.value == "identity" else src_node.key,
                "statement": (
                    f"Identity authentication telemetry indicates mfa_enforced=false along '{edge.relation_type.value}' pivot."
                ),
                "verification_action": (
                    "Scope or rotate non-human credentials and restrict workload token binding."
                ),
                "can_challenge_edge": False,
            }
        )

    return items


def build_step_explanation(
    *,
    step_order: int,
    edge: GraphEdge,
    src_node: GraphNode,
    tgt_node: GraphNode,
) -> PathStepData:
    preconditions: list[str] = []
    assumptions: list[str] = []
    missing_corroboration = False

    protocol = edge.edge_metadata.get("protocol")
    ports = edge.edge_metadata.get("ports")
    acl_rule = edge.edge_metadata.get("acl_rule")

    if edge.relation_type in (RelationType.CONNECTS_TO.value, RelationType.EXPOSES.value):
        port_txt = f" on {protocol or 'tcp'}/{ports}" if ports else ""
        preconditions.append(
            f"Network reachability from '{src_node.label}' to '{tgt_node.label}'{port_txt} remains permitted."
        )
        if not acl_rule:
            assumptions.append(
                "No explicit firewall/ACL rule ID recorded; intermediate packet filtering may block traversal."
            )
            missing_corroboration = True
    elif edge.relation_type == RelationType.RUNS_SERVICE.value:
        preconditions.append(
            f"Service '{tgt_node.label}' is actively listening and reachable on '{src_node.label}'."
        )
    elif edge.relation_type == RelationType.HAS_ROLE.value:
        preconditions.append(
            f"Compromise or valid invocation of '{src_node.label}' yields context/credentials for '{tgt_node.label}'."
        )
    elif edge.relation_type == RelationType.MEMBER_OF.value:
        preconditions.append(
            f"Active directory/IAM membership of '{src_node.label}' in '{tgt_node.label}' is enabled and unrevoked."
        )
    elif edge.relation_type == RelationType.CAN_ADMINISTER.value:
        preconditions.append(
            f"Administrative privilege held by '{src_node.label}' over '{tgt_node.label}' is not blocked by PAM/JIT controls."
        )
    elif edge.relation_type == RelationType.TRUSTS.value:
        preconditions.append(
            f"Trust boundary between '{src_node.label}' and '{tgt_node.label}' permits token/session acceptance."
        )
    else:
        preconditions.append(
            f"Relationship {edge.relation_type.value} between '{src_node.label}' and '{tgt_node.label}' remains active."
        )

    if edge.fact_kind == FactKind.INFERRED_RELATIONSHIP:
        assumptions.append(
            "Inferred relationship (not directly observed); requires analyst verification before treating as confirmed."
        )
    elif edge.fact_kind == FactKind.ANALYST_ASSERTION:
        assumptions.append(
            "Analyst-asserted edge; depends on documented assessment assumption."
        )

    if edge.confidence < 0.7:
        assumptions.append(
            f"Edge confidence is moderate/low ({edge.confidence:.2f}); underlying evidence may be incomplete."
        )

    if tgt_node.open_cve_count > 0:
        assumptions.append(
            f"Target carries {tgt_node.open_cve_count} CVE observation(s); CVE presence is not proof of exploitability."
        )

    if src_node.stale_observation or tgt_node.stale_observation:
        assumptions.append(
            "At least one endpoint has stale observation data (>30 days old)."
        )
        missing_corroboration = True

    prov = dict(edge.provenance) if edge.provenance else {}
    evidence_refs = [
        {
            "relationship_id": edge.edge_id,
            "source_product": prov.get("source_product", "unknown"),
            "source_record_id": prov.get("source_record_id", edge.edge_id),
            "import_id": prov.get("import_id"),
            "collection_time": prov.get("collection_time"),
            "parser_version": prov.get("parser_version", "unknown"),
            "confidence": edge.confidence,
            "evidence_hash": prov.get("evidence_hash"),
            "fact_kind": edge.fact_kind.value,
        }
    ]

    narrative = (
        f"Step {step_order}: {src_node.label} ({src_node.node_kind.value}) "
        f"--[{edge.relation_type.value} | {edge.fact_kind.value} | conf={edge.confidence:.2f}]--> "
        f"{tgt_node.label} ({tgt_node.node_kind.value})."
    )

    return PathStepData(
        step_order=step_order,
        relationship_id=edge.edge_id,
        from_node_kind=src_node.node_kind.value,
        from_node_id=src_node.node_id,
        from_node_label=src_node.label,
        to_node_kind=tgt_node.node_kind.value,
        to_node_id=tgt_node.node_id,
        to_node_label=tgt_node.label,
        relation_type=edge.relation_type.value,
        fact_kind=edge.fact_kind.value,
        confidence=edge.confidence,
        preconditions=preconditions,
        assumptions=assumptions,
        evidence_refs=evidence_refs,
        narrative=narrative,
        missing_corroboration=missing_corroboration,
    )


def build_path_explanation(
    *,
    start_node: GraphNode,
    target_node: GraphNode,
    steps: list[PathStepData],
    breakdown: ScoreBreakdown,
    algorithm: str,
    algorithm_params: dict[str, Any],
    edges: list[GraphEdge] | None = None,
    path_nodes: list[GraphNode] | None = None,
) -> tuple[list[str], str, dict[str, Any]]:
    path_assumptions: list[str] = [
        "Plausible attack path only — does not constitute confirmed exploitation."
    ]
    seen: set[str] = set(path_assumptions)
    for step in steps:
        for item in step.assumptions:
            if item not in seen:
                seen.add(item)
                path_assumptions.append(item)

    capability_chain: list[dict[str, Any]] = []
    assumptions_register: list[dict[str, Any]] = [
        {
            "assumption_id": "asm-plausibility-invariant",
            "category": "plausibility_invariant",
            "fragility": "low",
            "step_order": None,
            "relationship_id": None,
            "node_key": target_node.key,
            "statement": (
                "Plausible exposure hypothesis only — score measures remediation priority (0-100), "
                "not statistical exploitability or confirmed breach."
            ),
            "verification_action": (
                "Validate mitigating runtime controls (EDR, WAF, segmentation) and evidence provenance before action."
            ),
            "can_challenge_edge": False,
        }
    ]

    if edges is not None and path_nodes is not None and len(edges) == len(steps) and len(path_nodes) == len(steps) + 1:
        for idx, (_st, edge_obj) in enumerate(zip(steps, edges, strict=True), start=1):
            src_n = path_nodes[idx - 1]
            tgt_n = path_nodes[idx]
            capability_chain.append(
                describe_capability_transition(
                    step_order=idx, edge=edge_obj, src_node=src_n, tgt_node=tgt_n
                )
            )
            assumptions_register.extend(
                extract_step_assumptions_structured(
                    step_order=idx, edge=edge_obj, src_node=src_n, tgt_node=tgt_n
                )
            )
    else:
        for st in steps:
            stage_name, base_mech = _CAPABILITY_STAGE_MAP.get(
                st.relation_type, ("Capability Transition", f"Traverses {st.relation_type}")
            )
            capability_chain.append(
                {
                    "step_order": st.step_order,
                    "relationship_id": st.relationship_id,
                    "source_key": f"{st.from_node_kind}:{st.from_node_id}",
                    "source_label": st.from_node_label,
                    "target_key": f"{st.to_node_kind}:{st.to_node_id}",
                    "target_label": st.to_node_label,
                    "relation_type": st.relation_type,
                    "fact_kind": st.fact_kind,
                    "confidence": st.confidence,
                    "stage_name": stage_name,
                    "mechanism": base_mech,
                    "requires_cve": None,
                    "acl_rule": None,
                    "protocol": None,
                    "ports": None,
                    "source_product": (
                        st.evidence_refs[0].get("source_product", "unknown")
                        if st.evidence_refs
                        else "unknown"
                    ),
                }
            )

    remediation_options: list[str] = []
    for step in steps:
        if step.relation_type in (RelationType.CONNECTS_TO.value, RelationType.EXPOSES.value):
            remediation_options.append(
                f"Segment network access or restrict firewall rules between {step.from_node_label} and {step.to_node_label}."
            )
        elif step.relation_type == RelationType.MEMBER_OF.value:
            remediation_options.append(
                f"Remove {step.from_node_label} from privileged group {step.to_node_label}."
            )
        elif step.relation_type == RelationType.HAS_ROLE.value:
            remediation_options.append(
                f"Rotate or restrict service identity {step.to_node_label} used by {step.from_node_label}."
            )
        elif step.relation_type == RelationType.CAN_ADMINISTER.value:
            remediation_options.append(
                f"Enforce least privilege / disable standing admin rights from {step.from_node_label} to {step.to_node_label}."
            )

    narrative_lines = [
        f"Plausible {len(steps)}-hop path from '{start_node.label}' to '{target_node.label}' "
        f"(Priority Score {breakdown.priority_score}/100, Scoring {breakdown.scoring_version} — not a probability).",
        f"Business Impact: Target '{target_node.label}' has criticality='{target_node.criticality}'"
        + (" (Crown Jewel)." if target_node.is_crown_jewel else "."),
        "Transition chain:",
        *[f"  - {s.narrative}" for s in steps],
    ]
    if path_assumptions:
        narrative_lines.append("Key assumptions & uncertainties:")
        narrative_lines.extend(f"  * {a}" for a in path_assumptions)

    trace: dict[str, Any] = {
        "plausible_only": True,
        "algorithm": algorithm,
        "algorithm_params": algorithm_params,
        "scoring": {
            "version": breakdown.scoring_version,
            "formula": breakdown.formula,
            "is_probability": breakdown.is_probability,
            "disclaimer": breakdown.disclaimer,
            "priority_score": breakdown.priority_score,
            "impact_weight": breakdown.impact_weight,
            "exposure_factor": breakdown.exposure_factor,
            "privilege_factor": breakdown.privilege_factor,
            "evidence_confidence": breakdown.evidence_confidence,
            "missing_data_penalty": breakdown.missing_data_penalty,
        },
        "business_impact": {
            "target_label": target_node.label,
            "target_criticality": target_node.criticality,
            "is_crown_jewel": target_node.is_crown_jewel,
            "environment": target_node.environment,
        },
        "capability_chain": capability_chain,
        "assumptions_register": assumptions_register,
        "steps": [
            {
                "step_order": s.step_order,
                "relationship_id": s.relationship_id,
                "from": f"{s.from_node_kind}:{s.from_node_label}",
                "to": f"{s.to_node_kind}:{s.to_node_label}",
                "relation_type": s.relation_type,
                "fact_kind": s.fact_kind,
                "confidence": s.confidence,
                "preconditions": s.preconditions,
                "precondition_outcomes": s.precondition_outcomes,
                "assumptions": s.assumptions,
                "evidence_refs": s.evidence_refs,
            }
            for s in steps
        ],
        "assumptions": path_assumptions,
        "remediation_options": remediation_options,
    }

    return path_assumptions, "\n".join(narrative_lines), trace
