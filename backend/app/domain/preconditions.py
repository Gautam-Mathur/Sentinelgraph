from __future__ import annotations

from typing import Any

from app.domain.models import GraphEdge, RelationType

TRUE = "true"
FALSE = "false"
UNKNOWN = "unknown"
_VALID_STATUSES = {TRUE, FALSE, UNKNOWN}


def _field_value(metadata: dict[str, Any], field: str) -> Any:
    value: Any = metadata
    for part in field.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def _status_from_value(value: Any, expected: Any = True) -> str:
    if value is None:
        return UNKNOWN
    if isinstance(expected, list):
        return TRUE if value in expected else FALSE
    return TRUE if value == expected else FALSE


def _outcome(
    *,
    condition_id: str,
    kind: str,
    status: str,
    field: str | None = None,
    observed_value: Any = None,
    expected: Any = True,
    reason: str | None = None,
    evidence_ref: str | None = None,
) -> dict[str, Any]:
    return {
        "condition_id": condition_id,
        "kind": kind,
        "status": status if status in _VALID_STATUSES else UNKNOWN,
        "field": field,
        "observed_value": observed_value,
        "expected": expected,
        "reason": reason
        or (
            f"Requires {field} to match the expected value."
            if field
            else "Explicit transition precondition supplied by the evidence record."
        ),
        "evidence_ref": evidence_ref,
    }


def _field_condition(
    edge: GraphEdge,
    *,
    condition_id: str,
    kind: str,
    field: str,
    expected: Any = True,
    reason: str | None = None,
) -> dict[str, Any]:
    value = _field_value(edge.edge_metadata, field)
    return _outcome(
        condition_id=condition_id,
        kind=kind,
        status=_status_from_value(value, expected),
        field=field,
        observed_value=value,
        expected=expected,
        reason=reason,
    )


def _network_condition(edge: GraphEdge) -> dict[str, Any]:
    metadata = edge.edge_metadata
    if "network_reachable" in metadata:
        return _field_condition(
            edge,
            condition_id=f"{edge.edge_id}:network-reachable",
            kind="network_reachable",
            field="network_reachable",
            reason="Network path must be permitted by routing and packet-filter policy.",
        )
    action = metadata.get("acl_action")
    if isinstance(action, str):
        normalized = action.strip().lower()
        if normalized in {"allow", "permit", "accept"}:
            status = TRUE
        elif normalized in {"deny", "block", "drop", "reject"}:
            status = FALSE
        else:
            status = UNKNOWN
        return _outcome(
            condition_id=f"{edge.edge_id}:acl-action",
            kind="network_reachable",
            status=status,
            field="acl_action",
            observed_value=action,
            expected=["allow", "permit", "accept"],
            reason="ACL action must permit the source-to-target flow.",
            evidence_ref=str(metadata.get("acl_rule") or "") or None,
        )
    return _outcome(
        condition_id=f"{edge.edge_id}:network-reachable",
        kind="network_reachable",
        status=UNKNOWN,
        field="network_reachable",
        reason="No explicit network reachability or ACL action evidence is attached to this relationship.",
        evidence_ref=str(metadata.get("acl_rule") or "") or None,
    )


def _admin_conditions(edge: GraphEdge) -> list[dict[str, Any]]:
    metadata = edge.edge_metadata
    conditions = [
        _field_condition(
            edge,
            condition_id=f"{edge.edge_id}:admin-enabled",
            kind="standing_admin_right_active",
            field="admin_enabled" if "admin_enabled" in metadata else "standing_admin_enabled",
            reason="The administrative right must be active for this transition.",
        )
        if ("admin_enabled" in metadata or "standing_admin_enabled" in metadata)
        else _outcome(
            condition_id=f"{edge.edge_id}:admin-enabled",
            kind="standing_admin_right_active",
            status=UNKNOWN,
            field="admin_enabled",
            reason="The edge records an administrative relationship but does not state whether the right is currently active.",
        )
    ]

    for gate, required_key, satisfied_key in (
        ("pam", "pam_enforced", "pam_approval_granted"),
        ("mfa", "mfa_required", "mfa_satisfied"),
    ):
        if required_key not in metadata:
            conditions.append(
                _outcome(
                    condition_id=f"{edge.edge_id}:{gate}-gate",
                    kind=f"{gate}_gate",
                    status=UNKNOWN,
                    field=required_key,
                    reason=f"It is unknown whether the {gate.upper()} gate is enforced for this transition.",
                )
            )
        elif metadata.get(required_key) is False:
            conditions.append(
                _outcome(
                    condition_id=f"{edge.edge_id}:{gate}-gate",
                    kind=f"{gate}_gate",
                    status=TRUE,
                    field=required_key,
                    observed_value=False,
                    reason=f"{gate.upper()} is explicitly not required for this transition.",
                )
            )
        else:
            conditions.append(
                _field_condition(
                    edge,
                    condition_id=f"{edge.edge_id}:{gate}-gate",
                    kind=f"{gate}_gate",
                    field=satisfied_key,
                    reason=f"{gate.upper()} approval/satisfaction must be present when the gate is enforced.",
                )
            )
    return conditions


def _vulnerability_condition(edge: GraphEdge) -> dict[str, Any] | None:
    required_cve = edge.edge_metadata.get("requires_cve")
    if not isinstance(required_cve, str) or not required_cve:
        return None
    cve = required_cve.upper()
    states = edge.edge_metadata.get("vulnerability_status")
    state = states.get(cve) if isinstance(states, dict) else None
    remediated = edge.edge_metadata.get("remediated_cves", [])
    if isinstance(remediated, list) and cve in {str(value).upper() for value in remediated}:
        state = "patched"
    normalized = str(state).lower() if state is not None else None
    if normalized in {"patched", "mitigated", "remediated", "fixed", "closed"}:
        status = FALSE
    elif normalized in {"open", "unpatched", "vulnerable", "confirmed"}:
        status = TRUE
    else:
        status = UNKNOWN
    return _outcome(
        condition_id=f"{edge.edge_id}:cve:{cve}",
        kind="vulnerability_unpatched",
        status=status,
        field=f"vulnerability_status.{cve}",
        observed_value=state,
        expected="open/unpatched",
        reason=(
            f"Transition requires {cve} to remain unpatched; a patched or mitigated CVE blocks the transition."
        ),
        evidence_ref=edge.edge_metadata.get("vulnerability_evidence_ref"),
    )


def evaluate_edge_preconditions(edge: GraphEdge) -> list[dict[str, Any]]:
    """Evaluate typed transition prerequisites with true/false/unknown outcomes.

    Explicit edge_metadata['preconditions'] entries take precedence. Each entry may
    declare a boolean 'status', or a metadata 'field' and an 'expected' value.
    Missing facts evaluate to unknown; they are never silently treated as true.
    """
    explicit = edge.edge_metadata.get("preconditions")
    if isinstance(explicit, list):
        outcomes: list[dict[str, Any]] = []
        for index, spec in enumerate(explicit):
            if not isinstance(spec, dict):
                outcomes.append(
                    _outcome(
                        condition_id=f"{edge.edge_id}:explicit-{index}",
                        kind="invalid_precondition",
                        status=UNKNOWN,
                        reason="Malformed precondition entry; analyst review is required.",
                    )
                )
                continue
            kind = str(spec.get("kind") or spec.get("type") or "custom")
            condition_id = str(spec.get("id") or f"{edge.edge_id}:{kind}:{index}")
            raw_status = spec.get("status")
            if isinstance(raw_status, bool):
                status = TRUE if raw_status else FALSE
                outcomes.append(
                    _outcome(
                        condition_id=condition_id,
                        kind=kind,
                        status=status,
                        reason=str(spec.get("reason") or "Explicit boolean precondition status."),
                        evidence_ref=spec.get("evidence_ref"),
                    )
                )
                continue
            field = spec.get("field")
            if isinstance(field, str) and field:
                value = _field_value(edge.edge_metadata, field)
                expected = spec.get("expected", True)
                outcomes.append(
                    _outcome(
                        condition_id=condition_id,
                        kind=kind,
                        status=_status_from_value(value, expected),
                        field=field,
                        observed_value=value,
                        expected=expected,
                        reason=str(spec.get("reason") or f"Requires {field} to match its expected value."),
                        evidence_ref=spec.get("evidence_ref"),
                    )
                )
                continue
            outcomes.append(
                _outcome(
                    condition_id=condition_id,
                    kind=kind,
                    status=UNKNOWN,
                    reason="Precondition has neither an explicit status nor a metadata field to evaluate.",
                    evidence_ref=spec.get("evidence_ref"),
                )
            )
        cve_condition = _vulnerability_condition(edge)
        if cve_condition is not None:
            outcomes.append(cve_condition)
        return outcomes

    outcomes = []
    if edge.relation_type in (RelationType.CONNECTS_TO, RelationType.EXPOSES):
        outcomes.append(_network_condition(edge))
    elif edge.relation_type == RelationType.CAN_ADMINISTER:
        outcomes.extend(_admin_conditions(edge))
    elif edge.relation_type == RelationType.MEMBER_OF:
        outcomes.append(
            _field_condition(
                edge,
                condition_id=f"{edge.edge_id}:membership-active",
                kind="membership_active",
                field="membership_active",
                reason="Directory/IAM membership must be enabled and unrevoked.",
            )
        )
    elif edge.relation_type == RelationType.HAS_ROLE:
        outcomes.append(
            _field_condition(
                edge,
                condition_id=f"{edge.edge_id}:credential-available",
                kind="credential_available",
                field="credential_available",
                reason="The required role credentials or invocation context must be available.",
            )
        )
    elif edge.relation_type == RelationType.TRUSTS:
        outcomes.append(
            _field_condition(
                edge,
                condition_id=f"{edge.edge_id}:trust-accepts-token",
                kind="trust_accepts_token",
                field="trust_accepts_token",
                reason="The receiving trust boundary must accept the relevant token or session.",
            )
        )
    elif edge.relation_type == RelationType.RUNS_SERVICE:
        outcomes.append(
            _field_condition(
                edge,
                condition_id=f"{edge.edge_id}:service-listening",
                kind="service_listening",
                field="service_listening",
                reason="The target service must be active and listening.",
            )
        )

    cve_condition = _vulnerability_condition(edge)
    if cve_condition is not None:
        outcomes.append(cve_condition)

    return outcomes


def edge_preconditions_allow(edge: GraphEdge, *, allow_unknown: bool = True) -> bool:
    outcomes = evaluate_edge_preconditions(edge)
    if any(item["status"] == FALSE for item in outcomes):
        return False
    if not allow_unknown and any(item["status"] == UNKNOWN for item in outcomes):
        return False
    return True


def precondition_summary(outcomes: list[dict[str, Any]]) -> str:
    if any(item["status"] == FALSE for item in outcomes):
        return "blocked"
    if any(item["status"] == UNKNOWN for item in outcomes):
        return "conditional"
    return "satisfied"
