from __future__ import annotations

from typing import Any

from app.domain.models import GraphEdge, GraphNode, NodeKind, RelationType

TRUE = "true"
FALSE = "false"
UNKNOWN = "unknown"
_VALID_STATUSES = {TRUE, FALSE, UNKNOWN}


def kleene_all(statuses: list[str]) -> str:
    """Three-valued Kleene AND: FALSE dominates, else UNKNOWN if any UNKNOWN, else TRUE."""
    if any(status == FALSE for status in statuses):
        return FALSE
    if any(status == UNKNOWN for status in statuses):
        return UNKNOWN
    return TRUE


def kleene_any(statuses: list[str]) -> str:
    """Three-valued Kleene OR: TRUE dominates, else UNKNOWN if any UNKNOWN, else FALSE."""
    if any(status == TRUE for status in statuses):
        return TRUE
    if any(status == UNKNOWN for status in statuses):
        return UNKNOWN
    return FALSE


def kleene_not(status: str) -> str:
    """Three-valued Kleene NOT: swaps TRUE/FALSE and preserves UNKNOWN."""
    if status == TRUE:
        return FALSE
    if status == FALSE:
        return TRUE
    return UNKNOWN


def _field_value(metadata: dict[str, Any], field: str) -> Any:
    if field in metadata:
        return metadata[field]
    value: Any = metadata
    for part in field.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def _lookup_scoped_field(
    field: str,
    edge: GraphEdge,
    source_node: GraphNode | None = None,
    target_node: GraphNode | None = None,
    *,
    scope: str | None = None,
) -> Any:
    normalized_scope = str(scope or "auto").strip().lower()
    if normalized_scope == "edge":
        return _field_value(edge.edge_metadata, field)
    if normalized_scope == "source":
        return (
            _field_value(source_node.metadata, field)
            if source_node is not None and isinstance(source_node.metadata, dict)
            else None
        )
    if normalized_scope == "target":
        return (
            _field_value(target_node.metadata, field)
            if target_node is not None and isinstance(target_node.metadata, dict)
            else None
        )
    edge_val = _field_value(edge.edge_metadata, field)
    if edge_val is not None:
        return edge_val
    if target_node is not None and isinstance(target_node.metadata, dict):
        tgt_val = _field_value(target_node.metadata, field)
        if tgt_val is not None:
            return tgt_val
    if source_node is not None and isinstance(source_node.metadata, dict):
        return _field_value(source_node.metadata, field)
    return None


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


def _network_conditions(edge: GraphEdge) -> list[dict[str, Any]]:
    metadata = edge.edge_metadata
    conditions: list[dict[str, Any]] = []
    if "network_reachable" in metadata:
        conditions.append(
            _field_condition(
                edge,
                condition_id=f"{edge.edge_id}:network-reachable",
                kind="network_reachable",
                field="network_reachable",
                reason="Network path must be permitted by routing and packet-filter policy.",
            )
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
        conditions.append(
            _outcome(
                condition_id=f"{edge.edge_id}:acl-action",
                kind="network_reachable",
                status=status,
                field="acl_action",
                observed_value=action,
                expected=["allow", "permit", "accept"],
                reason="ACL action must permit the source-to-target flow.",
                evidence_ref=str(metadata.get("acl_rule") or "") or None,
            )
        )

    if not conditions:
        conditions.append(
            _outcome(
                condition_id=f"{edge.edge_id}:network-reachable",
                kind="network_reachable",
                status=UNKNOWN,
                field="network_reachable",
                reason="No explicit network reachability or ACL action evidence is attached to this relationship.",
                evidence_ref=str(metadata.get("acl_rule") or "") or None,
            )
        )
    return conditions

def _explicit_gate_status(
    gate_kind: str,
    explicit_statuses: dict[str, list[str]],
) -> str:
    statuses = explicit_statuses.get(gate_kind, [])
    if FALSE in statuses:
        return FALSE
    if TRUE in statuses:
        return TRUE
    return UNKNOWN


def _admin_conditions(
    edge: GraphEdge,
    explicit_statuses: dict[str, list[str]],
) -> list[dict[str, Any]]:
    metadata = edge.edge_metadata
    admin_field = (
        "admin_enabled"
        if "admin_enabled" in metadata
        else "standing_admin_enabled"
    )
    conditions = [
        _field_condition(
            edge,
            condition_id=f"{edge.edge_id}:admin-enabled",
            kind="standing_admin_right_active",
            field=admin_field,
            reason="The administrative right must be active for this transition.",
        )
        if (("admin_enabled" in metadata) or ("standing_admin_enabled" in metadata))
        else _outcome(
            condition_id=f"{edge.edge_id}:admin-enabled",
            kind="standing_admin_right_active",
            status=UNKNOWN,
            field="admin_enabled",
            reason=(
                "The edge records an administrative relationship but does not state "
                "whether the right is currently active."
            ),
        )
    ]

    for gate, required_key, satisfied_key in (
        ("pam", "pam_enforced", "pam_approval_granted"),
        ("mfa", "mfa_required", "mfa_satisfied"),
    ):
        explicit_status = _explicit_gate_status(
            f"{gate}_gate", explicit_statuses
        )
        required_present = required_key in metadata
        required = metadata.get(required_key)
        satisfied_present = satisfied_key in metadata
        satisfied_status = _status_from_value(metadata.get(satisfied_key))

        if required is False:
            status = TRUE
            reason = f"{gate.upper()} is explicitly not required for this transition."
        elif required is True:
            # An explicit typed gate may resolve missing satisfaction evidence, but
            # it cannot overrule an observed failure of the gate.
            status = (
                satisfied_status
                if satisfied_status != UNKNOWN
                else explicit_status
            )
            reason = (
                f"{gate.upper()} approval/satisfaction must be present when the gate is enforced."
            )
        elif not required_present:
            # With no policy flag, the gate is unknown unless a typed, evidence-backed
            # precondition explicitly records its outcome.
            if satisfied_present and satisfied_status == FALSE:
                status = FALSE
                reason = f"{gate.upper()} satisfaction is explicitly recorded as false."
            else:
                status = explicit_status
                reason = (
                    f"It is unknown whether the {gate.upper()} gate is enforced; "
                    "a typed explicit gate result may resolve this uncertainty."
                )
        else:
            # A malformed/non-boolean policy value cannot be silently treated as
            # either enforced or disabled.
            status = explicit_status
            reason = f"The {gate.upper()} enforcement flag is not a recognised boolean."

        conditions.append(
            _outcome(
                condition_id=f"{edge.edge_id}:{gate}-gate",
                kind=f"{gate}_gate",
                status=status,
                field=satisfied_key if required is True else required_key,
                observed_value=metadata.get(satisfied_key)
                if required is True or satisfied_present
                else required,
                reason=reason,
            )
        )
    return conditions


def _vulnerability_condition(
    edge: GraphEdge,
    source_node: GraphNode | None = None,
    target_node: GraphNode | None = None,
) -> dict[str, Any] | None:
    required_cve = edge.edge_metadata.get("requires_cve")
    if not isinstance(required_cve, str) or not required_cve:
        return None
    return _cve_status_for_code(required_cve, edge, source_node, target_node)

def _cve_status_for_code(
    cve_code: str,
    edge: GraphEdge,
    source_node: GraphNode | None = None,
    target_node: GraphNode | None = None,
) -> dict[str, Any]:
    cve = cve_code.upper()
    sources: list[Any] = []

    def add_state(metadata: dict[str, Any], *, state_field: str, remediated_field: str) -> None:
        states = metadata.get(state_field)
        if isinstance(states, dict):
            sources.extend(
                value for key, value in states.items() if str(key).upper() == cve
            )
        remediated = metadata.get(remediated_field, [])
        if isinstance(remediated, list) and any(
            str(value).upper() == cve for value in remediated
        ):
            sources.append("patched")

    add_state(
        edge.edge_metadata,
        state_field="vulnerability_status",
        remediated_field="remediated_cves",
    )
    required_scope = str(edge.edge_metadata.get("requires_cve_on") or "").lower()
    scoped_nodes = (
        [source_node]
        if required_scope == "source"
        else [target_node]
        if required_scope == "target"
        else [source_node, target_node]
    )
    for node in scoped_nodes:
        if node is not None and isinstance(node.metadata, dict):
            add_state(
                node.metadata,
                state_field="vulnerability_status",
                remediated_field="remediated_cves",
            )

    normalized = {str(value).strip().lower() for value in sources}
    active_states = {"open", "unpatched", "vulnerable", "confirmed"}
    patched_states = {"patched", "mitigated", "remediated", "fixed", "closed"}
    has_active = bool(normalized & active_states)
    has_patched = bool(normalized & patched_states)
    if has_active and has_patched:
        status = UNKNOWN
        reason = (
            f"Conflicting evidence exists for {cve}: at least one source says open "
            "and another says patched or remediated."
        )
    elif has_active:
        status = TRUE
        reason = f"Evidence records {cve} as open/unpatched on the relationship or a scoped endpoint."
    elif has_patched:
        status = FALSE
        reason = f"Evidence records {cve} as patched or remediated on the relationship or scoped endpoint."
    else:
        status = UNKNOWN
        reason = f"No CVE-specific state for {cve} is available on the relationship or scoped endpoints."

    return _outcome(
        condition_id=f"{edge.edge_id}:cve:{cve}",
        kind="vulnerability_unpatched",
        status=status,
        field=f"vulnerability_status.{cve}",
        observed_value=sorted(normalized),
        expected="open/unpatched",
        reason=reason,
        evidence_ref=edge.edge_metadata.get("vulnerability_evidence_ref"),
    )


def _is_expr_spec(spec: Any) -> bool:
    if not isinstance(spec, dict):
        return False
    return any(
        key in spec
        for key in (
            "ALL",
            "all",
            "and",
            "AND",
            "ANY",
            "any",
            "or",
            "OR",
            "NOT",
            "not",
            "op",
            "capability",
            "has_capability",
            "lacks_capability",
            "cve",
            "requires_cve",
        )
    )


def _collect_expr_capabilities(spec: Any, out: set[str]) -> None:
    if isinstance(spec, list):
        for item in spec:
            _collect_expr_capabilities(item, out)
        return
    if not isinstance(spec, dict):
        return
    for cap_key in ("capability", "has_capability", "lacks_capability"):
        cap_val = spec.get(cap_key)
        if isinstance(cap_val, str) and cap_val.strip():
            out.add(cap_val.strip())
    for list_key in ("ALL", "all", "AND", "and", "ANY", "any", "OR", "or", "children"):
        children = spec.get(list_key)
        if isinstance(children, list):
            for child in children:
                _collect_expr_capabilities(child, out)
    for single_key in ("NOT", "not", "child"):
        if single_key in spec:
            _collect_expr_capabilities(spec[single_key], out)


def extract_referenced_capabilities(
    edges: list[GraphEdge],
    nodes: list[GraphNode] | None = None,
) -> frozenset[str]:
    """Return every capability identifier referenced by edge/node preconditions."""
    caps: set[str] = set()
    for edge in edges:
        meta = edge.edge_metadata if isinstance(edge.edge_metadata, dict) else {}
        for list_key in ("requires_capabilities", "requires_capability"):
            raw = meta.get(list_key)
            if isinstance(raw, str) and raw.strip():
                caps.add(raw.strip())
            elif isinstance(raw, list):
                for item in raw:
                    if isinstance(item, str) and item.strip():
                        caps.add(item.strip())
        for expr_key in ("precondition_expr", "requires_expr", "preconditions"):
            if expr_key in meta:
                _collect_expr_capabilities(meta[expr_key], caps)
    if nodes:
        for node in nodes:
            meta = node.metadata if isinstance(node.metadata, dict) else {}
            raw = meta.get("requires_capabilities")
            if isinstance(raw, list):
                for item in raw:
                    if isinstance(item, str) and item.strip():
                        caps.add(item.strip())
            for expr_key in ("precondition_expr", "requires_expr"):
                if expr_key in meta:
                    _collect_expr_capabilities(meta[expr_key], caps)
    return frozenset(caps)


def initial_capabilities_for_node(node: GraphNode) -> frozenset[str]:
    """Return initial attacker capability propositions held at a starting node."""
    caps: set[str] = {f"foothold:{node.key}"}
    meta = node.metadata if isinstance(node.metadata, dict) else {}
    raw_init = meta.get("initial_capabilities")
    if isinstance(raw_init, list):
        for cap in raw_init:
            if isinstance(cap, str) and cap.strip():
                caps.add(cap.strip())
    if node.node_kind == NodeKind.IDENTITY:
        caps.add(f"identity:{node.node_id}")
        principal = meta.get("principal_name")
        if isinstance(principal, str) and principal.strip():
            caps.add(f"principal:{principal.strip()}")
    elif node.node_kind == NodeKind.GROUP:
        caps.add(f"group:{node.node_id}")
    return frozenset(caps)


def transition_capability_effects(
    edge: GraphEdge,
    source_node: GraphNode | None = None,
    target_node: GraphNode | None = None,
) -> tuple[list[str], list[str]]:
    """Compute ordered (adds, removes) capability effects for a transition."""
    adds: list[str] = [f"foothold:{edge.target_key}"]
    removes: list[str] = []

    if edge.relation_type == RelationType.HAS_ROLE:
        adds.extend([f"role:{edge.target_id}", f"identity:{edge.target_id}"])
        if target_node is not None and isinstance(target_node.metadata, dict):
            principal = target_node.metadata.get("principal_name")
            if isinstance(principal, str) and principal.strip():
                adds.append(f"principal:{principal.strip()}")
    elif edge.relation_type == RelationType.MEMBER_OF:
        adds.append(f"group:{edge.target_id}")
    elif edge.relation_type == RelationType.TRUSTS:
        adds.append(f"trust:{edge.target_key}")
    elif edge.relation_type == RelationType.RUNS_SERVICE:
        adds.append(f"service:{edge.target_id}")

    meta = edge.edge_metadata if isinstance(edge.edge_metadata, dict) else {}
    raw_adds = meta.get("adds_capabilities")
    if isinstance(raw_adds, list):
        adds.extend(str(c).strip() for c in raw_adds if isinstance(c, str) and str(c).strip())
    if target_node is not None and isinstance(target_node.metadata, dict):
        node_adds = target_node.metadata.get("adds_capabilities")
        if isinstance(node_adds, list):
            adds.extend(str(c).strip() for c in node_adds if isinstance(c, str) and str(c).strip())

    for rem_key in ("removes_capabilities", "revokes_capabilities", "expires_capabilities"):
        raw_rem = meta.get(rem_key)
        if isinstance(raw_rem, list):
            removes.extend(str(c).strip() for c in raw_rem if isinstance(c, str) and str(c).strip())
    if target_node is not None and isinstance(target_node.metadata, dict):
        node_rem = target_node.metadata.get("removes_capabilities")
        if isinstance(node_rem, list):
            removes.extend(str(c).strip() for c in node_rem if isinstance(c, str) and str(c).strip())

    if (
        meta.get("token_expired") is True
        or meta.get("credential_expired") is True
        or meta.get("revoked") is True
    ):
        removes.extend([f"identity:{edge.target_id}", f"role:{edge.target_id}", f"identity:{edge.source_id}"])

    # Preserve insertion order while deduplicating.
    dedup_adds = list(dict.fromkeys(adds))
    dedup_removes = list(dict.fromkeys(removes))
    return dedup_adds, dedup_removes


def apply_transition_effects(
    edge: GraphEdge,
    source_node: GraphNode | None,
    target_node: GraphNode | None,
    capability_state: frozenset[str] | set[str],
) -> tuple[frozenset[str], list[str], list[str]]:
    """Apply non-monotonic STRIPS effects: delete first, then add."""
    adds, removes = transition_capability_effects(edge, source_node, target_node)
    remove_set = set(removes)
    add_set = set(adds)
    next_state = (set(capability_state) - remove_set) | add_set
    # Record effective deltas (what changed or was explicitly declared by edge/node)
    removed_effective = sorted(c for c in removes if c in capability_state and c not in add_set)
    explicit_adds = sorted(
        c
        for c in adds
        if c not in capability_state or not c.startswith("foothold:")
    )
    return frozenset(next_state), explicit_adds, removed_effective


def evaluate_precondition_expr(
    expr: Any,
    edge: GraphEdge,
    source_node: GraphNode | None = None,
    target_node: GraphNode | None = None,
    *,
    capability_state: frozenset[str] | set[str] | None = None,
) -> tuple[str, str]:
    """Evaluate a nested ALL/ANY/NOT expression under Kleene three-valued logic.

    Returns ``(status, summary_reason)``.
    """
    if not isinstance(expr, dict):
        return UNKNOWN, "Malformed compound precondition expression; analyst review required."

    # 1. Compound logical combinators
    all_children = expr.get("ALL") or expr.get("all") or expr.get("AND") or expr.get("and")
    if all_children is None and str(expr.get("op") or "").upper() in {"ALL", "AND"}:
        all_children = expr.get("children")
    if isinstance(all_children, list):
        if not all_children:
            return TRUE, "Empty ALL expression evaluates to true."
        child_results = [
            evaluate_precondition_expr(
                c, edge, source_node, target_node, capability_state=capability_state
            )
            for c in all_children
        ]
        status = kleene_all([r[0] for r in child_results])
        if status == FALSE:
            failing = next(r[1] for r in child_results if r[0] == FALSE)
            return FALSE, f"ALL condition blocked: {failing}"
        if status == UNKNOWN:
            unknowns = next(r[1] for r in child_results if r[0] == UNKNOWN)
            return UNKNOWN, f"ALL condition uncertain: {unknowns}"
        return TRUE, f"All {len(child_results)} conjunctive precondition(s) satisfied."

    any_children = expr.get("ANY") or expr.get("any") or expr.get("OR") or expr.get("or")
    if any_children is None and str(expr.get("op") or "").upper() in {"ANY", "OR"}:
        any_children = expr.get("children")
    if isinstance(any_children, list):
        if not any_children:
            return FALSE, "Empty ANY expression evaluates to false."
        child_results = [
            evaluate_precondition_expr(
                c, edge, source_node, target_node, capability_state=capability_state
            )
            for c in any_children
        ]
        status = kleene_any([r[0] for r in child_results])
        if status == TRUE:
            passing = next(r[1] for r in child_results if r[0] == TRUE)
            return TRUE, f"ANY condition satisfied: {passing}"
        if status == UNKNOWN:
            return UNKNOWN, "ANY condition unresolved: no alternative branch is proven true."
        return FALSE, "ANY condition blocked: every disjunctive alternative evaluated false."

    has_not = "NOT" in expr or "not" in expr or str(expr.get("op") or "").upper() == "NOT"
    if has_not:
        child = expr.get("NOT") if "NOT" in expr else expr.get("not") if "not" in expr else expr.get("child")
        inner_status, inner_reason = evaluate_precondition_expr(
            child, edge, source_node, target_node, capability_state=capability_state
        )
        inv = kleene_not(inner_status)
        if inv == TRUE:
            return TRUE, f"Negated condition holds (inner false: {inner_reason})."
        if inv == FALSE:
            return FALSE, f"Negated condition failed (inner true: {inner_reason})."
        return UNKNOWN, f"Negated condition uncertain (inner unknown: {inner_reason})."

    # 2. Capability state predicates
    cap = expr.get("capability") or expr.get("has_capability")
    if isinstance(cap, str) and cap.strip():
        cap_name = cap.strip()
        if capability_state is None:
            return UNKNOWN, f"Capability '{cap_name}' requires stateful path evaluation."
        if cap_name in capability_state:
            return TRUE, f"Attacker state holds required capability '{cap_name}'."
        return FALSE, f"Attacker state lacks required capability '{cap_name}'."

    lacks_cap = expr.get("lacks_capability")
    if isinstance(lacks_cap, str) and lacks_cap.strip():
        cap_name = lacks_cap.strip()
        if capability_state is None:
            return UNKNOWN, f"Negated capability '{cap_name}' requires stateful path evaluation."
        if cap_name not in capability_state:
            return TRUE, f"Attacker state confirms absence of capability '{cap_name}'."
        return FALSE, f"Attacker state holds conflicting capability '{cap_name}'."

    # 3. CVE leaf predicate
    cve_code = expr.get("cve") or expr.get("requires_cve")
    if isinstance(cve_code, str) and cve_code.strip():
        cve_out = _cve_status_for_code(cve_code.strip(), edge, source_node, target_node)
        return str(cve_out["status"]), str(cve_out["reason"])

    # 4. Explicit boolean/tri-state status
    if "status" in expr:
        raw_status = expr.get("status")
        if isinstance(raw_status, bool):
            return (TRUE if raw_status else FALSE), str(
                expr.get("reason") or f"Explicit status={raw_status}."
            )
        if isinstance(raw_status, str) and raw_status.strip().lower() in _VALID_STATUSES:
            s_val = raw_status.strip().lower()
            return s_val, str(expr.get("reason") or f"Explicit status={s_val}.")

    # 5. Scoped metadata field predicate
    field = expr.get("field")
    if isinstance(field, str) and field:
        expected = expr.get("expected", True)
        value = _lookup_scoped_field(
            field,
            edge,
            source_node,
            target_node,
            scope=expr.get("scope"),
        )
        status = _status_from_value(value, expected)
        return status, str(
            expr.get("reason")
            or f"Field '{field}' observed={value!r}, expected={expected!r}."
        )

    return UNKNOWN, "Unrecognized precondition expression leaf; analyst review required."


def evaluate_edge_preconditions(
    edge: GraphEdge,
    source_node: GraphNode | None = None,
    target_node: GraphNode | None = None,
    *,
    capability_state: frozenset[str] | set[str] | None = None,
) -> list[dict[str, Any]]:
    """Evaluate explicit, compound logical, stateful-capability, and relationship preconditions.

    Explicit requirements are additive. They do not bypass mandatory relationship
    gates or a requires_cve prerequisite.
    """
    outcomes: list[dict[str, Any]] = []
    explicit = edge.edge_metadata.get("preconditions")
    explicit_kinds: set[str] = set()
    if isinstance(explicit, list):
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
            explicit_kinds.add(kind)
            condition_id = str(spec.get("id") or f"{edge.edge_id}:{kind}:{index}")
            if _is_expr_spec(spec):
                status, reason = evaluate_precondition_expr(
                    spec,
                    edge,
                    source_node,
                    target_node,
                    capability_state=capability_state,
                )
                outcomes.append(
                    _outcome(
                        condition_id=condition_id,
                        kind=kind if kind != "custom" else "compound_precondition",
                        status=status,
                        reason=str(spec.get("reason") or reason),
                        evidence_ref=spec.get("evidence_ref"),
                    )
                )
                continue
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
                value = _lookup_scoped_field(
                    field,
                    edge,
                    source_node,
                    target_node,
                    scope=spec.get("scope"),
                )
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

    # Top-level compound expression (precondition_expr / requires_expr)
    for expr_key in ("precondition_expr", "requires_expr"):
        expr_val = edge.edge_metadata.get(expr_key)
        if expr_val is not None:
            status, reason = evaluate_precondition_expr(
                expr_val,
                edge,
                source_node,
                target_node,
                capability_state=capability_state,
            )
            outcomes.append(
                _outcome(
                    condition_id=f"{edge.edge_id}:{expr_key}",
                    kind="compound_precondition",
                    status=status,
                    field=expr_key,
                    reason=reason,
                )
            )

    # Required attacker capabilities (edge and target node metadata)
    req_caps: list[str] = []
    for raw_source in (
        edge.edge_metadata.get("requires_capabilities"),
        edge.edge_metadata.get("requires_capability"),
        target_node.metadata.get("requires_capabilities")
        if target_node is not None and isinstance(target_node.metadata, dict)
        else None,
    ):
        if isinstance(raw_source, str) and raw_source.strip():
            req_caps.append(raw_source.strip())
        elif isinstance(raw_source, list):
            req_caps.extend(str(c).strip() for c in raw_source if isinstance(c, str) and str(c).strip())
    for cap_name in dict.fromkeys(req_caps):
        if capability_state is None:
            cap_status = UNKNOWN
            cap_reason = f"Requires attacker capability '{cap_name}' (resolved during stateful path search)."
        elif cap_name in capability_state:
            cap_status = TRUE
            cap_reason = f"Attacker holds required capability '{cap_name}' from an earlier step."
        else:
            cap_status = FALSE
            cap_reason = f"Attacker lacks required capability '{cap_name}' at this step."
        outcomes.append(
            _outcome(
                condition_id=f"{edge.edge_id}:cap:{cap_name}",
                kind="requires_capability",
                status=cap_status,
                field=cap_name,
                observed_value=sorted(capability_state) if capability_state is not None else None,
                expected=cap_name,
                reason=cap_reason,
            )
        )

    # Required host/registry configuration flags (if explicitly declared on edge)
    for cfg_key in ("requires_config", "requires_registry_keys"):
        cfg_req = edge.edge_metadata.get(cfg_key)
        if isinstance(cfg_req, dict):
            for setting_key, expected_val in sorted(cfg_req.items()):
                observed_val = _lookup_scoped_field(
                    str(setting_key), edge, source_node, target_node
                )
                outcomes.append(
                    _outcome(
                        condition_id=f"{edge.edge_id}:cfg:{setting_key}",
                        kind="required_config",
                        status=_status_from_value(observed_val, expected_val),
                        field=str(setting_key),
                        observed_value=observed_val,
                        expected=expected_val,
                        reason=f"Requires configuration/registry setting '{setting_key}' == {expected_val!r}.",
                    )
                )

    if edge.relation_type in (RelationType.CONNECTS_TO, RelationType.EXPOSES):
        if (
            "network_reachable" in edge.edge_metadata
            or "acl_action" in edge.edge_metadata
            or not ({"network_reachable", "acl_permitted"} & explicit_kinds)
        ):
            # Evaluate every supplied routing/ACL fact, even when an explicit
            # precondition also exists, so contradictory evidence cannot be hidden.
            outcomes.extend(_network_conditions(edge))
    elif edge.relation_type == RelationType.CAN_ADMINISTER:
        explicit_gate_statuses: dict[str, list[str]] = {}
        for outcome in outcomes:
            if outcome["kind"] in {"pam_gate", "mfa_gate"}:
                explicit_gate_statuses.setdefault(outcome["kind"], []).append(
                    outcome["status"]
                )
        outcomes.extend(_admin_conditions(edge, explicit_gate_statuses))
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

    # Explicit MFA enforcement on non-CAN_ADMINISTER edges when explicitly annotated
    if edge.relation_type != RelationType.CAN_ADMINISTER and (
        "mfa_required" in edge.edge_metadata or "mfa_satisfied" in edge.edge_metadata
    ):
        mfa_req = edge.edge_metadata.get("mfa_required")
        mfa_sat = _status_from_value(edge.edge_metadata.get("mfa_satisfied"))
        if mfa_req is False:
            mfa_status = TRUE
            mfa_reason = "MFA is explicitly not required for this transition."
        elif mfa_req is True:
            mfa_status = mfa_sat
            mfa_reason = "MFA satisfaction is required for this transition."
        elif mfa_sat == FALSE:
            mfa_status = FALSE
            mfa_reason = "MFA satisfaction is explicitly recorded as false."
        else:
            mfa_status = UNKNOWN
            mfa_reason = "MFA requirement is unresolved."
        outcomes.append(
            _outcome(
                condition_id=f"{edge.edge_id}:mfa-gate",
                kind="mfa_gate",
                status=mfa_status,
                field="mfa_satisfied" if mfa_req is True else "mfa_required",
                observed_value=edge.edge_metadata.get("mfa_satisfied")
                if mfa_req is True or "mfa_satisfied" in edge.edge_metadata
                else mfa_req,
                reason=mfa_reason,
            )
        )

    # Explicit expiry/revocation flags block transition when recorded as True
    for expiry_field in ("credential_expired", "token_expired", "revoked"):
        if edge.edge_metadata.get(expiry_field) is True:
            outcomes.append(
                _outcome(
                    condition_id=f"{edge.edge_id}:{expiry_field}",
                    kind="credential_not_expired",
                    status=FALSE,
                    field=expiry_field,
                    observed_value=True,
                    expected=False,
                    reason=f"Transition blocked because '{expiry_field}' is true.",
                )
            )

    cve_condition = _vulnerability_condition(edge, source_node, target_node)
    if cve_condition is not None:
        outcomes.append(cve_condition)

    return outcomes


def edge_preconditions_allow(
    edge: GraphEdge,
    *,
    allow_unknown: bool = True,
    source_node: GraphNode | None = None,
    target_node: GraphNode | None = None,
    capability_state: frozenset[str] | set[str] | None = None,
) -> bool:
    outcomes = evaluate_edge_preconditions(
        edge,
        source_node,
        target_node,
        capability_state=capability_state,
    )
    if any(item["status"] == FALSE for item in outcomes):
        return False
    return allow_unknown or not any(item["status"] == UNKNOWN for item in outcomes)


def precondition_summary(outcomes: list[dict[str, Any]]) -> str:
    if any(item["status"] == FALSE for item in outcomes):
        return "blocked"
    if any(item["status"] == UNKNOWN for item in outcomes):
        return "conditional"
    return "satisfied"
