from app.core.errors import FieldError, ValidationAppError
from app.domain.models import FactKind, NodeKind, RelationType

ALLOWED_ENDPOINTS: dict[RelationType, frozenset[tuple[NodeKind, NodeKind]]] = {
    RelationType.HOSTS: frozenset(
        {
            (NodeKind.ASSET, NodeKind.ASSET),
            (NodeKind.ASSET, NodeKind.SERVICE),
        }
    ),
    RelationType.CONNECTS_TO: frozenset(
        {
            (NodeKind.ASSET, NodeKind.ASSET),
            (NodeKind.ASSET, NodeKind.SERVICE),
            (NodeKind.SERVICE, NodeKind.ASSET),
            (NodeKind.SERVICE, NodeKind.SERVICE),
        }
    ),
    RelationType.RUNS_SERVICE: frozenset(
        {
            (NodeKind.ASSET, NodeKind.SERVICE),
        }
    ),
    RelationType.EXPOSES: frozenset(
        {
            (NodeKind.ASSET, NodeKind.SERVICE),
            (NodeKind.SERVICE, NodeKind.ASSET),
            (NodeKind.ASSET, NodeKind.ASSET),
        }
    ),
    RelationType.DEPENDS_ON: frozenset(
        {
            (NodeKind.ASSET, NodeKind.ASSET),
            (NodeKind.ASSET, NodeKind.SERVICE),
            (NodeKind.SERVICE, NodeKind.SERVICE),
            (NodeKind.SERVICE, NodeKind.IDENTITY),
            (NodeKind.ASSET, NodeKind.IDENTITY),
        }
    ),
    RelationType.MEMBER_OF: frozenset(
        {
            (NodeKind.IDENTITY, NodeKind.GROUP),
            (NodeKind.GROUP, NodeKind.GROUP),
        }
    ),
    RelationType.HAS_ROLE: frozenset(
        {
            (NodeKind.IDENTITY, NodeKind.GROUP),
            (NodeKind.IDENTITY, NodeKind.IDENTITY),
            (NodeKind.GROUP, NodeKind.GROUP),
            (NodeKind.ASSET, NodeKind.IDENTITY),
            (NodeKind.SERVICE, NodeKind.IDENTITY),
        }
    ),
    RelationType.CAN_ADMINISTER: frozenset(
        {
            (NodeKind.IDENTITY, NodeKind.ASSET),
            (NodeKind.IDENTITY, NodeKind.SERVICE),
            (NodeKind.IDENTITY, NodeKind.GROUP),
            (NodeKind.IDENTITY, NodeKind.IDENTITY),
            (NodeKind.GROUP, NodeKind.ASSET),
            (NodeKind.GROUP, NodeKind.SERVICE),
            (NodeKind.GROUP, NodeKind.GROUP),
            (NodeKind.GROUP, NodeKind.IDENTITY),
            (NodeKind.ASSET, NodeKind.ASSET),
        }
    ),
    RelationType.TRUSTS: frozenset(
        {
            (NodeKind.IDENTITY, NodeKind.IDENTITY),
            (NodeKind.ASSET, NodeKind.ASSET),
            (NodeKind.ASSET, NodeKind.IDENTITY),
            (NodeKind.IDENTITY, NodeKind.ASSET),
            (NodeKind.GROUP, NodeKind.GROUP),
        }
    ),
    RelationType.OWNS: frozenset(
        {
            (NodeKind.IDENTITY, NodeKind.ASSET),
            (NodeKind.IDENTITY, NodeKind.SERVICE),
            (NodeKind.IDENTITY, NodeKind.GROUP),
            (NodeKind.GROUP, NodeKind.ASSET),
            (NodeKind.GROUP, NodeKind.SERVICE),
        }
    ),
}


def validate_relationship(
    *,
    source_kind: str,
    target_kind: str,
    relation_type: str,
    fact_kind: str,
    confidence: float,
    source_id: str,
    target_id: str,
) -> tuple[NodeKind, NodeKind, RelationType, FactKind]:
    errors: list[FieldError] = []
    try:
        src_k = NodeKind(source_kind)
    except ValueError:
        errors.append(
            FieldError(
                field="source_kind",
                message=f"Unsupported source_kind '{source_kind}'",
                code="invalid_node_kind",
            )
        )
        src_k = NodeKind.ASSET

    try:
        tgt_k = NodeKind(target_kind)
    except ValueError:
        errors.append(
            FieldError(
                field="target_kind",
                message=f"Unsupported target_kind '{target_kind}'",
                code="invalid_node_kind",
            )
        )
        tgt_k = NodeKind.ASSET

    try:
        rel_t = RelationType(relation_type)
    except ValueError:
        errors.append(
            FieldError(
                field="relation_type",
                message=(
                    f"Unsupported relation_type '{relation_type}'. "
                    f"Allowed types: {', '.join(r.value for r in RelationType)}"
                ),
                code="invalid_relation_type",
            )
        )
        raise ValidationAppError(
            code="INVALID_RELATIONSHIP",
            message="Arbitrary or unsupported relationship type rejected.",
            field_errors=errors,
        ) from None

    try:
        fact_k = FactKind(fact_kind)
    except ValueError:
        errors.append(
            FieldError(
                field="fact_kind",
                message=f"Unsupported fact_kind '{fact_kind}'",
                code="invalid_fact_kind",
            )
        )
        fact_k = FactKind.OBSERVED_FACT

    if not (0.0 < confidence <= 1.0):
        errors.append(
            FieldError(
                field="confidence",
                message="Confidence must be in range (0.0, 1.0]",
                code="invalid_confidence",
            )
        )

    if source_kind == target_kind and source_id == target_id:
        errors.append(
            FieldError(
                field="target_id",
                message="Self-loop relationship on identical node is not permitted",
                code="self_loop_rejected",
            )
        )

    if not errors and (src_k, tgt_k) not in ALLOWED_ENDPOINTS[rel_t]:
        errors.append(
            FieldError(
                field="relation_type",
                message=(
                    f"Relation '{rel_t.value}' does not allow endpoint pair "
                    f"({src_k.value} -> {tgt_k.value})."
                ),
                code="disallowed_endpoint_pair",
            )
        )

    if errors:
        raise ValidationAppError(
            code="INVALID_RELATIONSHIP",
            message="Relationship failed domain validation.",
            field_errors=errors,
        )

    return src_k, tgt_k, rel_t, fact_k
