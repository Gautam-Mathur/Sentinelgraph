import pytest

from app.core.errors import ValidationAppError
from app.domain.models import NodeKind, RelationType
from app.domain.relationship_rules import ALLOWED_ENDPOINTS, validate_relationship


def test_all_allowed_relationship_pairs_pass() -> None:
    for rel_type in RelationType:
        pairs = ALLOWED_ENDPOINTS[rel_type]
        assert len(pairs) > 0
        for src_k, tgt_k in pairs:
            sk, tk, rt, fk = validate_relationship(
                source_kind=src_k.value,
                target_kind=tgt_k.value,
                relation_type=rel_type.value,
                fact_kind="observed_fact",
                confidence=0.85,
                source_id="id-1",
                target_id="id-2",
            )
            assert sk == src_k
            assert tk == tgt_k
            assert rt == rel_type
            assert fk.value == "observed_fact"


def test_disallowed_endpoint_pair_rejected() -> None:
    with pytest.raises(ValidationAppError) as exc:
        validate_relationship(
            source_kind=NodeKind.SERVICE.value,
            target_kind=NodeKind.GROUP.value,
            relation_type=RelationType.MEMBER_OF.value,
            fact_kind="observed_fact",
            confidence=0.9,
            source_id="svc-1",
            target_id="grp-1",
        )
    assert exc.value.code == "INVALID_RELATIONSHIP"


def test_arbitrary_relation_type_and_self_loop_rejected() -> None:
    with pytest.raises(ValidationAppError):
        validate_relationship(
            source_kind="asset",
            target_kind="asset",
            relation_type="MAGICALLY_PWNED",
            fact_kind="observed_fact",
            confidence=0.9,
            source_id="a1",
            target_id="a2",
        )

    with pytest.raises(ValidationAppError):
        validate_relationship(
            source_kind="asset",
            target_kind="asset",
            relation_type="CONNECTS_TO",
            fact_kind="observed_fact",
            confidence=0.9,
            source_id="same-id",
            target_id="same-id",
        )
