from copy import deepcopy
from datetime import UTC, datetime, timedelta

from app.domain.models import (
    FactKind,
    GraphEdge,
    GraphNode,
    NodeKind,
    PathSearchConstraints,
    RelationType,
    RemediationTransformType,
)
from app.domain.remediation_sim import RemediationTransform, simulate_remediation


def test_sandbox_simulation_leaves_baseline_intact_and_computes_deltas() -> None:
    now = datetime.now(UTC)
    nodes = [
        GraphNode(NodeKind.ASSET, "web", "web-dmz", criticality="medium", is_external_entry=True),
        GraphNode(NodeKind.IDENTITY, "svc", "svc-etl", criticality="medium"),
        GraphNode(NodeKind.ASSET, "db", "db-crown", criticality="critical", is_crown_jewel=True),
    ]
    edges = [
        GraphEdge("e1", NodeKind.ASSET, "web", NodeKind.IDENTITY, "svc", RelationType.HAS_ROLE, FactKind.OBSERVED_FACT, 0.9, now - timedelta(days=1)),
        GraphEdge("e2", NodeKind.IDENTITY, "svc", NodeKind.ASSET, "db", RelationType.CAN_ADMINISTER, FactKind.OBSERVED_FACT, 0.95, now - timedelta(days=1)),
    ]
    nodes_snap = deepcopy(nodes)
    edges_snap = deepcopy(edges)

    sim = simulate_remediation(
        nodes=nodes,
        edges=edges,
        constraints=PathSearchConstraints(
            start_node_keys=["asset:web"],
            target_node_keys=["asset:db"],
            max_hops=5,
        ),
        transforms=[
            RemediationTransform(
                transform_type=RemediationTransformType.REMOVE_RELATIONSHIP,
                relationship_id="e2",
                notes="Sever admin link",
            )
        ],
    )
    assert sim.is_modelled_only is True
    assert sim.baseline.total_paths == 1
    assert sim.modelled.total_paths == 0
    assert sim.delta_summary["paths_eliminated"] == 1
    assert sim.delta_summary["critical_assets_unlinked"] == 1
    # Original baseline inputs MUST not be mutated in place
    assert nodes == nodes_snap
    assert edges == edges_snap
