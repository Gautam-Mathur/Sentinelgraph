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
from app.domain.remediation_sim import (
    RemediationTransform,
    apply_sandbox_transforms,
    simulate_remediation,
)


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



def test_simulation_reports_reachability_when_candidate_enumeration_is_truncated() -> None:
    now = datetime.now(UTC)
    nodes = [
        GraphNode(NodeKind.ASSET, "web", "web", is_external_entry=True),
        GraphNode(NodeKind.ASSET, "app", "app"),
        GraphNode(NodeKind.ASSET, "db", "db", criticality="critical", is_crown_jewel=True),
    ]
    edges = [
        GraphEdge("e1", NodeKind.ASSET, "web", NodeKind.ASSET, "app", RelationType.CONNECTS_TO, FactKind.OBSERVED_FACT, 0.9, now),
        GraphEdge("e2", NodeKind.ASSET, "app", NodeKind.ASSET, "db", RelationType.CONNECTS_TO, FactKind.OBSERVED_FACT, 0.9, now),
        GraphEdge("e3", NodeKind.ASSET, "web", NodeKind.ASSET, "db", RelationType.CONNECTS_TO, FactKind.OBSERVED_FACT, 0.95, now, edge_metadata={"network_reachable": True}),
    ]
    constraints = PathSearchConstraints(
        start_node_keys=["asset:web"],
        target_node_keys=["asset:db"],
        max_hops=4,
        max_candidates=1,
        top_k=1,
    )
    sim = simulate_remediation(nodes=nodes, edges=edges, constraints=constraints, transforms=[])

    assert sim.baseline.total_paths == 1
    assert sim.baseline.path_search_complete is False
    assert sim.baseline.reachable_unbounded is True
    assert sim.modelled.reachable_unbounded is True
    assert sim.delta_summary["paths_eliminated_is_complete"] is False
    assert sim.delta_summary["possible_residual_reachability"] is True


def test_patching_cve_invalidates_vulnerability_prerequisite_without_changing_confidence() -> None:
    now = datetime.now(UTC)
    nodes = [
        GraphNode(
            NodeKind.ASSET,
            "web",
            "web",
            is_external_entry=True,
            open_cve_count=1,
            metadata={"vulnerability_status": {"CVE-2024-12345": "open"}},
        ),
        GraphNode(NodeKind.ASSET, "app", "app", criticality="critical", is_crown_jewel=True),
    ]
    edges = [
        GraphEdge(
            "cve-edge",
            NodeKind.ASSET,
            "web",
            NodeKind.ASSET,
            "app",
            RelationType.CONNECTS_TO,
            FactKind.OBSERVED_FACT,
            0.91,
            now,
            edge_metadata={
                "network_reachable": True,
                "requires_cve": "CVE-2024-12345",
            },
        )
    ]
    transform = RemediationTransform(
        transform_type=RemediationTransformType.PATCH_VULNERABILITY,
        asset_id="web",
        cve_id="CVE-2024-12345",
        notes="Patch the referenced vulnerability",
    )

    patched_nodes, patched_edges, applied = apply_sandbox_transforms(
        nodes, edges, [transform]
    )
    assert applied[0]["status"] == "applied"
    assert patched_edges[0].confidence == 0.91
    assert patched_edges[0].edge_metadata["vulnerability_status"]["CVE-2024-12345"] == "patched"
    assert patched_nodes[0].open_cve_count == 0

    sim = simulate_remediation(
        nodes=nodes,
        edges=edges,
        constraints=PathSearchConstraints(
            start_node_keys=["asset:web"],
            target_node_keys=["asset:app"],
            max_hops=2,
        ),
        transforms=[transform],
    )
    assert sim.baseline.reachable_unbounded is True
    assert sim.modelled.reachable_unbounded is False
    assert sim.delta_summary["possible_reachability_eliminated"] is True
    # Evidence strength is unchanged; the vulnerability prerequisite is what changed.
    assert edges[0].confidence == 0.91


def test_cve_patch_without_identifier_is_not_applied() -> None:
    now = datetime.now(UTC)
    nodes = [GraphNode(NodeKind.ASSET, "web", "web", open_cve_count=2)]
    edges = [
        GraphEdge(
            "cve-edge",
            NodeKind.ASSET,
            "web",
            NodeKind.ASSET,
            "web2",
            RelationType.CONNECTS_TO,
            FactKind.OBSERVED_FACT,
            0.9,
            now,
            edge_metadata={"requires_cve": "CVE-2024-12345"},
        )
    ]
    _, patched_edges, applied = apply_sandbox_transforms(
        nodes,
        edges,
        [RemediationTransform(transform_type=RemediationTransformType.PATCH_VULNERABILITY, asset_id="web")],
    )
    assert applied[0]["status"] == "not_applied"
    assert applied[0]["reason"].startswith("cve_id_required")
    assert patched_edges[0].confidence == 0.9
    assert nodes[0].open_cve_count == 2



def test_arbitrary_cve_is_not_applied_from_asset_id_or_open_count_alone() -> None:
    now = datetime.now(UTC)
    nodes = [
        GraphNode(NodeKind.ASSET, "web", "web", open_cve_count=4),
        GraphNode(NodeKind.ASSET, "db", "db"),
    ]
    transform = RemediationTransform(
        transform_type=RemediationTransformType.PATCH_VULNERABILITY,
        asset_id="web",
        cve_id="CVE-2024-99999",
    )
    patched_nodes, patched_edges, applied = apply_sandbox_transforms(
        nodes, [], [transform]
    )

    assert applied[0]["status"] == "not_applied"
    assert applied[0]["affected_elements"] == 0
    assert patched_nodes[0].open_cve_count == 4
    assert patched_nodes[0].metadata == {}
    assert patched_edges == []
