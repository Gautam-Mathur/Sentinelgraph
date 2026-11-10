from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class AssetType(StrEnum):
    HOST = "host"
    ENDPOINT = "endpoint"
    SERVER = "server"
    CLOUD_RESOURCE = "cloud_resource"
    APPLICATION = "application"
    DATABASE = "database"
    NETWORK_DEVICE = "network_device"
    IDENTITY_PROVIDER = "identity_provider"


class EnvironmentType(StrEnum):
    PROD = "prod"
    STAGING = "staging"
    DEV = "dev"
    LAB = "lab"


class CriticalityLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class LifecycleState(StrEnum):
    ACTIVE = "active"
    DECOMMISSIONED = "decommissioned"
    PLANNED = "planned"
    UNKNOWN = "unknown"


class IdentityType(StrEnum):
    HUMAN_USER = "human_user"
    SERVICE_ACCOUNT = "service_account"
    MACHINE_IDENTITY = "machine_identity"
    WORKLOAD_IDENTITY = "workload_identity"
    ROLE_IDENTITY = "role_identity"


class NodeKind(StrEnum):
    ASSET = "asset"
    SERVICE = "service"
    IDENTITY = "identity"
    GROUP = "group"


class RelationType(StrEnum):
    HOSTS = "HOSTS"
    CONNECTS_TO = "CONNECTS_TO"
    RUNS_SERVICE = "RUNS_SERVICE"
    MEMBER_OF = "MEMBER_OF"
    HAS_ROLE = "HAS_ROLE"
    CAN_ADMINISTER = "CAN_ADMINISTER"
    TRUSTS = "TRUSTS"
    OWNS = "OWNS"
    EXPOSES = "EXPOSES"
    DEPENDS_ON = "DEPENDS_ON"


class FactKind(StrEnum):
    OBSERVED_FACT = "observed_fact"
    INFERRED_RELATIONSHIP = "inferred_relationship"
    ANALYST_ASSERTION = "analyst_assertion"


class AlgorithmType(StrEnum):
    BFS = "bfs"
    DIJKSTRA = "dijkstra"


class RemediationTransformType(StrEnum):
    REMOVE_RELATIONSHIP = "remove_relationship"
    DOWNGRADE_RELATIONSHIP = "downgrade_relationship"
    PATCH_VULNERABILITY = "patch_vulnerability"
    DISABLE_ROLE = "disable_role"
    SEGMENT_NETWORK = "segment_network"
    ROTATE_SERVICE_IDENTITY = "rotate_service_identity"


@dataclass(frozen=True)
class EvidenceProvenance:
    source_product: str
    source_record_id: str
    import_id: str | None
    collection_time: datetime
    parser_version: str
    confidence: float
    evidence_hash: str | None = None


@dataclass
class GraphNode:
    node_kind: NodeKind
    node_id: str
    label: str
    criticality: str = "medium"
    environment: str = "prod"
    is_external_entry: bool = False
    is_crown_jewel: bool = False
    privilege_level: str = "standard"
    stale_observation: bool = False
    open_cve_count: int = 0
    max_cvss: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.node_kind.value}:{self.node_id}"


@dataclass
class GraphEdge:
    edge_id: str
    source_kind: NodeKind
    source_id: str
    target_kind: NodeKind
    target_id: str
    relation_type: RelationType
    fact_kind: FactKind
    confidence: float
    valid_from: datetime
    valid_to: datetime | None = None
    provenance: dict[str, Any] = field(default_factory=dict)
    edge_metadata: dict[str, Any] = field(default_factory=dict)
    is_suppressed: bool = False

    @property
    def source_key(self) -> str:
        return f"{self.source_kind.value}:{self.source_id}"

    @property
    def target_key(self) -> str:
        return f"{self.target_kind.value}:{self.target_id}"


@dataclass(frozen=True)
class PathSearchConstraints:
    start_node_keys: list[str]
    target_node_keys: list[str]
    algorithm: AlgorithmType = AlgorithmType.DIJKSTRA
    allowed_edge_types: list[RelationType] | None = None
    excluded_node_keys: list[str] = field(default_factory=list)
    excluded_environments: list[str] = field(default_factory=list)
    min_confidence: float = 0.2
    max_hops: int = 6
    max_candidates: int = 200
    top_k: int = 10
    timeout_seconds: float = 5.0
    include_inferred: bool = True
    as_of: datetime | None = None
    # True keeps unknown transitions as explicitly conditional hypotheses.
    # False requires every executable precondition to be known true.
    allow_unknown_preconditions: bool = True


@dataclass
class PathStepData:
    step_order: int
    relationship_id: str
    from_node_kind: str
    from_node_id: str
    from_node_label: str
    to_node_kind: str
    to_node_id: str
    to_node_label: str
    relation_type: str
    fact_kind: str
    confidence: float
    preconditions: list[str]
    assumptions: list[str]
    evidence_refs: list[dict[str, Any]]
    narrative: str
    missing_corroboration: bool = False
    precondition_outcomes: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class AttackPathResult:
    title: str
    start_node_kind: str
    start_node_id: str
    start_node_label: str
    target_node_kind: str
    target_node_id: str
    target_node_label: str
    algorithm: str
    algorithm_params: dict[str, Any]
    scoring_version: str
    priority_score: float
    impact_weight: float
    exposure_factor: float
    privilege_factor: float
    evidence_confidence: float
    missing_data_penalty: float
    hop_count: int
    is_truncated: bool
    assumptions: list[str]
    explanation_narrative: str
    explanation_trace: dict[str, Any]
    determinism_hash: str
    steps: list[PathStepData]
