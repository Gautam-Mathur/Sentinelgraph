"""Phase 2 Connector Specifications (Explicitly disabled in MVP).

Per the SentinelGraph 100-page build contract (Pages 15, 16, 65, 66):
Cloud inventory connectors (AWS Config/Organizations, Azure Resource Graph,
Google Cloud Asset Inventory) and live directory connectors (Microsoft Graph)
are Phase 2 capabilities and MUST NOT be silently enabled in MVP.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Phase2ConnectorSpec:
    source_type: str
    display_name: str
    phase: str
    enabled_in_mvp: bool
    required_auth_model: str
    read_only_scopes: list[str]
    threat_notes: str


PHASE2_CONNECTORS: list[Phase2ConnectorSpec] = [
    Phase2ConnectorSpec(
        source_type="cloud_aws_phase2",
        display_name="AWS Config & Organizations Inventory",
        phase="Phase 2 (Disabled in MVP)",
        enabled_in_mvp=False,
        required_auth_model="Short-lived IAM Role / OIDC Workload Identity",
        read_only_scopes=["config:SelectResourceConfig", "organizations:ListAccounts"],
        threat_notes="Never deploy agents or alter cloud policies; strictly read-only inventory.",
    ),
    Phase2ConnectorSpec(
        source_type="cloud_azure_phase2",
        display_name="Azure Resource Graph Inventory",
        phase="Phase 2 (Disabled in MVP)",
        enabled_in_mvp=False,
        required_auth_model="Scoped Managed Identity / Workload Identity Federation",
        read_only_scopes=["Microsoft.ResourceGraph/resources/read"],
        threat_notes="Scoped per subscription/tenant boundary; no write roles permitted.",
    ),
    Phase2ConnectorSpec(
        source_type="cloud_gcp_phase2",
        display_name="Google Cloud Asset Inventory",
        phase="Phase 2 (Disabled in MVP)",
        enabled_in_mvp=False,
        required_auth_model="Workload Identity Federation (short-lived OAuth)",
        read_only_scopes=["cloudasset.assets.searchAllResources"],
        threat_notes="Project/folder scoped read-only export.",
    ),
    Phase2ConnectorSpec(
        source_type="ms_graph_phase2",
        display_name="Microsoft Graph Read-Only Directory",
        phase="Phase 2 (Disabled in MVP)",
        enabled_in_mvp=False,
        required_auth_model="Tenant-consented OAuth App (Read.All only)",
        read_only_scopes=["User.Read.All", "Group.Read.All", "Directory.Read.All"],
        threat_notes="Treats directory records as sensitive personal data; never validates credentials.",
    ),
]
