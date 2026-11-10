export interface FieldError {
  field: string;
  message: string;
  code: string;
}

export interface ApiErrorEnvelope {
  code: string;
  message: string;
  request_id: string;
  field_errors: FieldError[];
}

export type RoleName =
  | "tenant_admin"
  | "assessor"
  | "analyst"
  | "remediation_owner"
  | "auditor"
  | "read_only";

export type FactKind = "observed_fact" | "inferred_relationship" | "analyst_assertion";

export type RelationType =
  | "HOSTS"
  | "CONNECTS_TO"
  | "RUNS_SERVICE"
  | "EXPOSES"
  | "DEPENDS_ON"
  | "MEMBER_OF"
  | "HAS_ROLE"
  | "CAN_ADMINISTER"
  | "TRUSTS"
  | "OWNS";

export interface UserProfile {
  id: string;
  email: string;
  display_name: string;
  mfa_enabled?: boolean;
}

export interface TenantInfo {
  id: string;
  slug: string;
  name: string;
  is_demo: boolean;
  role: RoleName;
}

export interface MembershipSummary {
  tenant_id: string;
  tenant_slug: string;
  tenant_name: string;
  is_demo: boolean;
  role: RoleName;
}

export interface LoginResponse {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  token_type: string;
  oidc_subject?: string;
  user: UserProfile;
  active_tenant: TenantInfo;
  memberships: MembershipSummary[];
}

export interface OidcConfigResponse {
  oidc_enabled: boolean;
  issuer_url: string | null;
  client_id: string | null;
  redirect_uri: string;
  local_dev_auth_enabled: boolean;
  supported_roles: RoleName[];
}

export interface OidcLoginStartResponse {
  oidc_enabled: boolean;
  authorization_url: string;
  state: string;
}

export interface DashboardOverview {
  kpis: {
    assets_observed: number;
    critical_assets: number;
    exposed_services: number;
    high_confidence_paths: number;
    paths_to_critical_assets: number;
    stale_observations: number;
    unreviewed_imports: number;
  };
  freshness_and_coverage: {
    latest_observation_at: string | null;
    assessments_count: number;
    observed_source_formats: Array<{
      source_format: string;
      last_committed_at: string | null;
    }>;
    missing_recommended_sources: string[];
    coverage_status: string;
    completeness_notice: string;
  };
}

export interface ProvenanceRef {
  import_id?: string | null;
  source_product: string;
  source_record_id?: string | null;
  collection_time: string;
  evidence_hash?: string | null;
  parser_version?: string | null;
  confidence: number;
  fact_kind?: FactKind;
  relationship_id?: string;
}

export interface AssetAddress {
  id: string;
  address_type: string;
  value: string;
  is_primary: boolean;
}

export interface ServiceItem {
  id: string;
  port: number;
  protocol: string;
  state: string;
  service_name: string | null;
  product: string | null;
  version: string | null;
  banner_raw: string | null;
  analyst_corrected_product: string | null;
  analyst_corrected_version: string | null;
  confidence: number;
  provenance: ProvenanceRef;
}

export interface FindingItem {
  id: string;
  cve_id: string | null;
  severity: string;
  cvss_score: number | null;
  affected_component: string | null;
  status: string;
  exploitability_proven: boolean;
}

export interface AssetItem {
  id: string;
  tenant_id: string;
  canonical_key: string;
  display_name: string;
  asset_type: string;
  environment: string;
  criticality: string;
  owner: string;
  business_unit: string;
  lifecycle_state: string;
  first_seen: string;
  last_seen: string;
  confidence: number;
  is_external_entry: boolean;
  is_crown_jewel: boolean;
  raw_attributes: Record<string, unknown>;
  source_refs: ProvenanceRef[];
  addresses: AssetAddress[];
  services: ServiceItem[];
  open_findings: FindingItem[];
}

export interface IdentityItem {
  id: string;
  identity_type: string;
  external_id: string;
  provider: string;
  display_name: string;
  principal_name: string;
  enabled: boolean;
  privilege_level: string;
  privilege_indicators: string[];
  auth_metadata: Record<string, unknown>;
  confidence: number;
  first_seen: string;
  last_seen: string;
  source_refs: ProvenanceRef[];
}

export interface GroupItem {
  id: string;
  external_id: string;
  provider: string;
  display_name: string;
  group_type: string;
  privilege_indicators: string[];
  enabled: boolean;
  confidence: number;
  source_refs: ProvenanceRef[];
}

export interface RelationshipItem {
  id: string;
  assessment_id: string | null;
  source_kind: string;
  source_id: string;
  source_label: string;
  target_kind: string;
  target_id: string;
  target_label: string;
  relation_type: RelationType;
  fact_kind: FactKind;
  confidence: number;
  valid_from: string | null;
  valid_to: string | null;
  provenance: ProvenanceRef;
  edge_metadata: Record<string, unknown>;
  is_suppressed: boolean;
  suppressed_reason: string | null;
  suppressed_at: string | null;
}

export interface BridgeNodeStat {
  label: string;
  node_key: string;
  node_kind: string;
  betweenness_centrality: number;
}

export interface BridgeEdgeStat {
  edge_id: string;
  source_key: string;
  target_key: string;
  source_label: string;
  target_label: string;
  relation_type: string;
  fact_kind: string;
  confidence: number;
  betweenness_centrality: number;
}

export interface AssessmentItem {
  id: string;
  tenant_id: string;
  name: string;
  description: string;
  status: string;
  approved_scope_cidrs: string[];
  time_window_start: string;
  time_window_end: string;
  operator_user_id: string | null;
  approved_by_user_id: string | null;
  approved_at: string | null;
  is_synthetic: boolean;
  graph_version: number;
  graph_built_at: string | null;
  graph_stats: {
    edge_count?: number;
    node_count?: number;
    scc_cycles?: string[][];
    scc_cycle_count?: number;
    top_bridge_nodes?: BridgeNodeStat[];
    top_bridge_edges?: BridgeEdgeStat[];
    build_duration_ms?: number;
    expired_edge_count?: number;
    suppressed_edge_count?: number;
  };
  created_at: string;
}

export interface GraphNode {
  key: string;
  node_kind: string;
  node_id: string;
  label: string;
  criticality: string;
  environment: string;
  is_external_entry: boolean;
  is_crown_jewel: boolean;
  privilege_level: string;
  open_cve_count: number;
  metadata: Record<string, unknown>;
}

export interface GraphEdge {
  edge_id: string;
  source: string;
  target: string;
  relation_type: RelationType;
  fact_kind: FactKind;
  confidence: number;
  provenance: ProvenanceRef;
  edge_metadata: Record<string, unknown>;
}

export interface AssessmentGraphPayload {
  assessment: AssessmentItem;
  nodes: GraphNode[];
  edges: GraphEdge[];
  stats: AssessmentItem["graph_stats"];
}

export interface PathStepItem {
  id: string;
  step_order: number;
  relationship_id: string;
  from_node_kind: string;
  from_node_id: string;
  from_node_label: string;
  to_node_kind: string;
  to_node_id: string;
  to_node_label: string;
  relation_type: RelationType;
  fact_kind: FactKind;
  confidence: number;
  preconditions: string[];
  precondition_outcomes?: Array<{
    condition_id: string;
    kind: string;
    status: "true" | "false" | "unknown";
    field?: string | null;
    observed_value?: unknown;
    expected?: unknown;
    reason: string;
    evidence_ref?: string | null;
  }>;
  assumptions: string[];
  evidence_refs: ProvenanceRef[];
  narrative: string;
}

export interface AttackPathItem {
  id: string;
  assessment_id: string;
  title: string;
  start_node_kind: string;
  start_node_id: string;
  start_node_label: string;
  target_node_kind: string;
  target_node_id: string;
  target_node_label: string;
  algorithm: string;
  algorithm_params: Record<string, unknown>;
  scoring_version: string;
  priority_score: number;
  impact_weight: number;
  exposure_factor: number;
  privilege_factor: number;
  evidence_confidence: number;
  missing_data_penalty: number;
  hop_count: number;
  is_truncated: boolean;
  assumptions: string[];
  explanation_narrative: string;
  explanation_trace: {
    steps?: Array<Record<string, unknown>>;
    scoring?: Record<string, unknown>;
    algorithm?: string;
    assumptions?: string[];
    plausible_only?: boolean;
    business_impact?: Record<string, unknown>;
    remediation_options?: string[];
    [key: string]: unknown;
  };
  determinism_hash: string;
  created_at: string;
  steps?: PathStepItem[];
}

export interface GraphMetricSnapshot {
  /** Number of returned path candidates; not necessarily the total graph path count. */
  total_paths: number;
  path_count_semantics?: string;
  path_search_complete?: boolean;
  path_search_truncation_reason?: string | null;
  high_confidence_paths: number;
  highest_path_score: number;
  reachable_critical_assets: number;
  reachable_critical_asset_labels: string[];
  key_bridge_nodes: BridgeNodeStat[];
  reachability_status?: string;
  reachable_within_max_hops?: boolean;
  reachable_unbounded?: boolean;
  confirmed_reachable_unbounded?: boolean;
  reachability_verification_complete?: boolean;
  reachable_target_keys?: string[];
  witness_path_edge_ids?: string[];
  conditional_witness_edge_ids?: string[];
  reachability_examined_nodes?: number;
  reachability_examined_edges?: number;
}

export interface RemediationItem {
  id: string;
  assessment_id: string;
  name: string;
  description: string;
  status: string;
  transforms: Array<Record<string, unknown>>;
  baseline_metrics: GraphMetricSnapshot;
  modelled_metrics: GraphMetricSnapshot;
  delta_summary: {
    paths_eliminated: number;
    highest_score_reduction: number;
    critical_assets_unlinked: number;
    high_confidence_paths_reduced: number;
    disclaimer: string;
    sampled_paths_eliminated?: number;
    paths_eliminated_is_complete?: boolean;
    possible_reachability_eliminated?: boolean;
    possible_residual_reachability?: boolean;
    confirmed_residual_reachability?: boolean;
    reachability_verification_complete?: boolean;
  };
  is_modelled_only: boolean;
  validation_assessment_id: string | null;
  validation_result: Record<string, unknown> | null;
  created_at: string;
}

export interface ImportItem {
  id: string;
  tenant_id: string;
  assessment_id: string;
  filename: string;
  source_format: string;
  parser_version: string;
  file_sha256: string;
  file_size_bytes: number;
  mime_type: string;
  status: string;
  idempotency_key: string | null;
  raw_metadata: Record<string, unknown>;
  preview_summary: {
    warnings?: string[];
    scope_valid?: boolean;
    hosts_count?: number;
    services_count?: number;
    relationships_count?: number;
    identities_count?: number;
    groups_count?: number;
    findings_count?: number;
    [key: string]: unknown;
  };
  error_detail: string | Record<string, unknown> | null;
  created_at: string;
  committed_at: string | null;
}

export interface IntegrationsResponse {
  configured_sources: Array<{
    id: string;
    name: string;
    source_type: string;
    mode: string;
    enabled: boolean;
    has_secret_configured: boolean;
    config_metadata: Record<string, unknown>;
    last_sync_at: string | null;
  }>;
  phase2_roadmap_connectors: Array<{
    source_type: string;
    display_name: string;
    phase: string;
    enabled_in_mvp: boolean;
    required_auth_model: string;
    read_only_scopes: string[];
    threat_notes: string;
  }>;
}

export interface ReportItem {
  id: string;
  assessment_id: string;
  title: string;
  report_format: string;
  is_synthetic_watermarked: boolean;
  scoring_version: string;
  created_at: string;
  html_content?: string;
}

export interface AuditEventItem {
  id: string;
  actor_email: string | null;
  action: string;
  object_type: string;
  object_id: string;
  outcome: string;
  request_id: string;
  details: Record<string, unknown>;
  prev_hash: string | null;
  event_hash: string;
  created_at: string;
}

export interface MemberItem {
  membership_id: string;
  user_id: string;
  email: string;
  display_name: string;
  auth_provider?: string;
  role: RoleName;
  status: string;
  mfa_enabled: boolean;
}

export interface FindingRecord {
  id: string;
  tenant_id: string;
  assessment_id: string;
  asset_id: string;
  asset_display_name: string;
  asset_canonical_key: string | null;
  cve_id: string | null;
  cvss_version: string | null;
  cvss_vector: string | null;
  cvss_score: number | null;
  severity: string;
  affected_component: string | null;
  status: "open" | "mitigated" | "accepted_risk" | "false_positive" | string;
  scanner_name: string;
  scanner_context: string | null;
  evidence: Record<string, unknown>;
  exploitability_proven: boolean;
  observed_at: string;
  confidence: number;
  provenance: ProvenanceRef;
  triage_note: string | null;
  triaged_by_user_id: string | null;
  triaged_at: string | null;
}

export type BackgroundJobType =
  | "build_graph"
  | "generate_paths"
  | "generate_report"
  | "enforce_retention";

export interface JobItem {
  id: string;
  tenant_id: string;
  job_type: BackgroundJobType | string;
  status: "queued" | "running" | "succeeded" | "failed" | "dead_letter" | "cancelled" | string;
  progress: number;
  attempts: number;
  max_attempts: number;
  payload: Record<string, unknown>;
  result: Record<string, unknown> | null;
  error_message: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
}

export interface WebhookItem {
  id: string;
  tenant_id: string;
  name: string;
  target_url: string;
  event_types: string[];
  enabled: boolean;
  min_priority_score: number;
  has_signing_secret: boolean;
  last_delivery_at: string | null;
  last_status_code: number | null;
  last_error: string | null;
  created_at: string;
}

export interface RetentionResponse {
  policies: Array<{
    id: string;
    data_class: string;
    retention_days: number;
    lawful_basis: string;
  }>;
  requests: Array<{
    id: string;
    request_type: string;
    data_class: string | null;
    status: string;
    summary: Record<string, unknown>;
    created_at: string;
  }>;
}

export interface SearchResultsResponse {
  query: string;
  assets: Array<{ id: string; display_name: string; canonical_key: string; criticality: string }>;
  identities: Array<{ id: string; display_name: string; principal_name: string; privilege_level: string }>;
  paths: Array<{ id: string; title: string; priority_score: number; assessment_id: string }>;
}

export interface EdgeBlastRadius {
  edge_id: string;
  source_key: string;
  source_label: string;
  target_key: string;
  target_label: string;
  relation_type: RelationType | string;
  fact_kind: FactKind | string;
  confidence: number;
  betweenness_centrality: number;
  paths_traversed_count: number;
  total_paths: number;
  path_coverage_pct: number;
  critical_targets_affected: string[];
  cumulative_risk_score: number;
  max_path_score: number;
  residual_paths_if_cut: number;
  residual_paths_semantics?: string;
  residual_reachability?: string;
  residual_reachable?: boolean;
  reachability_verification_complete?: boolean;
  residual_witness_edge_ids?: string[];
  is_single_point_chokepoint: boolean;
  action_label: string;
  recommended_transform: Record<string, unknown>;
}

export interface CutSetRecommendation {
  id: string;
  label: string;
  cut_size: number;
  effort_score: number;
  baseline_paths: number;
  paths_broken: number;
  /** Enumerated candidate count only. Use reachability fields for disconnection claims. */
  residual_paths: number;
  residual_paths_semantics?: string;
  reachability_status?: string;
  reachable_unbounded?: boolean;
  reachable_within_max_hops?: boolean;
  confirmed_reachable_unbounded?: boolean;
  reachability_verification_complete?: boolean;
  witness_path_edge_ids?: string[];
  conditional_witness_edge_ids?: string[];
  path_search_complete?: boolean;
  path_search_truncation_reason?: string | null;
  verification_status?: "MODEL_VERIFIED_CUT" | "PARTIAL_CUT" | "INDETERMINATE" | string;
  minimum_cut_proven?: boolean;
  coverage_pct: number;
  critical_assets_unlinked: number;
  highest_score_reduction: number;
  edge_ids: string[];
  steps_summary: string[];
  transforms: Array<Record<string, unknown>>;
  rationale: string;
  scope?: "full_cut_set" | "single_step";
  same_pair_bypasses_remaining?: number;
  eliminates_all_bypasses?: boolean;
}

export interface SensitivityScenario {
  scenario_id: string;
  label: string;
  assumption_tested: string;
  baseline_paths: number;
  remaining_paths: number;
  paths_eliminated: number;
  highest_score_remaining: number;
  score_reduction: number;
  critical_targets_remaining: string[];
  verdict: string;
}

export interface PathOverlayEntry {
  path_id: string | null;
  determinism_hash: string;
  title: string;
  priority_score: number;
  hop_count: number;
  evidence_confidence: number;
  start_node_key: string;
  target_node_key: string;
  start_node_label: string;
  target_node_label: string;
  node_keys: string[];
  edge_ids: string[];
  has_inferred: boolean;
  capability_stages: string[];
}

export interface AssumptionEntry {
  assumption_id: string;
  category: string;
  fragility: "critical" | "high" | "moderate" | "low" | string;
  step_order?: number | null;
  relationship_id: string | null;
  node_key?: string;
  statement: string;
  if_falsified?: string;
  verification_action: string;
  affected_paths_count?: number;
  can_challenge_edge: boolean;
}

export interface CapabilityTransition {
  step_order: number;
  relationship_id: string;
  source_key: string;
  source_label: string;
  target_key: string;
  target_label: string;
  relation_type: RelationType | string;
  fact_kind: FactKind | string;
  confidence: number;
  stage_name: string;
  mechanism: string;
  preconditions_met?: string[];
  same_pair_path_search_complete?: boolean;
  same_pair_reachable_if_removed?: boolean;
  same_pair_reachability_verification_complete?: boolean;
  evidence_provenance?: Record<string, unknown>;
  paths_in_assessment_count: number;
  same_pair_bypasses_if_removed: number;
  is_pair_bridge_chokepoint: boolean;
  is_assessment_chokepoint: boolean;
  edge_betweenness: number;
}

export interface PerStepSensitivityItem {
  step_order: number;
  relationship_id: string;
  transition: string;
  this_path_eliminated: boolean;
  /** Candidate count only, not necessarily the total number of simple paths. */
  same_pair_bypasses_remaining: number;
  same_pair_path_search_complete?: boolean;
  same_pair_reachability_status?: string;
  same_pair_reachable?: boolean;
  same_pair_reachability_verification_complete?: boolean;
  bypass_routes_preview: string[];
  assessment_paths_broken: number;
  assessment_paths_remaining: number;
  assessment_reachable_remaining?: boolean;
  assessment_reachability_verification_complete?: boolean;
  is_pair_bridge_chokepoint: boolean;
  is_assessment_chokepoint: boolean;
}

export interface AssessmentIntelligenceResponse {
  assessment_id: string;
  assessment_name: string;
  graph_version: number;
  graph_stats: AssessmentItem["graph_stats"];
  summary: {
    /** Legacy count of returned candidates, not necessarily all graph paths. */
    total_active_paths: number;
    path_count_semantics?: string;
    path_search_complete?: boolean;
    path_search_truncation_reason?: string | null;
    baseline_possible_reachability?: boolean;
    baseline_reachable_within_max_hops?: boolean;
    baseline_confirmed_reachability?: boolean;
    reachability_verification_complete?: boolean;
    reachable_target_keys?: string[];
    reachable_crown_jewels: string[];
    single_point_chokepoints_count: number;
    /** Deprecated: always null until a globally optimal cut is actually proven. */
    min_cut_size: number | null;
    candidate_cut_size?: number | null;
    minimum_cut_proven?: boolean;
    inferred_dependent_paths: number;
    observed_only_paths: number;
    uncorroborated_acl_edges: number;
    stale_nodes_count: number;
  };
  paths_overlay: PathOverlayEntry[];
  edge_blast_radius: Record<string, EdgeBlastRadius>;
  cut_sets: CutSetRecommendation[];
  sensitivity_analysis: SensitivityScenario[];
  assumptions_summary: AssumptionEntry[];
}

export interface PathIntelligenceResponse {
  assessment_id: string;
  path_id: string;
  path_title: string;
  stale_path_notice: string | null;
  why_exists: {
    summary: string;
    capability_chain: CapabilityTransition[];
    structural_context: {
      total_assessment_paths: number;
      /** Candidate route count returned by bounded path enumeration. */
      same_pair_total_paths: number;
      same_pair_path_count_semantics?: string;
      same_pair_path_search_complete?: boolean;
      same_pair_reachable?: boolean;
      same_pair_reachability_verification_complete?: boolean;
      parallel_bypass_paths_count: number;
      chokepoint_step_orders: number[];
      scc_cycle_count: number;
    };
  };
  assumptions_register: AssumptionEntry[];
  per_step_sensitivity: PerStepSensitivityItem[];
  assessment_sensitivity: SensitivityScenario[];
  recommended_remediations: CutSetRecommendation[];
  edge_blast_radius: Record<string, EdgeBlastRadius>;
  subgraph: {
    nodes: GraphNode[];
    edges: GraphEdge[];
    highlighted_node_keys: string[];
    highlighted_edge_ids: string[];
  };
}
