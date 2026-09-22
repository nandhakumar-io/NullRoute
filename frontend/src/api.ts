import axios from "axios";

export interface ConfigSearchDeviceMatch {
  device_id: string;
  hostname: string | null;
  vendor: string | null;
  scan_id: string | null;
  final_decision: string | null;
  compliant: boolean | null;
  match_source: "finding" | "raw_config" | "finding+raw_config";
  match_count: number;
  matched_controls: string[];
  context_lines: string[];
}

export interface ConfigSearchResult {
  query: string;
  total_devices_searched: number;
  total_matches: number;
  compliant_count: number;
  non_compliant_count: number;
  unscanned_count: number;
  raw_config_search_truncated: boolean;
  devices: ConfigSearchDeviceMatch[];
}

// --- Unified Control Library ---
export interface FrameworkMapping {
  id: string;
  framework: string;
  external_id: string;
  confidence: number | null;
}

export interface ConfigConcept {
  id: string;
  concept_name: string;
  description: string | null;
}

export interface VendorConfigPattern {
  id: string;
  concept_id: string;
  vendor: string;
  pattern: string;
  example_snippet: string | null;
  created_by: string | null;
}

export interface UnifiedControl {
  id: string;
  name: string;
  objective: string | null;
  domain: string | null;
  source_text: string | null;
  normalized_description: string | null;
  status: "pending_review" | "approved";
  source_document: string | null;
  created_by: string | null;
  approved_by: string | null;
  approved_at: string | null;
  created_at: string | null;
  updated_at: string | null;
  framework_mappings?: FrameworkMapping[];
  config_concepts?: ConfigConcept[];
}

export interface ControlReview {
  id: string;
  control_id: string;
  reviewer: string;
  original_text: string | null;
  proposed_change: string | null;
  decision: "approved" | "rejected" | "corrected";
  correction_json: Record<string, unknown> | null;
  created_at: string | null;
}

export interface DocumentIngestionJob {
  id: string;
  filename: string;
  status: "queued" | "parsing" | "extracting" | "completed" | "failed";
  llm_used: boolean;
  controls_created: number;
  sections_found: number;
  warning: string | null;
  error: string | null;
  created_by: string | null;
  created_at: string | null;
  started_at: string | null;
  completed_at: string | null;
}

// --- Vulnerability Management ---
export interface Vulnerability {
  cve_id: string;
  cvss_score: number | null;
  severity: string | null;
  description: string | null;
  kev_flag: boolean;
  published_date: string | null;
  last_modified_date: string | null;
  source: string;
  remediation_advice: string | null;
}

export interface DeviceVulnerabilityMatch {
  id: string;
  device_id: string;
  cve_id: string;
  matched_via: string;
  risk_priority_score: number | null;
  status: "open" | "mitigated" | "accepted_risk" | "false_positive";
  evidence: Record<string, unknown> | null;
  justification: string | null;
  reviewed_by: string | null;
  reviewed_at: string | null;
  linked_control_id: string | null;
  created_at: string | null;
  vulnerability: Vulnerability | null;
}

// --- Report Verification (blockchain-backed tamper check) ---
export interface ReportArtifact {
  id: string;
  scan_id: string;
  format: "pdf" | "json" | "csv";
  sha256: string;
  size_bytes: number;
  created_at: string | null;
  has_stored_copy: boolean;
}

export interface ReportVerifyResult {
  status: "VERIFIED" | "TAMPERED" | "UNKNOWN_REPORT";
  match: boolean;
  calculated_hash: string;
  scan_id: string | null;
  format: string | null;
  artifact: ReportArtifact | null;
  fabric_checked: boolean;
  fabric_match: boolean | null;
  fabric_status: string | null;
  downloadable: boolean;
  message: string;
}

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || "",
});

export const setTargetTenant = (tenant: string) => {
  // Optional: Add tenant header if backend requires it. Or just export a no-op to fix the build.
  api.defaults.headers.common["X-Tenant-ID"] = tenant;
};

export interface Device {
  id: string;
  name?: string | null;
  hostname: string | null;
  vendor: string | null;
  model: string | null;
  os: string | null;
  version: string | null;
  serial_number: string | null;
  management_address?: string | null;
  site?: string | null;
  environment?: string | null;
  protocol?: string | null;
  description?: string | null;
  tags?: string[] | null;
  enabled: boolean;
  collection_status?: string | null;
  last_collected_at?: string | null;
  last_collection_error?: string | null;
  last_collection_transport?: string | null;
  last_scan_at: string | null;
  last_compliance_score: number | null;
  created_at?: string | null;
  updated_at?: string | null;
}

export interface DeviceListResponse {
  items: Device[];
  total: number;
  limit: number;
  offset: number;
}

export interface DeviceListParams {
  limit?: number;
  offset?: number;
  search?: string;
  vendor?: string;
  site?: string;
  environment?: string;
  protocol?: string;
  enabled?: boolean;
  collection_status?: string;
  sort_by?: string;
  sort_dir?: "asc" | "desc";
}

export interface DeviceCreatePayload {
  name?: string | null;
  hostname?: string | null;
  vendor?: string | null;
  model?: string | null;
  os?: string | null;
  version?: string | null;
  serial_number?: string | null;
  management_address?: string | null;
  site?: string | null;
  environment?: string | null;
  protocol?: string | null;
  description?: string | null;
  tags?: string[] | null;
  enabled?: boolean;
}

export type DeviceUpdatePayload = Partial<DeviceCreatePayload>;

export interface CollectionStatusResult {
  success: boolean;
  transport: string;
  duration_ms: number;
  config_hash: string | null;
  error: string | null;
}

export interface BulkDeviceResult {
  requested: number;
  affected: number;
  device_ids: string[];
}

export interface CredentialRef {
  credential_type: string;
  credential_ref: string;
  updated_at: string | null;
  rotated_at: string | null;
}

export interface Finding {
  id: string;
  scan_id?: string;
  framework: string;
  control_id: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  expected_value: string | null;
  actual_value: string | null;
  result: "PASS" | "FAIL" | "NOT_APPLICABLE" | "UNVERIFIED";
  parameter: string;
  reason?: string | null;
  policy_version?: string | null;
  vendor?: string | null;
  evidence_line: string | null;
  remediation: string | null;
  presentation_result?: string | null;
  // Trust-boundary provenance (see models.Finding): 'parser' | 'ai' | null,
  // with a 0-1 confidence when an AI/RAG interpretation produced this
  // finding's normalized parameter.
  source?: "parser" | "ai" | null;
  confidence?: number | null;
  created_at?: string | null;
}

export interface Scan {
  id: string;
  device_id: string;
  status: string;
  framework: string;
  compliance_score: number | null;
  error: string | null;
  created_at: string;
  updated_at: string;
  opa_decision?: string | null;
  opa_policy_version?: string | null;
  opa_decision_id?: string | null;
  batfish_status?: string | null;
  risk_score?: number | null;
  risk_level?: string | null;
  final_decision?: string | null;
  final_reason?: string | null;
  evidence_id?: string | null;
  source_filename?: string | null;
  control_state?: string | null;
  pipeline_stage?: string | null;
  stage_timings?: Record<string, any>;
  paused_at?: string | null;
  resumed_at?: string | null;
  stopped_at?: string | null;
}

export interface PipelineStatus {
  scan_id: string;
  status: string;
  control_state: string;
  pipeline_stage: string | null;
  pipeline_stage_label: string | null;
  paused_at: string | null;
  resumed_at: string | null;
  stopped_at: string | null;
  can_pause: boolean;
  can_stop: boolean;
  can_resume: boolean;
}

export interface ScanDetail extends Scan {
  baseline_json: Record<string, any> | null;
  findings: Finding[];
}

export interface RagSource {
  document_id: string;
  source_type: string;
  source_id?: string | null;
  title: string;
  content: string;
  metadata?: Record<string, unknown> | null;
  score: number;
}

export interface RagQueryResponse {
  query_id: string;
  answer: string;
  sources: RagSource[];
}

export interface DashboardStats {
  total_devices: number;
  devices_scanned: number;
  overall_compliance_score: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  framework_scores: Record<string, number>;
  recent_scans: Scan[];
  pending_ai_mappings: number;
  // Section 32: OPA/Batfish/risk/evidence/Fabric metrics.
  opa_violations: number;
  batfish_violations: number;
  unknown_configurations: number;
  high_risk_devices: number;
  evidence_anchors: number;
  fabric_failures: number;
  integrity_failures: number;
  opa_vs_batfish: Record<string, number>;
  risk_distribution: Record<string, number>;
  evidence_anchoring_status: Record<string, number>;
  // Part 2 §A/§F additions: REVIEW/UNVERIFIED counts (previously
  // uncountable because the states didn't exist) and a per-vendor score
  // breakdown for the multi-vendor proof (§9).
  review_scans: number;
  unverified_findings: number;
  vendor_scores: Record<string, number>;
  // Phase 1 security-audit dashboard (SIH26155).
  total_findings: number;
  configuration_drift_count: number;
  // Unified-dashboard KPIs -- the backend computed these already, they were
  // just silently dropped by an incomplete Pydantic schema (see schemas.py).
  devices_out_of_baseline: number;
  mttr_hours: number | null;
  mttr_improvement_pct: number | null;
}

export interface AuditLogEntry {
  id: string;
  tenant_id: string | null;
  username: string | null;
  user_id: string | null;
  action: string | null;
  object_type: string | null;
  object_id: string | null;
  source_ip: string | null;
  old_value: Record<string, any> | null;
  new_value: Record<string, any> | null;
  result: string | null;
  created_at: string;
}

export type DashboardRange = "24h" | "7d" | "30d" | "90d";

export interface DashboardMetricPoint {
  bucket: string;
  compliance_score: number | null;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  open_findings: number;
  resolved_findings: number;
}

export interface DashboardMetrics {
  range: DashboardRange;
  compliance_score: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  open_findings: number;
  resolved_findings: number;
  timeseries: DashboardMetricPoint[];
}

export interface CommandMapping {
  id: string;
  vendor: string;
  raw_command_pattern: string;
  normalized_parameter: string;
  example_value: string | null;
  ai_suggested_meaning: string | null;
  confidence: number;
  status: string;
}

// --- Unified Review Queue (Section 10) ---
// Advisory-only surfacing of every AIAnalysis row across every scan that the
// hybrid decision engine flagged `requires_review`. Never a compliance
// PASS/FAIL -- that authority stays with OPA/Batfish. The frontend unifies
// this with pending CommandMapping rows (Training Center) into one queue so
// a reviewer has a single place to triage everything awaiting human sign-off.
export interface ReviewQueueItem {
  id: string;
  scan_id: string;
  device_id: string | null;
  device_hostname: string | null;
  vendor: string | null;
  intent: string;
  classifier_confidence: number;
  semantic_similarity: number;
  nearest_intent: string | null;
  nearest_vendor: string | null;
  models_agree: boolean;
  decision: "KNOWN_CANDIDATE" | "UNKNOWN" | "REQUIRES_REVIEW";
  reason: string | null;
  model_version: string | null;
  inference_latency_ms: number | null;
  created_at: string;
}

export interface ReviewQueueResponse {
  count: number;
  items: ReviewQueueItem[];
}

export interface BatfishReachabilityCheck {
  type: string;
  control_id: string;
  title: string;
  severity: string;
  result: "PASS" | "FAIL" | "REVIEW";
  batfish_status: string;
  source_zone: string;
  destination_zone: string;
  protocol: string;
  reachable: boolean | null;
  expected_reachable: boolean;
  detail: string;
}

export interface BatfishAnalysis {
  scan_id: string;
  status: string; // BATFISH_PASS | BATFISH_FAIL | BATFISH_UNSUPPORTED | BATFISH_UNAVAILABLE | BATFISH_ERROR | NOT_INTEGRATED
  network_name: string | null;
  snapshot_name: string | null;
  critical_violation: boolean;
  init_issues: Array<{ status: string; device: string | null; line?: string; detail: string }>;
  nodes?: string[];
  interfaces?: Record<string, any>[];
  routes?: Record<string, any>[];
  reachability_checks?: BatfishReachabilityCheck[];
  created_at?: string;
}

export interface OpaAnalysis {
  scan_id: string;
  policy_version: string;
  decision: string;
  decision_id: string;
  source: string;
  findings?: Record<string, any>[];
  violations?: Record<string, any>[];
  evaluated_controls?: string[];
}

export interface EvidenceRecord {
  evidence_id: string;
  scan_id: string;
  device_id: string | null;
  tenant_id: string | null;
  event_type: string | null;
  evidence_hash: string;
  final_decision: string | null;
  opa_decision_id: string | null;
  fabric_status: string | null;
  fabric_tx_id: string | null;
  fabric_block_number: number | null;
  created_at: string | null;
}

export interface EvidenceDetail extends EvidenceRecord {
  evidence_json: Record<string, any>;
}

export interface VerifyResult {
  match: boolean;
  stored_hash: string;
  calculated_hash: string;
  status: "INTEGRITY_VERIFIED" | "INTEGRITY_FAILURE";
  fabric_checked?: boolean;
  fabric_match?: boolean | null;
  fabric_status?: string | null;
}

export interface AIAnalysisRow {
  id: string;
  raw_command_hash: string;
  intent: string;
  classifier_confidence: number;
  semantic_similarity: number;
  nearest_intent: string | null;
  nearest_vendor: string | null;
  models_agree: boolean;
  decision: "KNOWN_CANDIDATE" | "UNKNOWN" | "REQUIRES_REVIEW";
  requires_review: boolean;
  reason: string | null;
  model_version: string | null;
  inference_latency_ms: number | null;
  created_at: string;
}

export interface ScanAIAnalysis {
  scan_id: string;
  count: number;
  requires_review_count: number;
  analyses: AIAnalysisRow[];
}

export interface AIHealth {
  ai_enabled: boolean;
  classifier_loaded: boolean;
  embedder_loaded: boolean;
  classifier_backend: string;
  embedder_backend: string;
  model_version: string;
  reference_dataset: string | null;
  reference_examples: number;
}

export interface ConfidenceTrendPoint {
  date: string;
  analysis_count: number;
  avg_classifier_confidence: number;
  avg_semantic_similarity: number;
  requires_review_rate: number;
  below_threshold_rate: number;
}

export interface ModelHistoryPoint {
  model_id: string;
  model_version: string | null;
  status: string;
  accuracy: number | null;
  dataset_version: string;
  training_timestamp: string | null;
}

export interface ConfidenceTrendOut {
  current_model_version: string;
  confidence_threshold: number;
  drift_detected: boolean;
  drift_alert_delta: number;
  points: ConfidenceTrendPoint[];
  model_history: ModelHistoryPoint[];
}

export interface ServiceHealthEntry {
  name: string;
  category: "core" | "optional";
  status: "HEALTHY" | "DEGRADED" | "UNAVAILABLE" | "DISABLED" | "ERROR";
  latency_ms: number | null;
  detail: string | null;
  error: string | null;
  [key: string]: unknown;
}

export interface SystemHealth {
  overall_status: "HEALTHY" | "DEGRADED" | "UNAVAILABLE";
  core_services: ServiceHealthEntry[];
  optional_integrations: ServiceHealthEntry[];
  checked_at: number;
}

export interface ComplianceSummary {
  framework_compliance: Record<string, number>;
  severity_heatmap: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number };
  top_noncompliant_devices: {
    device_id: string;
    hostname: string;
    vendor: string | null;
    compliance_score: number;
  }[];
  ai_health: {
    ollama_reachable: boolean;
    ollama_host: string;
    production_model: string | null;
    production_model_macro_f1: number | null;
    pending_hitl_reviews: number;
  };
}

export interface AIModelInfo {
  component: string;
  path: string | null;
  backend: string;
  loaded: boolean;
  version: string;
}

export interface AIModelsInfo {
  models: AIModelInfo[];
  thresholds: Record<string, unknown>;
}

export interface NetworkInterface {
  id: string;
  name: string;
  description: string | null;
  ip_address: string | null;
  subnet_mask: string | null;
  vlan: string | null;
  vrf: string | null;
  admin_state: string | null;
  switchport_mode?: string | null;
  allowed_vlans?: string | null;
  source?: string | null;
}

export interface VlanMapEntry {
  vlan_id: string;
  name: string | null;
  devices: {
    device_id: string;
    hostname: string | null;
    interfaces: string[];
    layer3: { interface: string; ip_address: string; subnet_mask: string | null }[];
    source: string | null;
  }[];
}

export interface TopologyRefreshResult {
  engine: "batfish" | "batfish+regex" | "regex" | "none" | "error";
  detail?: string;
  devices_updated: number;
  links: number;
  unmapped_nodes?: string[];
  fallback_devices?: string[];
  skipped_devices?: string[];
}

export interface NetworkRoute {
  id: string;
  destination: string;
  mask: string | null;
  next_hop: string | null;
  vrf: string | null;
}

export interface TopologyNode {
  id: string;
  hostname: string | null;
  vendor: string | null;
  model: string | null;
  management_address: string | null;
  last_compliance_score: number | null;
  interface_count: number;
  vlan_count: number;
  vrf_count: number;
}

export interface TopologyLink {
  subnet?: string | null;
  source_device_id: string;
  source_interface: string | null;
  target_device_id: string;
  target_interface: string | null;
  link_type: string;
}

export interface Topology {
  nodes: TopologyNode[];
  links: TopologyLink[];
  has_interface_data?: boolean;
  observed_link_count?: number;
  inferred_link_count?: number;
  batfish_link_count?: number;
}

export interface SimulateDriftResult {
  deployment: DeploymentRecord;
  simulated: true;
  alert_dispatched: boolean;
  next_step: { description: string; rollback_url: string };
}

export interface SimulatableCategory {
  category: string;
  severity: string;
  title: string;
}

/** One row in any of the three blast-radius sections. */
export interface BlastRadiusItem {
  label: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | string;
  why?: string | null;
  source?: string;
  /** vulnerability_exposure only */
  change?: "added" | "removed";
  config_line?: string;
  /** compliance_violations only */
  control_id?: string | null;
  /** reachability_severance only */
  before?: string;
  after?: string;
}

/**
 * `status` is the load-bearing field: "NOT_ANALYZED" means the underlying
 * analysis never ran, which is NOT the same as "analyzed, nothing found".
 * The UI must render those two cases differently.
 */
export interface BlastRadiusSection {
  status: "ANALYZED" | "NOT_ANALYZED";
  reason?: string | null;
  items: BlastRadiusItem[];
  isolated_nodes?: string[];
  changed_flow_count?: number;
  added_line_count?: number;
  removed_line_count?: number;
  opa_decision?: string | null;
  batfish_status?: string | null;
  route_delta?: Record<string, number>;
}

export type BlastRadiusNodeState = "isolated" | "violating" | "exposed" | "ok" | "unknown";

export interface BlastRadiusNode {
  device_id: string | null;
  hostname: string | null;
  state: BlastRadiusNodeState;
  reasons: string[];
  is_change_target: boolean;
}

export interface BlastRadius {
  change_request_id: string;
  device_id: string;
  hostname: string | null;
  cr_status: string;
  final_decision: string | null;
  final_reason: string | null;
  risk_score: number | null;
  risk_level: string | null;
  vulnerability_exposure: BlastRadiusSection;
  compliance_violations: BlastRadiusSection;
  reachability_severance: BlastRadiusSection;
  node_states: BlastRadiusNode[];
  summary: {
    total_items: number;
    severity_counts: Record<string, number>;
    analyzed_sections: string[];
    fully_unanalyzed: boolean;
  };
}

export interface TopologyGroup {
  id: string;
  name: string;
  description: string | null;
  datacenter_id: string | null;
  rack_id: string | null;
  device_ids: string[];
  last_batfish_status: string | null;
  last_batfish_run_at: string | null;
  created_at: string;
}

export interface BuildTopologyFileResult {
  filename: string;
  device_id: string;
  hostname: string | null;
  vendor: string | null;
  vendor_review_required: boolean;
  family: string | null;
  interfaces: number;
  vlans: number;
  vrfs: number;
  routes: number;
  llm_fallback: { interfaces: number; vlans: number; vrfs: number; routes: number };
  unexplained_lines: number;
  total_lines: number;
  error: string | null;
}

export interface BuildTopologyResult {
  devices: BuildTopologyFileResult[];
  group_id: string | null;
  group_name: string | null;
}

export interface BatfishFlowDiff {
  control_id: string;
  title: string;
  source_zone: string;
  destination_zone: string;
  severity: string;
  before: "REACHABLE" | "BLOCKED" | "UNKNOWN";
  after: "REACHABLE" | "BLOCKED" | "UNKNOWN";
  changed: boolean;
  result: "CRITICAL NETWORK IMPACT" | "NETWORK IMPACT" | "NO IMPACT";
}

export interface SnapshotDiff {
  status: string;
  network_name?: string | null;
  current_snapshot?: string | null;
  proposed_snapshot?: string | null;
  node_delta?: { added: string[]; removed: string[] };
  route_delta?: { current_count: number; proposed_count: number; count_delta: number };
  differential_reachability?: { status: string; changed_flow_count?: number; sample?: string[]; method?: string; detail?: string };
  flow_diffs?: BatfishFlowDiff[];
  included_device_ids?: string[];
  device_had_prior_config?: boolean;
  detail?: string;
}

export interface DriftEvent {
  id: string;
  device_id: string;
  scan_id: string | null;
  previous_hash: string | null;
  current_hash: string;
  added_lines: number;
  removed_lines: number;
  changed_sections: string[] | null;
  security_impacting: boolean;
  affected_controls: string[] | null;
  created_at: string;
}

export interface ConfigSnapshot {
  snapshot_id: string;
  scan_id: string;
  tenant_id: string;
  device_id: string;
  vendor: string | null;
  platform: string | null;
  collected_at: string | null;
  source: string;
  configuration_hash: string | null;
  raw_config_reference: string | null;
  parser_version: string;
  normalization_version: string;
  compliance_score: number | null;
  final_decision: string | null;
  is_approved_baseline?: boolean;
}

export interface ConfigSnapshotDetail extends ConfigSnapshot {
  baseline: Record<string, unknown> | null;
  approval?: { approved_by: string; approved_at: string | null; approval_reason: string | null };
}

// --- Enterprise config backup / NCO management ---------------------------

export type BackupDestinationType = "s3" | "azure_blob" | "sftp" | "local";

export interface BackupDestination {
  id: string;
  name: string;
  destination_type: BackupDestinationType;
  enabled: boolean;
  config: Record<string, any>;
  has_credentials: boolean;
  auto_export_enabled: boolean;
  auto_export_scope: { all?: boolean; device_ids?: string[] } | null;
  retention_days: number | null;
  last_test_status: "SUCCESS" | "FAILED" | "NEVER_TESTED" | null;
  last_test_at: string | null;
  last_test_message: string | null;
  last_export_status: "SUCCESS" | "FAILED" | null;
  last_export_at: string | null;
  created_by: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface BackupDestinationCreate {
  name: string;
  destination_type: BackupDestinationType;
  enabled?: boolean;
  config: Record<string, any>;
  secret?: Record<string, any>;
  auto_export_enabled?: boolean;
  auto_export_scope?: { all?: boolean; device_ids?: string[] };
  retention_days?: number | null;
}

export interface BackupJob {
  id: string;
  destination_id: string;
  destination_name: string | null;
  device_id: string;
  device_hostname: string | null;
  scan_id: string;
  trigger: "manual" | "auto_on_backup" | "scheduled";
  status: "PENDING" | "RUNNING" | "SUCCESS" | "FAILED";
  remote_path: string | null;
  bytes_written: number | null;
  sha256: string | null;
  error: string | null;
  duration_ms: number | null;
  triggered_by: string | null;
  created_at: string | null;
  completed_at: string | null;
}

export interface BackupFleetSummary {
  total_devices: number;
  devices_with_snapshot: number;
  devices_without_snapshot: number;
  devices_with_golden_config: number;
  destination_count: number;
  destinations_healthy: number;
  destinations_failing: number;
  recent_jobs_evaluated: number;
  recent_jobs_success: number;
  recent_jobs_failed: number;
}

export interface SecurityDriftFinding {
  drift_id: string;
  tenant_id: string;
  device_id: string;
  previous_scan_id: string | null;
  current_scan_id: string;
  baseline_parameter: string;
  previous_value: unknown;
  current_value: unknown;
  drift_type: "NO_CHANGE" | "CONFIGURATION_CHANGE" | "SECURITY_IMPROVEMENT" | "SECURITY_DEGRADATION" | "COMPLIANCE_IMPACT" | "UNKNOWN_IMPACT";
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | null;
  compliance_controls: string[];
  evidence_reference: string | null;
  detected_at: string | null;
  status: "OPEN" | "ACKNOWLEDGED" | "REVIEWED" | "RESOLVED" | "ACCEPTED_RISK" | "FALSE_POSITIVE";
}

export interface CompliancePosturePoint {
  scan_id: string;
  scanned_at: string | null;
  compliance_score: number | null;
  final_decision: string | null;
  counts: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number };
}

export interface CompliancePostureHistory {
  device_id: string;
  count: number;
  history: CompliancePosturePoint[];
  summary: string | null;
  correlated_drift: SecurityDriftFinding[];
}

export interface AuditSchedule {
  id: string;
  tenant_id: string;
  name: string;
  scope: { all?: boolean; device_ids?: string[] };
  frequency: "manual" | "hourly" | "daily" | "weekly";
  time_of_day: string | null;
  enabled: boolean;
  framework: string;
  created_by: string | null;
  last_run: string | null;
  next_run: string | null;
  last_run_status: string | null;
  last_run_detail: string | null;
  created_at: string;
  updated_at: string;
}

export interface Alert {
  id: string;
  tenant_id: string;
  category: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  title: string;
  detail: string | null;
  scan_id: string | null;
  device_id: string | null;
  extra: Record<string, unknown> | null;
  status: "OPEN" | "ACKNOWLEDGED";
  acknowledged_by: string | null;
  acknowledged_at: string | null;
  dispatch_results: Record<string, string> | null;
  created_at: string;
}

// --- Enterprise alerting: channels, rules, push -----------------------------

export type AlertChannelType = "email" | "ntfy" | "webhook" | "push";

export interface AlertChannel {
  id: string;
  name: string;
  channel_type: AlertChannelType;
  enabled: boolean;
  config: Record<string, any>;
  has_credentials: boolean;
  last_test_status: "SUCCESS" | "FAILED" | "NEVER_TESTED" | null;
  last_test_at: string | null;
  last_test_message: string | null;
  created_by: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface AlertChannelCreate {
  name: string;
  channel_type: AlertChannelType;
  enabled?: boolean;
  config: Record<string, any>;
  secret?: Record<string, any>;
}

export interface AlertRule {
  id: string;
  name: string;
  enabled: boolean;
  match_categories: string[];
  match_severities: string[];
  channel_ids: string[];
  created_at: string | null;
  updated_at: string | null;
}

export interface AlertRuleCreate {
  name: string;
  enabled?: boolean;
  match_categories?: string[];
  match_severities?: string[];
  channel_ids: string[];
}

export interface ComplianceThreshold {
  id: string;
  name: string;
  enabled: boolean;
  threshold: number;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  device_id: string | null;
  framework: string | null;
  channel_ids: string[];
  only_on_crossing: boolean;
  last_triggered_at: string | null;
  created_by: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface ComplianceThresholdCreate {
  name: string;
  threshold: number;
  enabled?: boolean;
  severity?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  device_id?: string | null;
  framework?: string | null;
  channel_ids?: string[];
  only_on_crossing?: boolean;
}

export interface PushSubscriptionSummary {
  id: string;
  user_agent: string | null;
  created_at: string | null;
  last_used_at: string | null;
  last_error: string | null;
}

export interface ChangeRequest {
  id: string;
  tenant_id: string;
  device_id: string;
  created_by: string | null;
  source: string;
  current_config_hash: string | null;
  proposed_config_hash: string;
  status: string;
  syntax_status: string | null;
  opa_decision: string | null;
  batfish_status: string | null;
  risk_score: number | null;
  risk_level: string | null;
  final_decision: string | null;
  final_reason: string | null;
  validation_detail: Record<string, unknown> | null;
  // CURRENT-vs-PROPOSED Batfish snapshot diff (node/route delta,
  // differential reachability), or null when no prior known config
  // existed to diff against / Batfish is disabled / vendor unsupported.
  snapshot_diff: SnapshotDiff | null;
  approval_required: boolean;
  approved_by: string | null;
  approved_at: string | null;
  rejected_by: string | null;
  rejected_at: string | null;
  rejection_reason: string | null;
  // Present when the CR was created from a CLI delta (snippet) rather than a full config.
  snippet?: string | null;
  merge_style?: string | null;
  merge_confidence?: "HIGH" | "MEDIUM" | "LOW" | null;
  merge_warnings?: string[] | null;
  merge_commands?: string[] | null;
  edited_by?: string | null;
  edited_at?: string | null;
  revision?: number;
  // Human-in-the-loop binding + trail (see backend change_request_service).
  approved_revision?: number | null;
  approved_hash?: string | null;
  review_comment?: string | null;
  override_justification?: string | null;
  review_events?: ReviewEvent[];
  hitl?: HitlRequirements;
  created_at: string;
  updated_at: string;
}

export interface HitlRequirements {
  note_required: boolean;
  min_note_chars: number;
  /** The validator said BLOCK: approving is an explicit, justified override. */
  override_required: boolean;
  four_eyes_required: boolean;
  four_eyes_mode: "off" | "high_risk" | "always";
  approval_expires_at: string | null;
  approval_ttl_hours: number | null;
}

export interface ReviewEvent {
  at: string;
  action: string; // submitted | edited | approved | override_approved | rejected | deployed | deploy_failed | rolled_back | rollback_failed
  actor: string;
  revision?: number;
  comment?: string | null;
  [k: string]: unknown;
}

export type StageStatus = "pending" | "running" | "passed" | "warning" | "failed" | "skipped";

export interface PipelineStage {
  key: string;
  label: string;
  status: StageStatus;
  started_at: string | null;
  finished_at: string | null;
  detail: string | null;
  error: string | null;
  kind: string | null;
}

export interface PostValidation {
  scan_id: string | null;
  opa_decision: string | null;
  batfish_status: string | null;
  risk_level: string | null;
  risk_score: number | null;
  final_decision: string | null;
  final_reason: string | null;
  findings_total?: number;
  findings_failed?: number;
  failed_controls?: { control_id: string; title: string; severity: string }[];
  target_control_ids?: string[] | null;
  target_controls_result?: { control_id: string; result: string }[] | null;
  target_controls_passed?: boolean | null;
  batfish_diff_status?: string | null;
  batfish_diff_summary?: string | null;
  batfish_diff?: SnapshotDiff | null;
}

export interface RollbackRecord {
  id: string;
  deployment_record_id: string;
  initiated_by: string | null;
  reason: string | null;
  transport: string | null;
  target_config_hash: string | null;
  status: string; // PENDING | ROLLED_BACK | VERIFIED | CRITICAL_MANUAL_INTERVENTION_REQUIRED
  post_rollback_hash: string | null;
  post_rollback_verified: boolean | null;
  post_rollback_scan_id: string | null;
  error: string | null;
  started_at: string | null;
  completed_at: string | null;
  stages: PipelineStage[];
  stages_derived?: boolean;
  failed_stage: string | null;
  failure_label: string | null;
  post_validation?: PostValidation | null;
}

export interface PushPlan {
  commands: string[];
  source?: "merge_commands" | "snippet" | "proposed_as_snippet" | "computed_diff" | null;
  warnings: string[];
  error?: string | null;
  /** True when a safe, minimal command set could be derived (backend `deploy_plan`). */
  safe: boolean;
  style?: string | null;
}

export interface EditPreview {
  current_config: string | null;
  proposed_config: string;
  commands: string[];
  warnings?: string[];
  safe?: boolean;
  style?: string | null;
  confidence?: string | null;
  diff_stats?: { added: number; removed: number; unchanged?: number; total_after?: number };
}

export interface MergePreview {
  device_id: string;
  current_config: string | null;
  proposed_config: string;
  style: string;
  confidence: "HIGH" | "MEDIUM" | "LOW";
  warnings: string[];
  commands: string[];
  changed: boolean;
  diff_stats: { added: number; removed: number; unchanged: number; total_after: number };
}

export interface DeploymentRecord {
  id: string;
  tenant_id: string;
  change_request_id: string;
  device_id: string;
  initiated_by: string | null;
  transport: string | null; // ssh | netconf | gnmi
  expected_pre_hash: string | null;
  observed_pre_hash: string | null;
  status: string; // PENDING/DEPLOYING/FAILED/ABORTED_STALE_HASH/DEPLOYED/VERIFIED/DRIFTED
  post_config_hash: string | null;
  post_verification_passed: boolean | null;
  post_scan_id: string | null;
  error: string | null;
  /** True only after a VERIFIED rollback — never speculative. */
  rolled_back?: boolean;
  started_at: string | null;
  completed_at: string | null;
  // OpenConfig/gNMI metadata -- never credentials.
  request_hash: string | null;
  model_name: string | null;
  paths: string[] | null;
  operation: string | null;
  // Optional pyATS/Genie supplemental verification -- never authoritative.
  verification_engine: string | null;
  verification_result: string | null;
  verification_metadata: Record<string, unknown> | null;
  /** Ordered pipeline: credentials → connect → precheck → plan → commit → verify → postval. */
  stages: PipelineStage[];
  /** True for records created before per-stage tracking (reconstructed from status/error). */
  stages_derived?: boolean;
  failed_stage: string | null;
  failure_kind: string | null;
  failure_label: string | null;
  rollback_recommended?: boolean;
  post_validation?: PostValidation | null;
  rollbacks?: RollbackRecord[];
  target_control_ids?: string[] | null;
  batfish_diff_status?: string | null;
  batfish_diff_summary?: string | null;
}

export interface DiscoveredHost {
  ip: string;
  hostname: string | null;
  state: string;
  open_ports: number[];
  transport_hints: string[];
  vendor_guess: string | null;
  banner: string | null;
  os_guess: string | null;
}

export interface DiscoveryJob {
  id: string;
  cidr: string;
  ports: string;
  service_detection: boolean;
  os_detection: boolean;
  status: "PENDING" | "RUNNING" | "PAUSED" | "COMPLETED" | "FAILED" | "CANCELLED";
  total_targets: number;
  scanned_targets: number;
  progress_pct: number;
  host_count: number;
  hosts: DiscoveredHost[];
  error: string | null;
  created_at: number;
  updated_at: number;
}

export interface DiscoverImportPayload {
  hosts: { ip: string; hostname?: string | null; vendor_guess?: string | null }[];
}

export interface NetworkScanJobCreate {
  name?: string;
  device_ids?: string[];
  run_discovery?: boolean;
  target_cidr?: string;
  discovery_ports?: string;
  framework?: string;
  include_batfish?: boolean;
}

export interface NetworkScanJob {
  id: string;
  tenant_id: string;
  name: string | null;
  target_cidr: string | null;
  run_discovery: boolean;
  framework: string;
  include_batfish: boolean;
  status: string;
  stages: Record<string, { status: string; detail?: string }>;
  discovered_hosts?: Record<string, any>[] | null;
  resolved_device_ids?: string[] | null;
  scan_ids?: string[] | null;
  device_results?: Record<string, any>[] | null;
  error?: string | null;
  created_by?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
  started_at?: string | null;
  completed_at?: string | null;
}

export interface DatasetVersion {
  id: string;
  version: string;
  tenant_id: string | null;
  created_by: string;
  created_at: string;
  example_count: number;
  label_distribution: Record<string, number>;
  vendor_distribution: Record<string, number>;
  source_distribution: Record<string, number>;
  validation_status: string | null;
  training_status: string | null;
  is_immutable: boolean;
  dataset_hash: string;
  status: "DRAFT" | "FINALIZED";
  parent_version: string | null;
  finalized_at: string | null;
}

export interface AppUser {
  id: string;
  username: string;
  roles: string[];
  is_active: boolean;
  last_login_at: string | null;
  locked: boolean;
  created_at: string | null;
}

export interface TrainingExample {
  id: string;
  vendor: string | null;
  intent: string | null;
  raw_config_redacted: string;
  normalized_facts: Record<string, any>;
  human_action: "APPROVED" | "CORRECTED" | "REJECTED";
  correction_reason: string | null;
  created_by: string;
  created_at: string | null;
  dataset_version: string | null;
  validation_status: "PENDING" | "VALIDATED" | "EXCLUDED";
}

export interface TrainingJob {
  id: string;
  tenant_id: string | null;
  dataset_version_id: string;
  base_model_version: string | null;
  created_at: string | null;
  started_at: string | null;
  completed_at: string | null;
  status: string;
  artifact_path: string | null;
  metrics: Record<string, any> | null;
  error: string | null;
  created_by: string;
}

export interface ModelRegistryEntry {
  id: string;
  model_name: string;
  model_type: string;
  dataset_version: string;
  base_model_version: string | null;
  artifact_path: string | null;
  model_hash: string | null;
  metrics: Record<string, any> | null;
  training_timestamp: string | null;
  status: string;
  created_by: string;
  approved_by: string | null;
  approved_at: string | null;
  training_job_id: string | null;
  // Share of the 13 known intents this model was trained on (null for models
  // trained before coverage was recorded).
  intent_coverage: number | null;
  known_intents_covered: number | null;
  known_intents_total: number | null;
  known_intents_missing: string[] | null;
}

export interface ComplianceMatrixRow {
  control_id: string;
  title: string;
  vendors: Record<string, number | null>;
}

export interface ComplianceMatrix {
  vendors: string[];
  rows: ComplianceMatrixRow[];
}

// --- Event-driven scanning (Phase 16 event triggers) -----------------------
export interface EventTrigger {
  id: string;
  name: string;
  description: string | null;
  enabled: boolean;
  event_type: string;
  filter: Record<string, any> | Record<string, any>[] | null;
  action_type: string; // create_alert | run_schedule | run_scan
  action_config: Record<string, any>;
  cooldown_seconds: number;
  last_triggered_at: string | null;
  trigger_count: number;
  created_at: string;
}

export interface EventTriggerCreate {
  name: string;
  description?: string | null;
  enabled?: boolean;
  event_type: string;
  filter?: Record<string, any> | Record<string, any>[] | null;
  action_type: string;
  action_config?: Record<string, any>;
  cooldown_seconds?: number;
}

export interface EventTriggerLog {
  id: string;
  trigger_id: string;
  event_type: string;
  event_payload: Record<string, any> | null;
  outcome: string; // fired | skipped_cooldown | skipped_filter | error ...
  action_result: Record<string, any> | null;
  error: string | null;
  created_at: string;
}

export interface EventTriggerMetadata {
  event_types: string[];
  action_types: string[];
}

export const endpoints = {
  dashboard: () => api.get<DashboardStats>("/api/dashboard"),
  complianceMatrix: () => api.get<ComplianceMatrix>("/api/dashboard/compliance-matrix"),
  dashboardMetrics: (range: DashboardRange) =>
    api.get<DashboardMetrics>("/api/dashboard/metrics", { params: { range } }),
  auditLog: (params?: {
    action?: string; object_type?: string; object_id?: string;
    username?: string; result?: string; since?: string; until?: string; limit?: number; offset?: number;
  }) => api.get<AuditLogEntry[]>("/api/audit-log", { params }),
  exportAuditLog: (format: "csv" | "json", params?: any) =>
    api.get("/api/audit-log/export", { params: { ...params, format }, responseType: "blob" }),
  devices: (params?: DeviceListParams) => api.get<DeviceListResponse>("/api/devices", { params }),
  createDevice: (payload: DeviceCreatePayload) => api.post<Device>("/api/devices", payload),
  updateDevice: (id: string, payload: DeviceUpdatePayload) => api.patch<Device>(`/api/devices/${id}`, payload),
  deleteDevice: (id: string) => api.delete(`/api/devices/${id}`),
  enableDevice: (id: string) => api.post(`/api/devices/bulk/enable`, { device_ids: [id] }),
  disableDevice: (id: string) => api.post(`/api/devices/bulk/disable`, { device_ids: [id] }),

  // Credentials
  storeCredentials: (deviceId: string, credentialType: string, secret: Record<string, any>) =>
    api.post(`/api/devices/${deviceId}/credentials`, { credential_type: credentialType, secret }),
  listCredentials: (deviceId: string) =>
    api.get<CredentialRef[]>(`/api/devices/${deviceId}/credentials`),

  bulkEnableDevices: (deviceIds: string[]) => api.post<BulkDeviceResult>("/api/devices/bulk/enable", { device_ids: deviceIds }),
  bulkDisableDevices: (deviceIds: string[]) => api.post<BulkDeviceResult>("/api/devices/bulk/disable", { device_ids: deviceIds }),
  bulkDeleteDevices: (deviceIds: string[]) => api.post<BulkDeviceResult>("/api/devices/bulk/delete", { device_ids: deviceIds }),
  testDeviceConnection: (id: string, transport?: string, credentialRefId?: string) =>
    api.post<CollectionStatusResult>(`/api/devices/${id}/test-connection`, {
      credential_ref_id: credentialRefId, transport: transport || undefined,
    }),
  collectDeviceConfig: (id: string, transport?: string, credentialRefId?: string) =>
    api.post<CollectionStatusResult>(`/api/devices/${id}/collect`, {
      credential_ref_id: credentialRefId, transport: transport || undefined,
    }),
  collectAndScanDevice: (id: string, framework = "ALL", transport?: string) =>
    api.post<ScanDetail>(`/api/devices/${id}/scan`, { transport: transport || undefined }, { params: { framework } }),

  // Network Discovery -- job-based: POST kicks off a background nmap scan
  // and returns immediately with a job id; poll getDiscoveryJob for
  // progress/results, and pause/resume/cancel an in-flight scan.
  discoverNetwork: (cidr: string, ports?: string, serviceDetection = true) =>
    api.post<DiscoveryJob>("/api/devices/discover", { cidr, ports, service_detection: serviceDetection }),
  importDiscoveredDevices: (payload: DiscoverImportPayload) =>
    api.post<Device[]>("/api/devices/discover/import", payload),
  discover: (payload: { cidr: string; ports?: string; service_detection?: boolean; os_detection?: boolean }) =>
    api.post<DiscoveryJob>("/api/devices/discover", payload),
  getDiscoveryJob: (jobId: string) => api.get<DiscoveryJob>(`/api/devices/discover/${jobId}`),
  pauseDiscoveryJob: (jobId: string) => api.post<DiscoveryJob>(`/api/devices/discover/${jobId}/pause`),
  resumeDiscoveryJob: (jobId: string) => api.post<DiscoveryJob>(`/api/devices/discover/${jobId}/resume`),
  cancelDiscoveryJob: (jobId: string) => api.post<DiscoveryJob>(`/api/devices/discover/${jobId}/cancel`),
  discoverImport: (payload: DiscoverImportPayload) =>
    api.post<Device[]>("/api/devices/discover/import", payload),

  // Network Scan jobs
  networkScans: () => api.get<NetworkScanJob[]>("/api/network-scans"),
  getNetworkScan: (id: string) => api.get<NetworkScanJob>(`/api/network-scans/${id}`),
  createNetworkScan: (payload: NetworkScanJobCreate) =>
    api.post<NetworkScanJob>("/api/network-scans", payload),
  scans: (params?: { device_id?: string; limit?: number }) => api.get<Scan[]>("/api/scans", { params }),
  runningScans: () => api.get<Scan[]>("/api/scans/running"),
  scan: (id: string) => api.get<ScanDetail>(`/api/scans/${id}`),
  rerunScan: (id: string) => api.post<ScanDetail>(`/api/scans/${id}/rerun`),
  pauseScan: (id: string) => api.post<ScanDetail>(`/api/scans/${id}/pause`),
  stopScan: (id: string, immediate = false) =>
    api.post<ScanDetail>(`/api/scans/${id}/stop`, undefined, { params: immediate ? { immediate: true } : undefined }),
  resumeScan: (id: string) => api.post<ScanDetail>(`/api/scans/${id}/resume`),
  bulkStopScans: (scanIds: string[], immediate = true) =>
    api.post<{ stopped: string[]; skipped: { id: string; detail: string }[] }>("/api/scans/bulk-stop", {
      scan_ids: scanIds,
      immediate,
    }),
  deleteScan: (id: string, force = false) =>
    api.delete<{ deleted: string }>(`/api/scans/${id}`, { params: force ? { force: true } : undefined }),
  bulkDeleteScans: (scanIds: string[], force = false) =>
    api.post<{ deleted: string[]; failed: { id: string; detail: string }[] }>("/api/scans/bulk-delete", {
      scan_ids: scanIds,
      force,
    }),
  pipelineStatus: (id: string) => api.get<PipelineStatus>(`/api/scans/${id}/pipeline-status`),
  batfishAnalysis: (scanId: string) => api.get<BatfishAnalysis>(`/api/scans/${scanId}/batfish`),
  snapshotDiff: (scanId: string) => api.get<SnapshotDiff>(`/api/scans/${scanId}/snapshot-diff`),
  opaAnalysis: (scanId: string) => api.get<OpaAnalysis>(`/api/scans/${scanId}/opa`),
  aiAnalysis: (scanId: string) => api.get<ScanAIAnalysis>(`/api/scans/${scanId}/ai`),
  aiRemediation: (scanId: string) => api.get<any>(`/api/scans/${scanId}/remediation/generate-cli`),
  aiHealth: () => api.get<AIHealth>("/api/ai/health"),
  confidenceTrend: (days = 30) => api.get<ConfidenceTrendOut>("/api/ai/confidence-trend", { params: { days } }),
  reviewQueue: (limit = 100) => api.get<ReviewQueueResponse>("/api/ai/review-queue", { params: { limit } }),
  systemHealth: () => api.get<SystemHealth>("/api/system/health"),
  complianceSummary: () => api.get<ComplianceSummary>("/api/metrics/compliance-summary"),
  findings: (params?: { scan_id?: string; severity?: string; result?: string; vendor?: string }) =>
    api.get<Finding[]>("/api/findings", { params }),
  finding: (findingId: string) => api.get<Finding>(`/api/findings/${findingId}`),
  uploadConfig: (file: File, framework: string, hostname?: string) => {
    const form = new FormData();
    form.append("file", file);
    form.append("framework", framework);
    if (hostname) form.append("hostname", hostname);
    return api.post<ScanDetail>("/api/scans/upload", form);
  },
  bulkUploadConfigs: (files: File[], framework = "ALL") => {
    const form = new FormData();
    files.forEach((f) => form.append("files", f));
    form.append("framework", framework);
    return api.post<ScanDetail[]>("/api/scans/bulk-upload", form, {
      headers: { "Content-Type": "multipart/form-data" },
    });
  },

  // --- Topology groups (Datacenter/Rack/NetworkGroup + Batfish) ---------
  topologyGroups: () => api.get<TopologyGroup[]>("/api/topology/groups"),
  topologyGroup: (id: string) => api.get<TopologyGroup>(`/api/topology/groups/${id}`),
  createTopologyGroup: (payload: { name: string; description?: string; device_ids: string[] }) =>
    api.post<TopologyGroup>("/api/topology/groups", payload),
  scanTopologyGroup: (id: string) => api.post<any>(`/api/topology/groups/${id}/scan`),
  buildTopology: (files: File[], groupName?: string) => {
    const form = new FormData();
    files.forEach((f) => form.append("files", f));
    if (groupName) form.append("group_name", groupName);
    return api.post<BuildTopologyResult>("/api/topology/build", form, {
      headers: { "Content-Type": "multipart/form-data" },
    });
  },
  
  // Training Center Layer 3+
  pendingMappings: () => api.get<CommandMapping[]>("/api/training/pending"),
  approvedMappings: () => api.get<CommandMapping[]>("/api/training/approved"),
  reviewMapping: (id: string, payload: { action: "approve" | "correct" | "reject", normalized_parameter?: string, normalized_facts?: Record<string, any>, correction_reason?: string }) =>
    api.post(`/api/training/${id}/review`, payload),
  trainingExamples: (status: string, humanAction?: string) =>
    api.get<TrainingExample[]>(`/api/training/examples?status=${status}${humanAction ? `&human_action=${humanAction}` : ""}`),
  validateTrainingExample: (id: string) => api.post<TrainingExample>(`/api/training/examples/${id}/validate`),
  excludeTrainingExample: (id: string) => api.post<TrainingExample>(`/api/training/examples/${id}/exclude`),
  bulkValidateTrainingExamples: (ids: string[]) => api.post<{ validated_count: number; validated_ids: string[] }>("/api/training/examples/bulk-validate", ids),
  changePassword: (currentPassword: string, newPassword: string) =>
    api.post<{ access_token: string; token_type: string; expires_in: number }>("/api/auth/change-password", {
      current_password: currentPassword, new_password: newPassword,
    }),
  listUsers: () => api.get<AppUser[]>("/api/users"),
  createUser: (username: string, password: string, roles: string[]) => api.post<AppUser>("/api/users", { username, password, roles }),
  updateUser: (id: string, patch: { roles?: string[]; is_active?: boolean }) => api.patch<AppUser>(`/api/users/${id}`, patch),
  resetUserPassword: (id: string, newPassword: string) => api.post(`/api/users/${id}/reset-password`, { new_password: newPassword }),
  trainingSettings: () => api.get<{ admin_auto_validate: boolean }>("/api/training/settings"),
  datasets: () => api.get<DatasetVersion[]>("/api/ai/datasets"),
  createDatasetDraft: (versionLabel: string) => api.post<DatasetVersion>("/api/ai/datasets/draft", { version_label: versionLabel }),
  datasetExamples: (id: string) => api.get<TrainingExample[]>(`/api/ai/datasets/${id}/examples`),
  addDatasetExamples: (id: string, exampleIds: string[]) => api.post<DatasetVersion>(`/api/ai/datasets/${id}/examples`, { example_ids: exampleIds }),
  removeDatasetExample: (id: string, exampleId: string) => api.delete<DatasetVersion>(`/api/ai/datasets/${id}/examples/${exampleId}`),
  finalizeDataset: (id: string) => api.post<DatasetVersion>(`/api/ai/datasets/${id}/finalize`),
  cloneDataset: (id: string, newLabel: string) => api.post<DatasetVersion>(`/api/ai/datasets/${id}/clone`, { new_label: newLabel }),
  deleteDatasetDraft: (id: string) => api.delete(`/api/ai/datasets/${id}`),
  trainingJobs: () => api.get<TrainingJob[]>("/api/ai/training/jobs"),
  createTrainingJob: (datasetVersionId: string) => api.post<TrainingJob>("/api/ai/training/jobs", { dataset_version_id: datasetVersionId }),
  retryTrainingJob: (id: string) => api.post<TrainingJob>(`/api/ai/training/jobs/${id}/retry`),
  cancelTrainingJob: (id: string) => api.post<TrainingJob>(`/api/ai/training/jobs/${id}/cancel`),
  registryModels: () => api.get<ModelRegistryEntry[]>("/api/ai/registry/models"),
  approveModel: (id: string) => api.post<ModelRegistryEntry>(`/api/ai/registry/models/${id}/approve`),
  rejectModel: (id: string) => api.post<ModelRegistryEntry>(`/api/ai/registry/models/${id}/reject`),
  promoteModel: (id: string) => api.post<ModelRegistryEntry>(`/api/ai/registry/models/${id}/promote`),
  rollbackModel: (targetModelId: string) => api.post<ModelRegistryEntry>("/api/ai/registry/models/rollback", { target_model_id: targetModelId }),

  reportUrl: (scanId: string, fmt: "pdf" | "json" | "csv") =>
    `${api.defaults.baseURL}/api/reports/${scanId}/${fmt}`,
  downloadReport: async (scanId: string, fmt: "pdf" | "json" | "csv") => {
    const res = await api.get(`/api/reports/${scanId}/${fmt}`, { responseType: "blob" });
    const url = window.URL.createObjectURL(new Blob([res.data]));
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", `scan_${scanId}_report.${fmt}`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  },
  // Fetches the same JSON report as reportUrl(scanId,"json") but via the
  // authenticated axios instance, so in-app tabs (Compliance Matrix /
  // Vulnerabilities on ScanDetail) can read compliance_matrix /
  // vulnerability_matches without a plain <a href> download.
  reportJson: (scanId: string) => api.get<{
    compliance_matrix: Array<Record<string, any>>;
    vulnerability_matches: Array<Record<string, any>>;
  }>(`/api/reports/${scanId}/json`),
  verifyReport: (file: File, scanId?: string, fmt?: string) => {
    const form = new FormData();
    form.append("file", file);
    if (scanId) form.append("scan_id", scanId);
    if (fmt) form.append("fmt", fmt);
    return api.post<ReportVerifyResult>("/api/reports/verify", form, {
      headers: { "Content-Type": "multipart/form-data" },
    });
  },
  downloadOriginalReportUrl: (artifactId: string) =>
    `${api.defaults.baseURL}/api/reports/artifact/${artifactId}/download`,
  downloadOriginalReport: (artifactId: string) =>
    api.get(`/api/reports/artifact/${artifactId}/download`, { responseType: "blob" }),
  evidenceList: (scanId?: string) => api.get<EvidenceRecord[]>("/api/evidence", { params: scanId ? { scan_id: scanId } : undefined }),
  evidenceDetail: (evidenceId: string) => api.get<EvidenceDetail>(`/api/evidence/${evidenceId}`),
  evidenceVerify: (evidenceId: string) => api.post<VerifyResult>(`/api/evidence/${evidenceId}/verify`),
  evidenceSimulateTamper: (evidenceId: string) => api.post<EvidenceDetail>(`/api/evidence/${evidenceId}/simulate-tamper`),
  evidenceRestore: (evidenceId: string) => api.post<EvidenceDetail>(`/api/evidence/${evidenceId}/restore`),
  topology: () => api.get<Topology>("/api/topology"),
  topologyVlans: () => api.get<{ count: number; vlans: VlanMapEntry[] }>("/api/topology/vlans"),
  refreshTopology: (deviceIds?: string[]) =>
    api.post<TopologyRefreshResult>("/api/topology/refresh", { device_ids: deviceIds ?? null }),
  deviceInterfaces: (deviceId: string) => api.get<NetworkInterface[]>(`/api/devices/${deviceId}/interfaces`),
  deviceRoutes: (deviceId: string) => api.get<NetworkRoute[]>(`/api/devices/${deviceId}/routes`),

  drift: (params?: { security_impacting?: boolean }) =>
    api.get<{ count: number; events: DriftEvent[] }>("/api/drift", { params }),
  deviceDrift: (deviceId: string) =>
    api.get<{ count: number; events: DriftEvent[] }>(`/api/devices/${deviceId}/drift`),

  deviceSnapshots: (deviceId: string) =>
    api.get<{ device_id: string; count: number; snapshots: ConfigSnapshot[] }>(`/api/devices/${deviceId}/snapshots`),
  deviceSnapshot: (deviceId: string, snapshotId: string) =>
    api.get<ConfigSnapshotDetail>(`/api/devices/${deviceId}/snapshots/${snapshotId}`),
  approveBaseline: (deviceId: string, snapshotId: string, approvalReason?: string) =>
    api.post(`/api/devices/${deviceId}/baselines/${snapshotId}/approve`, { approval_reason: approvalReason }),
  deviceDriftHistory: (deviceId: string, params?: { drift_type?: string; status?: string }) =>
    api.get<{ device_id: string; count: number; findings: SecurityDriftFinding[] }>(
      `/api/devices/${deviceId}/drift/history`, { params },
    ),

  // --- Enterprise config backup / NCO management ---
  backupSummary: () => api.get<BackupFleetSummary>("/api/backups/summary"),
  backupDestinations: () => api.get<{ count: number; destinations: BackupDestination[] }>("/api/backup-destinations"),
  createBackupDestination: (payload: BackupDestinationCreate) =>
    api.post<BackupDestination>("/api/backup-destinations", payload),
  updateBackupDestination: (id: string, payload: Partial<BackupDestinationCreate>) =>
    api.patch<BackupDestination>(`/api/backup-destinations/${id}`, payload),
  deleteBackupDestination: (id: string) => api.delete(`/api/backup-destinations/${id}`),
  testBackupDestination: (id: string) =>
    api.post<{ success: boolean; message: string }>(`/api/backup-destinations/${id}/test`),
  exportSnapshot: (deviceId: string, snapshotId: string, destinationIds: string[]) =>
    api.post<{ snapshot_id: string; results: BackupJob[] }>(
      `/api/devices/${deviceId}/snapshots/${snapshotId}/export`, { destination_ids: destinationIds },
    ),
  downloadSnapshot: (deviceId: string, snapshotId: string) =>
    api.get<{ snapshot_id: string; filename: string; content: string }>(
      `/api/devices/${deviceId}/snapshots/${snapshotId}/download`,
    ),
  backupJobs: (params?: { device_id?: string; destination_id?: string; status?: string; limit?: number }) =>
    api.get<{ count: number; jobs: BackupJob[] }>("/api/backup-jobs", { params }),
  deviceComplianceHistory: (deviceId: string) =>
    api.get<CompliancePostureHistory>(`/api/devices/${deviceId}/compliance/history`),
  auditDeviceViaGateway: (deviceId: string) => api.post(`/api/devices/${deviceId}/audit`),
  gatewayGetFacts: (deviceId: string, protocol?: string | null) =>
    api.post(`/api/devices/${deviceId}/gateway-get-facts`, { protocol }),
  gatewayGetInterfaces: (deviceId: string, protocol?: string | null) =>
    api.post(`/api/devices/${deviceId}/gateway-get-interfaces`, { protocol }),
  gatewayGetHealthMetrics: (deviceId: string, protocol?: string | null) =>
    api.post(`/api/devices/${deviceId}/gateway-get-health-metrics`, { protocol }),
  // Was missing entirely -- DeviceDetail.tsx's pollLiveTelemetry() called
  // endpoints.gatewayGetRoutes(...) (see backend routers/device_gateway.py's
  // POST /{device_id}/gateway-get-routes, GET_ROUTES) even though no such
  // method existed here. Calling an undefined property as a function throws
  // synchronously the instant "Live Telemetry" is polled; the surrounding
  // try/catch there kept it from crashing the page, but the panel could
  // never actually show a routing table -- it always failed with
  // "gatewayGetRoutes is not a function".
  gatewayGetRoutes: (deviceId: string, protocol?: string | null) =>
    api.post(`/api/devices/${deviceId}/gateway-get-routes`, { protocol }),
  gatewayGetNeighbors: (deviceId: string, protocol?: string) =>
    api.post<{ success: boolean; normalized_data?: { neighbors?: any[]; neighbor_count?: number }; links_stored?: number; error_message?: string }>(
      `/api/devices/${deviceId}/gateway-get-neighbors`, { protocol },
    ),
  gatewaySupportedOperations: () => api.get<{ read_only_operations: string[] }>("/api/devices/gateway/operations"),
  metricsHistory: (deviceId: string, hours = 24) =>
    api.get<{ device_id: string; count: number; snapshots: any[] }>(
      `/api/devices/${deviceId}/metrics/history?hours=${hours}`
    ),
  metricsLatest: (deviceId: string) =>
    api.get<{ device_id: string; snapshot: any | null }>(`/api/devices/${deviceId}/metrics/latest`),
  metricsThresholds: () => api.get<Record<string, number>>("/api/metrics/thresholds"),
  updateMetricsThresholds: (payload: Partial<Record<string, number>>) =>
    api.put<Record<string, number>>("/api/metrics/thresholds", payload),

  schedules: () => api.get<AuditSchedule[]>("/api/schedules"),
  createSchedule: (payload: {
    name: string;
    scope: { all?: boolean; device_ids?: string[] };
    frequency: string;
    time_of_day?: string | null;
    enabled: boolean;
    framework: string;
  }) => api.post<AuditSchedule>("/api/schedules", payload),
  updateSchedule: (id: string, payload: Partial<{ name: string; enabled: boolean; frequency: string; time_of_day: string | null; scope: unknown; framework: string }>) =>
    api.patch<AuditSchedule>(`/api/schedules/${id}`, payload),
  deleteSchedule: (id: string) => api.delete(`/api/schedules/${id}`),

  configSearch: (q: string, deep = true) =>
    api.get<ConfigSearchResult>("/api/config-search", { params: { q, deep } }),
  runScheduleNow: (id: string) => api.post(`/api/schedules/${id}/run`),

  // Event-driven scanning: user-defined triggers that fire on internal
  // events (compliance.scan.completed, drift.detected, ...) or an inbound
  // webhook, and either raise an alert or kick off a schedule immediately --
  // i.e. scanning driven by events rather than only by the clock.
  eventTriggerMetadata: () => api.get<EventTriggerMetadata>("/api/event-triggers/metadata"),
  eventTriggers: () => api.get<EventTrigger[]>("/api/event-triggers"),
  eventTrigger: (id: string) => api.get<EventTrigger>(`/api/event-triggers/${id}`),
  createEventTrigger: (payload: EventTriggerCreate) => api.post<EventTrigger>("/api/event-triggers", payload),
  updateEventTrigger: (id: string, payload: EventTriggerCreate) =>
    api.put<EventTrigger>(`/api/event-triggers/${id}`, payload),
  deleteEventTrigger: (id: string) => api.delete(`/api/event-triggers/${id}`),
  eventTriggerLogs: (id: string) => api.get<EventTriggerLog[]>(`/api/event-triggers/${id}/logs`),
  testEventTrigger: (id: string, samplePayload?: Record<string, any>) =>
    api.post<{ dispatched: boolean; latest_log: EventTriggerLog | null }>(
      `/api/event-triggers/${id}/test`, samplePayload || {},
    ),

  alerts: (params?: { status?: string; severity?: string; category?: string }) =>
    api.get<{ count: number; alerts: Alert[] }>("/api/alerts", { params }),
  acknowledgeAlert: (id: string) => api.post<Alert>(`/api/alerts/${id}/acknowledge`),

  // --- Simulated alerts (onboarding / channel-wiring verification) ---
  simulatableCategories: () =>
    api.get<{ categories: SimulatableCategory[] }>("/api/alerts/simulate/categories"),
  simulateAlert: (payload: { category: string; severity?: string; device_id?: string }) =>
    api.post<{ alert: Alert; dispatch_results: Record<string, string> }>(
      "/api/alerts/simulate",
      payload,
    ),

  // --- Enterprise alerting: channels / rules / push ---
  alertCategories: () => api.get<{ categories: string[]; severities: string[] }>("/api/alerts/categories"),
  alertChannels: () => api.get<{ count: number; channels: AlertChannel[] }>("/api/alerts/channels"),
  createAlertChannel: (payload: AlertChannelCreate) => api.post<AlertChannel>("/api/alerts/channels", payload),
  updateAlertChannel: (id: string, payload: Partial<AlertChannelCreate>) =>
    api.patch<AlertChannel>(`/api/alerts/channels/${id}`, payload),
  deleteAlertChannel: (id: string) => api.delete(`/api/alerts/channels/${id}`),
  testAlertChannel: (id: string) =>
    api.post<{ success: boolean; message: string }>(`/api/alerts/channels/${id}/test`),

  alertRules: () => api.get<{ count: number; rules: AlertRule[] }>("/api/alerts/rules"),
  createAlertRule: (payload: AlertRuleCreate) => api.post<AlertRule>("/api/alerts/rules", payload),
  updateAlertRule: (id: string, payload: Partial<AlertRuleCreate>) =>
    api.patch<AlertRule>(`/api/alerts/rules/${id}`, payload),
  deleteAlertRule: (id: string) => api.delete(`/api/alerts/rules/${id}`),

  complianceThresholds: () =>
    api.get<{ count: number; thresholds: ComplianceThreshold[] }>("/api/alerts/thresholds"),
  createComplianceThreshold: (payload: ComplianceThresholdCreate) =>
    api.post<ComplianceThreshold>("/api/alerts/thresholds", payload),
  updateComplianceThreshold: (id: string, payload: Partial<ComplianceThresholdCreate>) =>
    api.patch<ComplianceThreshold>(`/api/alerts/thresholds/${id}`, payload),
  deleteComplianceThreshold: (id: string) => api.delete(`/api/alerts/thresholds/${id}`),

  pushVapidPublicKey: () => api.get<{ public_key: string }>("/api/alerts/push/vapid-public-key"),
  pushSubscribe: (payload: { endpoint: string; keys: { p256dh: string; auth: string }; user_agent?: string }) =>
    api.post<{ status: string; id: string }>("/api/alerts/push/subscribe", payload),
  pushUnsubscribe: (endpoint: string) => api.post("/api/alerts/push/unsubscribe", { endpoint }),
  pushSubscriptions: () =>
    api.get<{ count: number; subscriptions: PushSubscriptionSummary[] }>("/api/alerts/push/subscriptions"),

  aiModels: () => api.get<AIModelsInfo>("/api/ai/models"),
  device: (id: string) => api.get<Device>(`/api/devices/${id}`),
  deviceScans: (deviceId: string) => api.get<Scan[]>("/api/scans", { params: { device_id: deviceId } }),

  changeRequests: (params?: { status?: string; device_id?: string }) =>
    api.get<{ count: number; change_requests: ChangeRequest[] }>("/api/change-requests", { params }),
  changeRequest: (id: string) => api.get<ChangeRequest>(`/api/change-requests/${id}`),
  changeRequestConfigs: (id: string) =>
    api.get<{ current_config: string | null; proposed_config: string | null; current_config_hash: string | null; proposed_config_hash: string | null }>(
      `/api/change-requests/${id}/configs`,
    ),
  createChangeRequest: (deviceId: string, proposedConfig: string) =>
    api.post<ChangeRequest>("/api/change-requests", { device_id: deviceId, proposed_config: proposedConfig }),
  /** Create from a CLI delta: the backend merges it onto the device's current config. */
  createChangeRequestFromSnippet: (deviceId: string, snippet: string) =>
    api.post<ChangeRequest>("/api/change-requests", { device_id: deviceId, snippet }),
  previewChangeRequestMerge: (deviceId: string, snippet: string, currentConfig?: string | null) =>
    api.post<MergePreview>("/api/change-requests/preview", {
      device_id: deviceId, snippet, current_config: currentConfig ?? null,
    }),
  /** Admin-only: edit, re-merge, re-validate; forces re-approval. */
  editChangeRequest: (id: string, body: { snippet?: string; proposed_config?: string }) =>
    api.patch<ChangeRequest>(`/api/change-requests/${id}`, body),
  /** Admin-only, read-only: what would this edit push? */
  previewChangeRequestEdit: (id: string, body: { snippet?: string; proposed_config?: string }) =>
    api.post<EditPreview>(`/api/change-requests/${id}/preview-edit`, body),
  changeRequestDeployPlan: (id: string) => api.get<PushPlan>(`/api/change-requests/${id}/deploy-plan`),
  /** `revision`/`proposed_config_hash` bind the approval to what the reviewer saw. */
  approveChangeRequest: (
    id: string,
    body: { comment?: string; revision?: number; proposed_config_hash?: string } = {},
  ) => api.post<ChangeRequest>(`/api/change-requests/${id}/approve`, body),
  rejectChangeRequest: (id: string, reason: string) =>
    api.post<ChangeRequest>(`/api/change-requests/${id}/reject`, { reason }),
  deployChangeRequest: (id: string, opts: { transport?: string; credential_ref_id?: string } = {}) =>
    api.post<DeploymentRecord>(`/api/change-requests/${id}/deploy`, opts),
  changeRequestDeployments: (id: string) =>
    api.get<{ count: number; deployments: DeploymentRecord[] }>(`/api/change-requests/${id}/deployments`),
  changeRequestBlastRadius: (id: string) =>
    api.get<BlastRadius>(`/api/change-requests/${id}/blast-radius`),
  /** Dev-mode only (backend returns 404 unless ENABLE_DEV_SIMULATION=true). */
  simulateDeploymentDrift: (crId: string, deploymentId?: string) =>
    api.post<SimulateDriftResult>(`/api/change-requests/${crId}/simulate-drift`, {
      deployment_id: deploymentId ?? null,
    }),
  rollbackDeployment: (crId: string, deploymentId: string, reason?: string) =>
    api.post(`/api/change-requests/${crId}/deployments/${deploymentId}/rollback`, {
      reason: reason ?? null,
    }),

  // GNS3
  gns3Servers: () => api.get("/api/gns3/servers"),
  addGns3Server: (data: any) => api.post("/api/gns3/servers", data),
  deleteGns3Server: (serverId: string) => api.delete(`/api/gns3/servers/${serverId}`),
  pingGns3Server: (serverId: string) => api.get(`/api/gns3/servers/${serverId}/ping`),
  gns3Labs: (serverId: string) => api.get(`/api/gns3/servers/${serverId}/labs`),
  gns3Topology: (serverId: string, labId: string) => api.get(`/api/gns3/servers/${serverId}/labs/${labId}/topology`),
  startGns3Lab: (serverId: string, labId: string) => api.post(`/api/gns3/servers/${serverId}/labs/${labId}/start`),
  stopGns3Lab: (serverId: string, labId: string) => api.post(`/api/gns3/servers/${serverId}/labs/${labId}/stop`),
  importGns3Lab: (serverId: string, labId: string, nodeIds?: string[]) =>
    api.post(`/api/gns3/servers/${serverId}/labs/${labId}/import`, { node_ids: nodeIds ?? null }),

  // --- Unified Control Library ---
  controls: (params?: { domain?: string; status?: string; limit?: number; offset?: number }) =>
    api.get<{ count: number; controls: UnifiedControl[] }>("/api/controls", { params }),
  createControl: (payload: {
    name: string; objective?: string; domain?: string; source_text?: string;
    normalized_description?: string; source_document?: string;
    framework_mappings?: { framework: string; external_id: string; confidence?: number }[];
  }) => api.post<UnifiedControl>("/api/controls", payload),
  control: (id: string) => api.get<UnifiedControl>(`/api/controls/${id}`),
  updateControl: (id: string, payload: Partial<{
    name: string; objective: string; domain: string; source_text: string;
    normalized_description: string; status: string;
  }>) => api.patch<UnifiedControl>(`/api/controls/${id}`, payload),
  controlPatterns: (id: string) =>
    api.get<{ count: number; patterns: VendorConfigPattern[] }>(`/api/controls/${id}/patterns`),
  addControlPattern: (id: string, payload: {
    concept_id?: string; concept_name?: string; vendor: string; pattern: string; example_snippet?: string;
  }) => api.post<VendorConfigPattern>(`/api/controls/${id}/patterns`, payload),
  compileControl: (id: string) => api.post(`/api/controls/${id}/compile`),
  pendingReviews: () => api.get<{ count: number; reviews: ControlReview[] }>("/api/controls/reviews/pending"),
  decideReview: (controlId: string, payload: {
    decision: "approved" | "rejected" | "corrected"; original_text?: string;
    proposed_change?: string; correction?: Record<string, unknown>;
  }) => api.post<ControlReview>(`/api/controls/reviews/${controlId}/decide`, payload),

  // --- Document Ingestion ---
  ingestDocument: (file: File) => {
    const form = new FormData();
    form.append("file", file);
    return api.post<DocumentIngestionJob>("/api/controls/ingest-document", form, {
      headers: { "Content-Type": "multipart/form-data" },
    });
  },
  ingestionStatus: (jobId: string) => api.get<DocumentIngestionJob>(`/api/controls/ingest-document/${jobId}`),

  // --- Vulnerability Management ---
  vulnerabilities: (params?: { severity?: string; kev_flag?: boolean; limit?: number; offset?: number }) =>
    api.get<{ count: number; vulnerabilities: Vulnerability[] }>("/api/vulnerabilities", { params }),
  vulnerability: (cveId: string) => api.get<Vulnerability>(`/api/vulnerabilities/${cveId}`),
  deviceVulns: (deviceId: string, status?: string) =>
    api.get<{ device_id: string; count: number; matches: DeviceVulnerabilityMatch[] }>(
      `/api/devices/${deviceId}/vulns`, { params: { status } },
    ),
  correlateDeviceVulns: (deviceId: string) => api.post(`/api/devices/${deviceId}/vulns/correlate`),
  updateVulnMatchStatus: (deviceId: string, matchId: string, payload: { status: string; justification?: string }) =>
    api.patch<DeviceVulnerabilityMatch>(`/api/devices/${deviceId}/vulns/${matchId}`, payload),
  syncVulnFeeds: (opts?: { full?: boolean }) =>
    api.post<{ synced_at: string; feeds: Array<{ status: string; source: string; upserted?: number; flagged?: number; error?: string; reason?: string }> }>(
      "/api/vulns/sync", null, { params: opts },
    ),

  // --- RAG chat (Ask NetSecAuditor) ---
  ragQuery: (question: string, top_k = 5) =>
    api.post<RagQueryResponse>("/api/rag/query", { question, top_k }),
  ragReindex: () => api.post<{ reindexed: Record<string, number> }>("/api/rag/reindex"),
  ragHistory: (limit = 20) =>
    api.get<{ id: string; question: string; answer: string; created_at: string }[]>("/api/rag/history", { params: { limit } }),
};