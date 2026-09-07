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

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || "http://localhost:8000",
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

export interface Finding {
  id: string;
  framework: string;
  control_id: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  expected_value: string | null;
  actual_value: string | null;
  result: "PASS" | "FAIL" | "NOT_APPLICABLE";
  parameter: string;
  evidence_line: string | null;
  remediation: string | null;
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
}

export interface ScanDetail extends Scan {
  baseline_json: Record<string, any> | null;
  findings: Finding[];
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
  subnet: string;
  source_device_id: string;
  source_interface: string | null;
  target_device_id: string;
  target_interface: string | null;
  link_type: string;
}

export interface Topology {
  nodes: TopologyNode[];
  links: TopologyLink[];
}

export interface SnapshotDiff {
  status: string;
  network_name?: string | null;
  current_snapshot?: string | null;
  proposed_snapshot?: string | null;
  node_delta?: { added: string[]; removed: string[] };
  route_delta?: { current_count: number; proposed_count: number; count_delta: number };
  differential_reachability?: { status: string; changed_flow_count?: number; detail?: string };
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
  snapshot_diff: {
    status: string;
    detail?: string;
    node_delta?: { added: string[]; removed: string[] };
    route_delta?: { current_count: number; proposed_count: number; count_delta: number };
    differential_reachability?: { status: string; changed_flow_count?: number; detail?: string };
  } | null;
  approval_required: boolean;
  approved_by: string | null;
  approved_at: string | null;
  rejected_by: string | null;
  rejected_at: string | null;
  rejection_reason: string | null;
  created_at: string;
  updated_at: string;
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

export interface DiscoverResponse {
  cidr: string;
  host_count: number;
  hosts: DiscoveredHost[];
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
}

export interface TrainingJob {
  id: string;
  tenant_id: string | null;
  dataset_version_id: string;
  base_model_version: string | null;
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
}

export const endpoints = {
  dashboard: () => api.get<DashboardStats>("/api/dashboard"),
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

  // Network Discovery
  discoverNetwork: (cidr: string, ports?: string, serviceDetection = true) =>
    api.post<DiscoverResponse>("/api/devices/discover", { cidr, ports, service_detection: serviceDetection }),
  importDiscoveredDevices: (payload: DiscoverImportPayload) =>
    api.post<Device[]>("/api/devices/discover/import", payload),
  discover: (payload: { cidr: string; ports?: string; service_detection?: boolean; os_detection?: boolean }) =>
    api.post<DiscoverResponse>("/api/devices/discover", payload),
  discoverImport: (payload: DiscoverImportPayload) =>
    api.post<Device[]>("/api/devices/discover/import", payload),

  // Network Scan jobs
  networkScans: () => api.get<NetworkScanJob[]>("/api/network-scans"),
  getNetworkScan: (id: string) => api.get<NetworkScanJob>(`/api/network-scans/${id}`),
  createNetworkScan: (payload: NetworkScanJobCreate) =>
    api.post<NetworkScanJob>("/api/network-scans", payload),
  scans: () => api.get<Scan[]>("/api/scans"),
  scan: (id: string) => api.get<ScanDetail>(`/api/scans/${id}`),
  rerunScan: (id: string) => api.post<ScanDetail>(`/api/scans/${id}/rerun`),
  batfishAnalysis: (scanId: string) => api.get<BatfishAnalysis>(`/api/scans/${scanId}/batfish`),
  snapshotDiff: (scanId: string) => api.get<SnapshotDiff>(`/api/scans/${scanId}/snapshot-diff`),
  opaAnalysis: (scanId: string) => api.get<OpaAnalysis>(`/api/scans/${scanId}/opa`),
  aiAnalysis: (scanId: string) => api.get<ScanAIAnalysis>(`/api/scans/${scanId}/ai`),
  aiHealth: () => api.get<AIHealth>("/api/ai/health"),
  systemHealth: () => api.get<SystemHealth>("/api/system/health"),
  findings: (params?: { scan_id?: string; severity?: string; result?: string }) =>
    api.get<Finding[]>("/api/findings", { params }),
  uploadConfig: (file: File, framework: string, hostname?: string) => {
    const form = new FormData();
    form.append("file", file);
    form.append("framework", framework);
    if (hostname) form.append("hostname", hostname);
    return api.post<ScanDetail>("/api/scans/upload", form);
  },
  
  // Training Center Layer 3+
  pendingMappings: () => api.get<CommandMapping[]>("/api/training/pending"),
  approvedMappings: () => api.get<CommandMapping[]>("/api/training/approved"),
  reviewMapping: (id: string, payload: { action: "approve" | "correct" | "reject", normalized_facts?: Record<string, any>, correction_reason?: string }) =>
    api.post(`/api/training/${id}/review`, payload),
  datasets: () => api.get<DatasetVersion[]>("/api/ai/datasets"),
  createDataset: (versionLabel: string) => api.post<DatasetVersion>(`/api/ai/datasets?version_label=${encodeURIComponent(versionLabel)}`),
  trainingJobs: () => api.get<TrainingJob[]>("/api/ai/training/jobs"),
  createTrainingJob: (datasetVersionId: string) => api.post<TrainingJob>("/api/ai/training/jobs", { dataset_version_id: datasetVersionId }),
  runTrainingJob: (id: string) => api.post<TrainingJob>(`/api/ai/training/jobs/${id}/run`),
  registryModels: () => api.get<ModelRegistryEntry[]>("/api/ai/registry/models"),
  approveModel: (id: string) => api.post<ModelRegistryEntry>(`/api/ai/registry/models/${id}/approve`),
  rejectModel: (id: string) => api.post<ModelRegistryEntry>(`/api/ai/registry/models/${id}/reject`),
  promoteModel: (id: string) => api.post<ModelRegistryEntry>(`/api/ai/registry/models/${id}/promote`),
  rollbackModel: (id: string) => api.post<ModelRegistryEntry>(`/api/ai/registry/models/${id}/rollback`),

  reportUrl: (scanId: string, fmt: "pdf" | "json" | "csv") =>
    `${api.defaults.baseURL}/api/reports/${scanId}/${fmt}`,
  evidenceList: (scanId?: string) => api.get<EvidenceRecord[]>("/api/evidence", { params: scanId ? { scan_id: scanId } : undefined }),
  evidenceDetail: (evidenceId: string) => api.get<EvidenceDetail>(`/api/evidence/${evidenceId}`),
  evidenceVerify: (evidenceId: string) => api.post<VerifyResult>(`/api/evidence/${evidenceId}/verify`),
  evidenceSimulateTamper: (evidenceId: string) => api.post<EvidenceDetail>(`/api/evidence/${evidenceId}/simulate-tamper`),
  evidenceRestore: (evidenceId: string) => api.post<EvidenceDetail>(`/api/evidence/${evidenceId}/restore`),
  topology: () => api.get<Topology>("/api/topology"),
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
  deviceComplianceHistory: (deviceId: string) =>
    api.get<CompliancePostureHistory>(`/api/devices/${deviceId}/compliance/history`),
  auditDeviceViaGateway: (deviceId: string) => api.post(`/api/devices/${deviceId}/audit`),
  gatewayGetFacts: (deviceId: string, protocol?: string) =>
    api.post(`/api/devices/${deviceId}/gateway-get-facts`, { protocol }),
  gatewayGetInterfaces: (deviceId: string, protocol?: string) =>
    api.post(`/api/devices/${deviceId}/gateway-get-interfaces`, { protocol }),
  gatewaySupportedOperations: () => api.get<{ read_only_operations: string[] }>("/api/devices/gateway/operations"),

  schedules: () => api.get<AuditSchedule[]>("/api/schedules"),
  createSchedule: (payload: {
    name: string;
    scope: { all?: boolean; device_ids?: string[] };
    frequency: string;
    enabled: boolean;
    framework: string;
  }) => api.post<AuditSchedule>("/api/schedules", payload),
  updateSchedule: (id: string, payload: Partial<{ name: string; enabled: boolean; frequency: string; scope: unknown; framework: string }>) =>
    api.patch<AuditSchedule>(`/api/schedules/${id}`, payload),
  deleteSchedule: (id: string) => api.delete(`/api/schedules/${id}`),

  configSearch: (q: string, deep = true) =>
    api.get<ConfigSearchResult>("/api/config-search", { params: { q, deep } }),
  runScheduleNow: (id: string) => api.post(`/api/schedules/${id}/run`),

  alerts: (params?: { status?: string; severity?: string; category?: string }) =>
    api.get<{ count: number; alerts: Alert[] }>("/api/alerts", { params }),
  acknowledgeAlert: (id: string) => api.post<Alert>(`/api/alerts/${id}/acknowledge`),

  aiModels: () => api.get<AIModelsInfo>("/api/ai/models"),
  device: (id: string) => api.get<Device>(`/api/devices/${id}`),
  deviceScans: (deviceId: string) => api.get<Scan[]>("/api/scans", { params: { device_id: deviceId } }),

  changeRequests: (params?: { status?: string; device_id?: string }) =>
    api.get<{ count: number; change_requests: ChangeRequest[] }>("/api/change-requests", { params }),
  changeRequest: (id: string) => api.get<ChangeRequest>(`/api/change-requests/${id}`),
  createChangeRequest: (deviceId: string, proposedConfig: string) =>
    api.post<ChangeRequest>("/api/change-requests", { device_id: deviceId, proposed_config: proposedConfig }),
  approveChangeRequest: (id: string) => api.post<ChangeRequest>(`/api/change-requests/${id}/approve`),
  rejectChangeRequest: (id: string, reason: string) =>
    api.post<ChangeRequest>(`/api/change-requests/${id}/reject`, { reason }),
  deployChangeRequest: (id: string, opts: { transport?: string; credential_ref_id?: string } = {}) =>
    api.post<DeploymentRecord>(`/api/change-requests/${id}/deploy`, opts),
  changeRequestDeployments: (id: string) =>
    api.get<{ count: number; deployments: DeploymentRecord[] }>(`/api/change-requests/${id}/deployments`),

  // GNS3
  gns3Servers: () => api.get("/api/gns3/servers"),
  addGns3Server: (data: any) => api.post("/api/gns3/servers", data),
  gns3Labs: (serverId: string) => api.get(`/api/gns3/servers/${serverId}/labs`),
  importGns3Lab: (serverId: string, labId: string) => api.post(`/api/gns3/servers/${serverId}/labs/${labId}/import`),
};