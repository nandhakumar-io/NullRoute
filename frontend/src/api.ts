import axios from "axios";

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || "http://localhost:8000",
});

export interface Device {
  id: string;
  hostname: string | null;
  vendor: string | null;
  model: string | null;
  os: string | null;
  version: string | null;
  serial_number: string | null;
  management_address?: string | null;
  collection_status?: string | null;
  last_collected_at?: string | null;
  last_collection_error?: string | null;
  last_collection_transport?: string | null;
  last_scan_at: string | null;
  last_compliance_score: number | null;
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

export const endpoints = {
  dashboard: () => api.get<DashboardStats>("/api/dashboard"),
  dashboardMetrics: (range: DashboardRange) =>
    api.get<DashboardMetrics>("/api/dashboard/metrics", { params: { range } }),
  auditLog: (params?: {
    action?: string; object_type?: string; object_id?: string;
    username?: string; result?: string; limit?: number; offset?: number;
  }) => api.get<AuditLogEntry[]>("/api/audit-log", { params }),
  devices: () => api.get<Device[]>("/api/devices"),
  scans: () => api.get<Scan[]>("/api/scans"),
  scan: (id: string) => api.get<ScanDetail>(`/api/scans/${id}`),
  rerunScan: (id: string) => api.post<ScanDetail>(`/api/scans/${id}/rerun`),
  batfishAnalysis: (scanId: string) => api.get<BatfishAnalysis>(`/api/scans/${scanId}/batfish`),
  snapshotDiff: (scanId: string) => api.get<SnapshotDiff>(`/api/scans/${scanId}/snapshot-diff`),
  opaAnalysis: (scanId: string) => api.get<OpaAnalysis>(`/api/scans/${scanId}/opa`),
  aiAnalysis: (scanId: string) => api.get<ScanAIAnalysis>(`/api/scans/${scanId}/ai`),
  aiHealth: () => api.get<AIHealth>("/api/ai/health"),
  findings: (params?: { scan_id?: string; severity?: string; result?: string }) =>
    api.get<Finding[]>("/api/findings", { params }),
  uploadConfig: (file: File, framework: string, hostname?: string) => {
    const form = new FormData();
    form.append("file", file);
    form.append("framework", framework);
    if (hostname) form.append("hostname", hostname);
    return api.post<ScanDetail>("/api/scans/upload", form, {
      headers: { "Content-Type": "multipart/form-data" },
    });
  },
  pendingMappings: () => api.get<CommandMapping[]>("/api/training/pending"),
  approvedMappings: () => api.get<CommandMapping[]>("/api/training/approved"),
  reviewMapping: (id: string, action: "approve" | "reject", normalized_parameter?: string) =>
    api.post(`/api/training/${id}/review`, { action, normalized_parameter, reviewer: "admin" }),
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

  // Phase 11 -- configuration drift
  drift: (params?: { security_impacting?: boolean }) =>
    api.get<{ count: number; events: DriftEvent[] }>("/api/drift", { params }),
  deviceDrift: (deviceId: string) =>
    api.get<{ count: number; events: DriftEvent[] }>(`/api/devices/${deviceId}/drift`),

  // Phase 12 -- scheduled audits
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
  runScheduleNow: (id: string) => api.post(`/api/schedules/${id}/run`),

  // Phase 13 -- alerts
  alerts: (params?: { status?: string; severity?: string; category?: string }) =>
    api.get<{ count: number; alerts: Alert[] }>("/api/alerts", { params }),
  acknowledgeAlert: (id: string) => api.post<Alert>(`/api/alerts/${id}/acknowledge`),

  // AI Analysis page -- Phase 1/2/19
  aiModels: () => api.get<AIModelsInfo>("/api/ai/models"),
  device: (id: string) => api.get<Device>(`/api/devices/${id}`),
  deviceScans: (deviceId: string) => api.get<Scan[]>("/api/scans", { params: { device_id: deviceId } }),

  // Phase 14 -- change requests
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
};