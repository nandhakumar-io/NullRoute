from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class DeviceOut(BaseModel):
    id: str
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    os: Optional[str] = None
    version: Optional[str] = None
    serial_number: Optional[str] = None
    management_address: Optional[str] = None
    collection_status: Optional[str] = None
    last_collected_at: Optional[datetime] = None
    last_collection_error: Optional[str] = None
    last_collection_transport: Optional[str] = None
    last_scan_at: Optional[datetime] = None
    last_compliance_score: Optional[float] = None
    # Device inventory / management fields
    name: Optional[str] = None
    site: Optional[str] = None
    environment: Optional[str] = None
    protocol: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    enabled: bool = True

    class Config:
        from_attributes = True


class DeviceCreate(BaseModel):
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    os: Optional[str] = None
    version: Optional[str] = None
    serial_number: Optional[str] = None
    management_address: Optional[str] = None
    name: Optional[str] = None
    site: Optional[str] = None
    environment: Optional[str] = None
    protocol: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    enabled: Optional[bool] = None

class DeviceUpdate(BaseModel):
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    os: Optional[str] = None
    version: Optional[str] = None
    serial_number: Optional[str] = None
    management_address: Optional[str] = None
    name: Optional[str] = None
    site: Optional[str] = None
    environment: Optional[str] = None
    protocol: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    enabled: Optional[bool] = None

class FindingOut(BaseModel):
    id: str
    scan_id: str
    framework: str
    control_id: str
    title: str
    severity: str
    expected_value: Optional[str]
    actual_value: Optional[str]
    result: str
    parameter: str
    reason: Optional[str] = None
    policy_version: Optional[str] = None
    vendor: Optional[str] = None
    evidence_line: Optional[str]
    remediation: Optional[str]
    presentation_result: Optional[str] = None  # Phase 16: result OR "EXCEPTION_ACCEPTED"; never replaces `result`
    created_at: Optional[datetime] = None  # Phase 1 security-audit UI: date filter + Finding Detail timestamp

    class Config:
        from_attributes = True


class ScanOut(BaseModel):
    id: str
    device_id: str
    status: str
    framework: str
    compliance_score: Optional[float]
    error: Optional[str]
    opa_decision: Optional[str] = None
    opa_policy_version: Optional[str] = None
    opa_decision_id: Optional[str] = None
    batfish_status: Optional[str] = None
    risk_score: Optional[int] = None
    risk_level: Optional[str] = None
    final_decision: Optional[str] = None
    final_reason: Optional[str] = None
    evidence_id: Optional[str] = None
    source_filename: Optional[str] = None
    control_state: Optional[str] = None
    pipeline_stage: Optional[str] = None
    paused_at: Optional[datetime] = None
    resumed_at: Optional[datetime] = None
    stopped_at: Optional[datetime] = None
    # Per-stage duration data (see services/pipeline.py _checkpoint).
    # Dict keyed by stage name: {started_at, completed_at, duration_ms}.
    stage_timings: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ScanDetailOut(ScanOut):
    baseline_json: Optional[Dict[str, Any]]
    findings: List[FindingOut] = []


class CommandMappingOut(BaseModel):
    id: str
    vendor: str
    raw_command_pattern: str
    normalized_parameter: str
    example_value: Optional[str]
    ai_suggested_meaning: Optional[str]
    confidence: float
    status: str

    class Config:
        from_attributes = True


class EvidenceOut(BaseModel):
    evidence_id: str
    scan_id: Optional[str] = None
    device_id: Optional[str] = None
    tenant_id: Optional[str] = None
    event_type: Optional[str] = None
    evidence_hash: str
    final_decision: Optional[str] = None
    opa_decision_id: Optional[str] = None
    fabric_status: Optional[str] = None
    fabric_tx_id: Optional[str] = None
    fabric_block_number: Optional[int] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class EvidenceDetailOut(EvidenceOut):
    evidence_json: dict


class VerifyResultOut(BaseModel):
    match: bool
    stored_hash: str
    calculated_hash: str
    status: str
    # On-chain half of verification (section 17). Populated only when
    # FABRIC_ENABLED=true and the gateway responded; otherwise both stay
    # None and the UI shows off-chain-only verification.
    fabric_checked: bool = False
    fabric_match: Optional[bool] = None
    fabric_status: Optional[str] = None


class ReportArtifactOut(BaseModel):
    """A previously archived report (see ReportArtifact / report_artifacts
    table). `has_stored_copy` tells the UI whether the original bytes can
    still be downloaded (object_key set) vs. only the hash/size metadata
    survives (MinIO write failed or was disabled at generation time)."""
    id: str
    scan_id: str
    format: str
    sha256: str
    size_bytes: int
    created_at: Optional[datetime] = None
    has_stored_copy: bool = False

    class Config:
        from_attributes = True


class ReportVerifyResultOut(BaseModel):
    """Result of uploading a previously-downloaded report for tamper
    verification (routers/report_verification.py). Mirrors the shape of
    VerifyResultOut above: an off-chain hash comparison against our own
    archived copy, plus an on-chain cross-check against the Fabric-anchored
    evidence hash for the same scan when available."""
    status: str  # VERIFIED | TAMPERED | UNKNOWN_REPORT
    match: bool
    calculated_hash: str
    scan_id: Optional[str] = None
    format: Optional[str] = None
    artifact: Optional[ReportArtifactOut] = None
    fabric_checked: bool = False
    fabric_match: Optional[bool] = None
    fabric_status: Optional[str] = None
    downloadable: bool = False
    message: str


class TrainingExampleOut(BaseModel):
    """A single HITL-reviewed example awaiting the second, dataset-level
    human approval gate (validation_status PENDING -> VALIDATED/EXCLUDED)
    before dataset_service.create_dataset_version() will include it."""
    id: str
    vendor: Optional[str]
    intent: Optional[str]
    raw_config_redacted: str
    normalized_facts: dict
    human_action: str  # APPROVED / CORRECTED / REJECTED
    correction_reason: Optional[str]
    created_by: str
    created_at: Optional[datetime] = None
    dataset_version: Optional[str] = None
    validation_status: str

    class Config:
        from_attributes = True


class MappingReviewIn(BaseModel):
    action: str  # "approve", "correct", or "reject"
    normalized_parameter: Optional[str] = None  # allow admin correction
    normalized_facts: Optional[Dict[str, Any]] = None
    correction_reason: Optional[str] = None
    reviewer: str = "admin"


class ComplianceMatrixRow(BaseModel):
    control_id: str
    title: str
    vendors: Dict[str, Optional[float]]

class ComplianceMatrix(BaseModel):
    vendors: List[str]
    rows: List[ComplianceMatrixRow]

class DashboardStats(BaseModel):
    total_devices: int
    devices_scanned: int
    overall_compliance_score: float
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    framework_scores: Dict[str, float]
    recent_scans: List[ScanOut]
    pending_ai_mappings: int
    # Section 32 additions: OPA/Batfish/risk/evidence/Fabric metrics.
    opa_violations: int = 0
    batfish_violations: int = 0
    unknown_configurations: int = 0
    high_risk_devices: int = 0
    evidence_anchors: int = 0
    fabric_failures: int = 0
    integrity_failures: int = 0
    opa_vs_batfish: Dict[str, int] = {}
    risk_distribution: Dict[str, int] = {}
    evidence_anchoring_status: Dict[str, int] = {}
    # Part 2 §A/§F additions: REVIEW/UNVERIFIED counts and a per-vendor
    # score breakdown (the multi-vendor proof from §9/§14 needs somewhere
    # to actually show "same control, same result across vendors" at the
    # fleet level, not just in a single scan's findings).
    review_scans: int = 0
    unverified_findings: int = 0
    vendor_scores: Dict[str, float] = {}
    # Phase 1 security-audit dashboard (SIH26155): two counts the existing
    # metrics didn't expose on their own -- total findings across all
    # results (not just the FAIL-only severity buckets above) and the
    # tenant-wide configuration-drift count already tracked by DriftEvent
    # (see routers/drift.py) surfaced here too so the dashboard doesn't
    # need a second round-trip just to show the headline number.
    total_findings: int = 0
    configuration_drift_count: int = 0


# ---------------------------------------------------------------------------
# Phase 12 -- scheduled audits (AuditSchedule). Mirrors app/models/db.py's
# AuditSchedule columns; consumed by app/routers/schedules.py and
# app/services/scheduling_service.to_dict().
# ---------------------------------------------------------------------------


class ScheduleCreate(BaseModel):
    name: str
    # {"all": true} or {"device_ids": [...]}; validated against
    # scheduling_service.VALID_FREQUENCIES by the router, not here, so the
    # 400 error message can reference the canonical list in one place.
    scope: Dict[str, Any]
    frequency: str = "manual"  # manual|hourly|daily|weekly
    time_of_day: Optional[str] = None  # "HH:MM", 24h UTC; anchors daily/weekly runs to a clock time
    enabled: bool = True
    framework: str = "ALL"


class ScheduleUpdate(BaseModel):
    name: Optional[str] = None
    scope: Optional[Dict[str, Any]] = None
    frequency: Optional[str] = None
    time_of_day: Optional[str] = None
    enabled: Optional[bool] = None
    framework: Optional[str] = None


class ScheduleOut(BaseModel):
    id: str
    tenant_id: str
    name: str
    scope: Dict[str, Any]
    frequency: str
    time_of_day: Optional[str] = None
    enabled: bool
    framework: str
    created_by: Optional[str] = None
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    last_run_status: Optional[str] = None
    last_run_detail: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class DashboardMetricPoint(BaseModel):
    bucket: str
    compliance_score: Optional[float]
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    open_findings: int
    resolved_findings: int

class DashboardMetrics(BaseModel):
    range: str
    compliance_score: float
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    open_findings: int
    resolved_findings: int
    timeseries: List[DashboardMetricPoint]

class NetworkScanJobCreate(BaseModel):
    name: Optional[str] = None  # auto-generated if omitted
    run_discovery: bool = False
    target_cidr: Optional[str] = None
    discovery_ports: Optional[List[int]] = None
    device_ids: Optional[List[str]] = None
    framework: str = "ALL"
    include_batfish: bool = False

class NetworkScanJobOut(BaseModel):
    id: str
    tenant_id: str
    name: str
    run_discovery: bool
    target_cidr: Optional[str] = None
    discovery_ports: Optional[List[int]] = None
    requested_device_ids: List[str]
    framework: str
    include_batfish: bool
    status: str
    stages: Dict[str, Any]
    created_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    result_summary: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True

class AuditLogOut(BaseModel):
    # Every column except id/created_at is nullable in the DB (rows written by
    # audit_service.record_from_user(object_id=None), record_event() without a
    # hostname, workers, legacy writers...). A required `str` here made ONE null
    # `resource` 500 the whole /api/audit-log list (ResponseValidationError).
    id: str
    actor: Optional[str] = None
    action: Optional[str] = None
    resource: Optional[str] = None
    details: Optional[Any] = None
    created_at: Optional[datetime] = None
    tenant_id: Optional[str] = None
    user_id: Optional[str] = None

    # Section 12 columns -- populated by app.services.audit_service and
    # consumed directly by the Audit Log page's Who/Object/Source IP/Result
    # columns.
    username: Optional[str] = None
    object_type: Optional[str] = None
    object_id: Optional[str] = None
    source_ip: Optional[str] = None
    result: Optional[str] = None
    old_value: Optional[Any] = None
    new_value: Optional[Any] = None

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Phase 1 trained-AI classification/decision pipeline contracts. This is a
# SEPARATE concern from app/ai/normalize.py (the Ollama/RAG LLM normalizer
# used for unknown config lines during parsing); this section wraps the
# trained DistilBERT intent classifier and all-MiniLM-L6-v2 semantic
# embedding model behind a hybrid decision engine.
#
# Hard rule (see decision_engine.py): this section NEVER produces a
# compliance PASS/FAIL. It only identifies/interprets configuration intent
# and flags UNKNOWN/disagreement for human review.
#
# NOTE: nothing in this codebase currently imports these from app.schemas
# (app.ai.schemas is the module routers actually use for AI contracts) --
# kept here only because an earlier edit accidentally overwrote this whole
# file with just this section, wiping the ~20 classes above. Restored those
# and kept this section too rather than deleting content that might be
# relied on elsewhere.
# ---------------------------------------------------------------------------
from pydantic import ConfigDict, Field

UNKNOWN_INTENT = "UNKNOWN"


class ClassifierResult(BaseModel):
    intent: str
    confidence: float
    model_version: str
    model_config = ConfigDict(protected_namespaces=())


class EmbeddingMatch(BaseModel):
    nearest_intent: str
    nearest_vendor: Optional[str] = None
    similarity: float


class AIAnalysisResult(BaseModel):
    """Full hybrid decision output for one raw configuration line/command."""

    raw_command: str
    intent: str
    classifier_confidence: float
    semantic_similarity: float
    nearest_intent: str
    nearest_vendor: Optional[str] = None
    models_agree: bool
    decision: str  # KNOWN_CANDIDATE | UNKNOWN | REQUIRES_REVIEW
    requires_review: bool
    model_version: str
    inference_latency_ms: float
    reason: str
    model_config = ConfigDict(protected_namespaces=())


class AIHealth(BaseModel):
    ai_enabled: bool
    classifier_loaded: bool
    embedder_loaded: bool
    classifier_backend: str
    embedder_backend: str
    model_version: str
    reference_dataset: Optional[str] = None
    reference_examples: int = 0
    model_config = ConfigDict(protected_namespaces=())


class AIModelInfo(BaseModel):
    component: str
    path: Optional[str] = None
    backend: str
    loaded: bool
    version: str


class AIModelsOut(BaseModel):
    models: List[AIModelInfo]
    thresholds: dict = Field(default_factory=dict)


class ConfidenceTrendPoint(BaseModel):
    """One day's aggregate classifier behavior, for the reviewer-facing
    'is the model drifting' chart. Computed purely from AIAnalysis rows
    already recorded during scans — never a synthetic/estimated value."""

    date: str  # YYYY-MM-DD
    analysis_count: int
    avg_classifier_confidence: float
    avg_semantic_similarity: float
    requires_review_rate: float  # 0-1, share of that day's analyses flagged for review
    below_threshold_rate: float  # 0-1, share below the configured confidence threshold


class ModelHistoryPoint(BaseModel):
    """One model-registry lifecycle event, for correlating a confidence dip
    on the trend chart with an actual retrain/promotion."""

    model_id: str
    model_version: Optional[str] = None
    status: str
    accuracy: Optional[float] = None
    dataset_version: str
    training_timestamp: Optional[str] = None
    model_config = ConfigDict(protected_namespaces=())


class ConfidenceTrendOut(BaseModel):
    current_model_version: str
    model_config = ConfigDict(protected_namespaces=())
    confidence_threshold: float
    # True once the most recent window's average confidence has dropped
    # more than `drift_alert_delta` below the earliest window in range —
    # a plain-language drift signal, not just a chart the reviewer has to
    # eyeball.
    drift_detected: bool
    drift_alert_delta: float = 0.10
    points: List[ConfidenceTrendPoint]
    model_history: List[ModelHistoryPoint]