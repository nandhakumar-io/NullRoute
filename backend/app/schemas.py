from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class DeviceOut(BaseModel):
    id: str
    name: Optional[str] = None
    hostname: Optional[str]
    vendor: Optional[str]
    model: Optional[str]
    os: Optional[str]
    version: Optional[str]
    serial_number: Optional[str]
    management_address: Optional[str] = None
    site: Optional[str] = None
    environment: Optional[str] = None
    protocol: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    enabled: bool = True
    collection_status: Optional[str] = None
    last_collected_at: Optional[datetime] = None
    last_collection_error: Optional[str] = None
    last_collection_transport: Optional[str] = None
    last_scan_at: Optional[datetime]
    last_compliance_score: Optional[float]
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class DeviceCreate(BaseModel):
    name: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    os: Optional[str] = None
    version: Optional[str] = None
    serial_number: Optional[str] = None
    management_address: Optional[str] = None
    site: Optional[str] = None
    environment: Optional[str] = None
    protocol: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    enabled: bool = True


class DeviceUpdate(BaseModel):
    """All fields optional -- PATCH semantics. Fields intentionally absent:
    tenant_id (never client-controlled, see get_current_tenant), credential
    material (see routers/credentials.py -- references only), and
    collection_status/last_* fields (system-written, not user-editable)."""
    name: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    os: Optional[str] = None
    version: Optional[str] = None
    serial_number: Optional[str] = None
    management_address: Optional[str] = None
    site: Optional[str] = None
    environment: Optional[str] = None
    protocol: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    enabled: Optional[bool] = None


class DeviceListOut(BaseModel):
    items: List[DeviceOut]
    total: int
    limit: int
    offset: int


class BulkDeviceRequest(BaseModel):
    device_ids: List[str]


class BulkDeviceResult(BaseModel):
    requested: int
    affected: int
    device_ids: List[str]


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
    evidence_line: Optional[str]
    remediation: Optional[str]

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
    scan_id: str
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


class MappingReviewIn(BaseModel):
    action: str  # "approve", "correct", or "reject"
    normalized_facts: Optional[Dict[str, Any]] = None
    correction_reason: Optional[str] = None
    reviewer: str = "admin"


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
    enabled: bool = True
    framework: str = "ALL"


class ScheduleUpdate(BaseModel):
    name: Optional[str] = None
    scope: Optional[Dict[str, Any]] = None
    frequency: Optional[str] = None
    enabled: Optional[bool] = None
    framework: Optional[str] = None


class ScheduleOut(BaseModel):
    id: str
    tenant_id: str
    name: str
    scope: Dict[str, Any]
    frequency: str
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


class NetworkScanJobCreate(BaseModel):
    name: Optional[str] = None
    # Either/both may be set: run_discovery over target_cidr to find new
    # devices, and/or explicit device_ids to scan directly. At least one
    # of the two must resolve to something (validated by the router).
    run_discovery: bool = False
    target_cidr: Optional[str] = None
    discovery_ports: Optional[str] = None
    device_ids: Optional[List[str]] = None
    framework: str = "ALL"
    include_batfish: bool = True


class NetworkScanJobOut(BaseModel):
    id: str
    tenant_id: str
    name: Optional[str] = None
    target_cidr: Optional[str] = None
    run_discovery: bool
    framework: str
    include_batfish: bool
    status: str
    stages: Dict[str, Any]
    discovered_hosts: Optional[List[Dict[str, Any]]] = None
    resolved_device_ids: Optional[List[str]] = None
    scan_ids: Optional[List[str]] = None
    device_results: Optional[List[Dict[str, Any]]] = None
    error: Optional[str] = None
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class AuditLogOut(BaseModel):
    id: str
    tenant_id: Optional[str] = None
    username: Optional[str] = None
    user_id: Optional[str] = None
    action: Optional[str] = None
    object_type: Optional[str] = None
    object_id: Optional[str] = None
    source_ip: Optional[str] = None
    old_value: Optional[Dict[str, Any]] = None
    new_value: Optional[Dict[str, Any]] = None
    result: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class DashboardMetricPoint(BaseModel):
    bucket: str
    compliance_score: Optional[float] = None
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    open_findings: int
    resolved_findings: int


class DashboardMetricsOut(BaseModel):
    range: str
    compliance_score: float
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    open_findings: int
    resolved_findings: int
    timeseries: List[DashboardMetricPoint]