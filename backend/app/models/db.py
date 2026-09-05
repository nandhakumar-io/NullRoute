"""SQLAlchemy ORM models — the system of record.

Runs against PostgreSQL + pgvector in production (docker-compose), but the
same models work against SQLite for local/offline development, which is what
the bundled `make dev` / `uvicorn app.main:app` path uses when POSTGRES is
unreachable (see app/db.py).
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (JSON, Boolean, Column, DateTime, Float, ForeignKey,
                         Integer, String, Text)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def gen_uuid() -> str:
    return str(uuid.uuid4())


class Tenant(Base):
    __tablename__ = "tenants"
    id = Column(String, primary_key=True, default=gen_uuid)
    name = Column(String, nullable=False, unique=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class Device(Base):
    __tablename__ = "devices"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    hostname = Column(String)
    vendor = Column(String)
    model = Column(String)
    os = Column(String)
    version = Column(String)
    serial_number = Column(String)
    last_scan_at = Column(DateTime, nullable=True)
    last_compliance_score = Column(Float, nullable=True)
    management_address = Column(String, nullable=True)  # Phase 7: host/IP collectors connect to
    collection_status = Column(String, nullable=True)  # NEVER_COLLECTED/SUCCESS/FAILED/IN_PROGRESS
    last_collected_at = Column(DateTime, nullable=True)
    last_collection_error = Column(Text, nullable=True)
    last_collection_transport = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship("Scan", back_populates="device")


class Scan(Base):
    __tablename__ = "scans"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    status = Column(String, default="uploaded")  # uploaded/parsed/normalized/evaluated/completed/failed
    framework = Column(String, default="CIS")
    raw_config_path = Column(String)  # MinIO object key
    raw_config_hash = Column(String)
    parsed_json = Column(JSON, nullable=True)
    baseline_json = Column(JSON, nullable=True)
    compliance_score = Column(Float, nullable=True)
    error = Column(Text, nullable=True)

    # OPA / risk / correlation outputs (see services/opa_service.py,
    # risk_engine.py, change_validation_service.py). final_decision is the
    # authoritative PASS/REVIEW/BLOCK verdict for the scan; `status` above
    # remains the pipeline-stage tracker.
    opa_decision = Column(String, nullable=True)  # PASS/REVIEW/BLOCK/OPA_UNAVAILABLE
    opa_policy_version = Column(String, nullable=True)
    opa_decision_id = Column(String, nullable=True)
    batfish_status = Column(String, default="NOT_INTEGRATED")  # see change_validation_service.VALID_BATFISH_STATUSES
    risk_score = Column(Integer, nullable=True)
    risk_level = Column(String, nullable=True)
    final_decision = Column(String, nullable=True)  # PASS/REVIEW/BLOCK
    final_reason = Column(Text, nullable=True)
    evidence_id = Column(String, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    device = relationship("Device", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")


class Finding(Base):
    __tablename__ = "findings"
    id = Column(String, primary_key=True, default=gen_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    framework = Column(String)
    control_id = Column(String)
    title = Column(String)
    severity = Column(String)  # CRITICAL/HIGH/MEDIUM/LOW
    expected_value = Column(String)
    actual_value = Column(String)
    result = Column(String)  # PASS/FAIL/NOT_APPLICABLE
    parameter = Column(String)
    evidence_line = Column(Text)
    remediation = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="findings")


class CommandMapping(Base):
    """Knowledge base: raw command pattern -> normalized security parameter.
    Populated by human-in-the-loop training; retrieved via pgvector similarity
    search for future unknown commands.

    tenant_id scopes the learned mapping to the tenant whose device produced
    it (Phase 5) — a training mapping learned for one tenant's fleet is never
    exposed to another tenant's pipeline, even for the same vendor."""
    __tablename__ = "command_mappings"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=True, index=True)
    vendor = Column(String)
    raw_command_pattern = Column(Text)
    normalized_parameter = Column(String)
    example_value = Column(String)
    ai_suggested_meaning = Column(Text)
    confidence = Column(Float)
    status = Column(String, default="pending")  # pending/approved/rejected
    embedding = Column(JSON, nullable=True)  # stored as list[float]; pgvector column in real PG migration
    model_version = Column(String, nullable=True)
    reviewed_by = Column(String, nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class OPAAnalysis(Base):
    """One row per OPA evaluation of a scan (kept even across reruns —
    historical evidence is never overwritten, per RULE 15)."""
    __tablename__ = "opa_analyses"
    id = Column(String, primary_key=True, default=gen_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    policy_version = Column(String)
    decision = Column(String)  # PASS/REVIEW/BLOCK/OPA_UNAVAILABLE
    decision_id = Column(String)
    source = Column(String, default="opa")  # "opa" | "fail_closed"
    result_json = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class BatfishAnalysis(Base):
    """One row per Batfish behavioral-analysis run of a scan (kept even
    across reruns — historical evidence is never overwritten, per RULE 15).
    `status` is always one of BATFISH_PASS/BATFISH_FAIL/BATFISH_UNSUPPORTED/
    BATFISH_UNAVAILABLE/BATFISH_ERROR/NOT_INTEGRATED — never silently
    coerced into a PASS (RULE 13)."""
    __tablename__ = "batfish_analyses"
    id = Column(String, primary_key=True, default=gen_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    network_name = Column(String, nullable=True)
    snapshot_name = Column(String, nullable=True)
    status = Column(String, default="NOT_INTEGRATED")
    critical_violation = Column(Boolean, default=False)
    init_issues = Column(JSON, nullable=True)
    result_json = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class EvidenceRecord(Base):
    """Off-chain evidence store (see services/evidence_service.py). Once
    fabric_service.py is implemented, `fabric_status`/`fabric_tx_id` move
    from placeholder values to real Fabric Gateway responses without any
    schema change."""
    __tablename__ = "evidence_records"
    id = Column(String, primary_key=True, default=gen_uuid)
    evidence_id = Column(String, unique=True, nullable=False)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    device_id = Column(String)
    tenant_id = Column(String, index=True)
    event_type = Column(String, nullable=True)  # e.g. "compliance_scan" -- see services/evidence_service.py
    evidence_json = Column(JSON, nullable=False)
    evidence_hash = Column(String, nullable=False)
    evidence_object_key = Column(String, nullable=True)  # MinIO key, Phase 8 (see services/minio_service.py)
    opa_decision_id = Column(String, nullable=True)
    final_decision = Column(String)
    fabric_status = Column(String, default="NOT_ANCHORED")  # NOT_ANCHORED/ANCHORED/FABRIC_UNAVAILABLE
    fabric_tx_id = Column(String, nullable=True)
    fabric_block_number = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class DeviceCredentialRef(Base):
    """Reference-only row (Phase 6). The actual secret material (password,
    SSH key, SNMP community string, API token, etc.) lives ONLY in OpenBao
    under a path derived from `credential_ref`. PostgreSQL never stores the
    secret itself -- only enough metadata to look it up and rotate it.

    See app/services/openbao_service.py for the get/store/rotate/delete
    operations that actually touch secret material, and RULE 6 (never store
    credentials in PostgreSQL, MinIO, NATS, logs, evidence, reports, or
    Fabric)."""
    __tablename__ = "device_credential_refs"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False, index=True)
    credential_ref = Column(String, nullable=False, unique=True)  # OpenBao secret path/key, not the secret
    credential_type = Column(String, nullable=False)  # ssh_password/ssh_key/netconf/restconf_token/snmp_community
    created_by = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    rotated_at = Column(DateTime, nullable=True)


class AIAnalysis(Base):
    """One row per trained-AI (DistilBERT classifier + MiniLM embedding)
    interpretation of a raw configuration command during a scan (Phase 1/2).

    This is distinct from CommandMapping (the Ollama/RAG LLM normalization
    knowledge base) — AIAnalysis records the hybrid-decision-engine output,
    never a compliance PASS/FAIL (see app/ai/decision_engine.py).
    Historical rows are never overwritten (RULE 15)."""
    __tablename__ = "ai_analyses"
    id = Column(String, primary_key=True, default=gen_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    device_id = Column(String, ForeignKey("devices.id"), nullable=True)
    tenant_id = Column(String, nullable=True, index=True)
    raw_command_hash = Column(String, nullable=False)
    intent = Column(String, nullable=False)
    classifier_confidence = Column(Float, nullable=False)
    semantic_similarity = Column(Float, nullable=False)
    nearest_intent = Column(String, nullable=True)
    nearest_vendor = Column(String, nullable=True)
    models_agree = Column(Boolean, default=False)
    decision = Column(String, nullable=False)  # KNOWN_CANDIDATE/UNKNOWN/REQUIRES_REVIEW
    requires_review = Column(Boolean, default=False)
    reason = Column(Text, nullable=True)
    model_version = Column(String, nullable=True)
    inference_latency_ms = Column(Float, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=True, index=True)
    actor = Column(String)
    action = Column(String)
    resource = Column(String)
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class ReportArtifact(Base):
    """Reference row for a generated PDF/JSON/CSV report (Phase 8/20).
    Reports are built on demand (see routers/compliance.py::get_report) and
    archived best-effort to MinIO; this row is written regardless of
    whether the MinIO upload succeeded (`object_key`/`object_bucket` are
    nullable) so the sha256 + size are always recorded even during a
    storage outage. Never contains the report bytes themselves."""
    __tablename__ = "report_artifacts"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False, index=True)
    format = Column(String, nullable=False)  # pdf/json/csv
    object_key = Column(String, nullable=True)  # MinIO key; null if the upload failed/was disabled
    object_bucket = Column(String, nullable=True)
    sha256 = Column(String, nullable=False)
    size_bytes = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

# ---------------------------------------------------------------------------
# Phase 9 -- inventory/topology. Populated best-effort from raw configuration
# text by services/topology_extractor.py, run once per successful collection
# (see services/pipeline.py). Every row here is data literally present in a
# device's raw config -- never inferred/guessed (RULE 10). Rows are replaced
# (not appended) on each new collection for a device, since these represent
# CURRENT observed state, not a history (immutable history lives in Scan/
# EvidenceRecord instead).
# ---------------------------------------------------------------------------

class NetworkInterface(Base):
    __tablename__ = "network_interfaces"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False, index=True)
    name = Column(String, nullable=False)
    description = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    subnet_mask = Column(String, nullable=True)
    vlan = Column(String, nullable=True)
    vrf = Column(String, nullable=True)
    admin_state = Column(String, nullable=True)  # up/down, only when explicitly stated in the config
    scan_id = Column(String, ForeignKey("scans.id"), nullable=True)  # scan that produced this snapshot
    created_at = Column(DateTime, default=datetime.utcnow)


class VLAN(Base):
    __tablename__ = "vlans"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False, index=True)
    vlan_id = Column(String, nullable=False)
    name = Column(String, nullable=True)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class VRF(Base):
    __tablename__ = "vrfs"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False, index=True)
    name = Column(String, nullable=False)
    route_distinguisher = Column(String, nullable=True)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class NetworkRoute(Base):
    __tablename__ = "network_routes"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False, index=True)
    destination = Column(String, nullable=False)
    mask = Column(String, nullable=True)
    next_hop = Column(String, nullable=True)
    vrf = Column(String, nullable=True)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class NetworkLink(Base):
    """An inferred adjacency between two devices' interfaces, derived by
    matching IP addresses onto the same /subnet (see routers/topology.py).
    Never persisted from a guess with no supporting data -- computed fresh
    from NetworkInterface rows at query time, not stored here; this table
    exists for a future explicit/manual-topology-override workflow and is
    currently unused by the read path (topology endpoint computes links
    on the fly instead, per RULE 10: don't persist an inferred fact as if
    it were observed)."""
    __tablename__ = "network_links"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    source_device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    source_interface = Column(String, nullable=True)
    target_device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    target_interface = Column(String, nullable=True)
    link_type = Column(String, default="inferred_subnet")
    created_at = Column(DateTime, default=datetime.utcnow)


class AuditSchedule(Base):
    """Phase 12 -- a recurring (or one-off manual) audit definition.

    Execution never happens inside a FastAPI request handler: a background
    worker (app/workers/scheduler_worker.py) polls for schedules whose
    `next_run` has passed and hands them to
    services/scheduling_service.execute_schedule(), which runs the SAME
    collection+scan pipeline used everywhere else (RULE 11 -- no second
    compliance implementation).
    """
    __tablename__ = "audit_schedules"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    name = Column(String, nullable=False)
    # scope: {"device_ids": [...]} or {"all": true} -- resolved at run time
    # against the CURRENT device inventory, so devices added after the
    # schedule was created are automatically included when scope=="all".
    scope = Column(JSON, nullable=False, default=dict)
    frequency = Column(String, nullable=False, default="manual")  # manual|hourly|daily|weekly
    enabled = Column(Boolean, default=True)
    framework = Column(String, default="ALL")
    created_by = Column(String, nullable=True)
    last_run = Column(DateTime, nullable=True)
    next_run = Column(DateTime, nullable=True, index=True)
    last_run_status = Column(String, nullable=True)
    last_run_detail = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Alert(Base):
    """Phase 13 -- alert engine output. Every trigger listed in the problem
    statement (CRITICAL finding, HIGH risk, drift, unknown config, AI low
    confidence, Batfish violation, collection failure, OPA failure, Fabric
    anchor failure, evidence integrity failure) creates a row here through
    services/alert_service.py -- nothing bypasses this table to notify a
    destination directly, so GET /api/alerts is always a complete history.
    """
    __tablename__ = "alerts"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    category = Column(String, nullable=False, index=True)
    severity = Column(String, nullable=False, default="MEDIUM")  # CRITICAL/HIGH/MEDIUM/LOW
    title = Column(String, nullable=False)
    detail = Column(Text, nullable=True)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=True)
    extra = Column(JSON, nullable=True)
    status = Column(String, default="OPEN")  # OPEN/ACKNOWLEDGED
    acknowledged_by = Column(String, nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)
    dispatch_results = Column(JSON, nullable=True)  # per-destination best-effort delivery outcome
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class DriftEvent(Base):
    """Phase 11: configuration drift.

    Every new collection/upload for a device is hashed and compared to the
    hash of that device's immediately-preceding scan. If the hashes differ,
    a DriftEvent row is written -- an immutable record (never edited/deleted
    by the app after creation) of *what* changed between two observed
    configurations. This table only records the fact and shape of a change;
    it never itself renders a compliance verdict -- that stays OPA's job
    (RULE 1). `security_impacting` / `affected_controls` are heuristic
    triage signals only, used to decide whether to re-run the compliance
    pipeline on a purely-cosmetic-looking change, not a compliance result.
    """
    __tablename__ = "drift_events"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False, index=True)
    previous_scan_id = Column(String, ForeignKey("scans.id"), nullable=True)
    current_scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    previous_config_hash = Column(String, nullable=True)
    current_config_hash = Column(String, nullable=False)
    added_lines = Column(JSON, default=list)
    removed_lines = Column(JSON, default=list)
    changed_sections = Column(JSON, default=list)
    security_impacting = Column(Boolean, default=False)
    affected_controls = Column(JSON, default=list)
    pipeline_rerun_triggered = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class ChangeRequest(Base):
    """Phase 14 -- a proposed configuration change, run through the same
    OPA/Batfish/risk pipeline as a scan (see services/change_request_service.py)
    but requiring an explicit human approval step before deployment (RULE 5).
    Never applied to a device directly by AI or by the browser."""
    __tablename__ = "change_requests"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False, index=True)
    created_by = Column(String, nullable=True)
    source = Column(String, default="manual")
    current_config_object_key = Column(String, nullable=True)
    current_config_hash = Column(String, nullable=True)
    proposed_config_object_key = Column(String, nullable=True)
    proposed_config_hash = Column(String, nullable=False)
    status = Column(String, default="DRAFT", index=True)  # DRAFT/PENDING_APPROVAL/APPROVED/REJECTED/DEPLOYING/DEPLOYED/FAILED
    syntax_status = Column(String, nullable=True)
    opa_decision = Column(String, nullable=True)
    batfish_status = Column(String, nullable=True)
    risk_score = Column(Integer, nullable=True)
    risk_level = Column(String, nullable=True)
    final_decision = Column(String, nullable=True)
    final_reason = Column(Text, nullable=True)
    validation_detail = Column(JSON, nullable=True)
    approval_required = Column(Boolean, default=True)
    approved_by = Column(String, nullable=True)
    approved_at = Column(DateTime, nullable=True)
    rejected_by = Column(String, nullable=True)
    rejected_at = Column(DateTime, nullable=True)
    rejection_reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class DeploymentRecord(Base):
    """Phase 15 -- one deployment attempt for an APPROVED ChangeRequest.
    `expected_pre_hash` is the ChangeRequest's current_config_hash at
    approval time; a mismatch against `observed_pre_hash` (freshly
    collected immediately before deployment) aborts the deployment
    (RULE 43 -- never deploy against stale configuration)."""
    __tablename__ = "deployment_records"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    change_request_id = Column(String, ForeignKey("change_requests.id"), nullable=False, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False, index=True)
    initiated_by = Column(String, nullable=True)
    transport = Column(String, nullable=True)  # ssh/netconf/gnmi
    expected_pre_hash = Column(String, nullable=True)
    observed_pre_hash = Column(String, nullable=True)
    status = Column(String, default="PENDING")  # PENDING/FAILED/DEPLOYED/DRIFTED
    post_config_hash = Column(String, nullable=True)
    post_verification_passed = Column(Boolean, nullable=True)
    post_scan_id = Column(String, ForeignKey("scans.id"), nullable=True)
    error = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    # OpenConfig/gNMI deployment metadata (spec sections 26/47/53) -- never
    # credentials, only what was requested/returned.
    request_hash = Column(String, nullable=True)
    model_name = Column(String, nullable=True)
    paths = Column(JSON, nullable=True)
    operation = Column(String, nullable=True)
    # Optional pyATS/Genie supplemental post-deployment verification
    # (spec sections 29-34/47/53) -- never authoritative for compliance.
    verification_engine = Column(String, nullable=True)
    verification_result = Column(String, nullable=True)
    verification_metadata = Column(JSON, nullable=True)


class ComplianceException(Base):
    """Phase 16 -- a time-bounded, human-approved exception for one
    device/control pair. Never overwrites the underlying OPA result (RULE
    45): the original OPA finding is preserved and the UI/report layer
    displays EXCEPTION_ACCEPTED alongside it while status==APPROVED and
    expires_at is in the future."""
    __tablename__ = "compliance_exceptions"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False, index=True)
    control_id = Column(String, nullable=False, index=True)
    reason = Column(Text, nullable=False)
    created_by = Column(String, nullable=True)
    approved_by = Column(String, nullable=True)
    approved_at = Column(DateTime, nullable=True)
    rejected_by = Column(String, nullable=True)
    rejected_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=False)
    status = Column(String, default="PENDING", index=True)  # PENDING/APPROVED/REJECTED/EXPIRED
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)