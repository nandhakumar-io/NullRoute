"""SQLAlchemy ORM models — the system of record.

Runs against PostgreSQL + pgvector in production (docker-compose), but the
same models work against SQLite for local/offline development, which is what
the bundled `make dev` / `uvicorn app.main:app` path uses when POSTGRES is
unreachable (see app/models/db.py).
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (JSON, Boolean, Column, DateTime, Float, ForeignKey,
                         Integer, String, Text, UniqueConstraint)
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
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Device-management fields (enterprise inventory pass). All nullable so
    # existing rows created before this migration remain valid without a
    # backfill; the API layer supplies sensible defaults on create.
    name = Column(String, nullable=True)  # display name, distinct from hostname
    site = Column(String, nullable=True)  # site/location
    environment = Column(String, nullable=True)  # e.g. production/staging/lab
    protocol = Column(String, nullable=True)  # preferred management protocol: ssh/netconf/restconf/snmp/gnmi
    description = Column(Text, nullable=True)
    tags = Column(JSON, nullable=True)  # list[str]
    enabled = Column(Boolean, nullable=False, default=True)

    # Physical/logical topology placement (all optional / independently
    # settable): a device can sit in a rack inside a datacenter, and/or be a
    # member of a NetworkGroup used for grouped Batfish analysis.
    datacenter_id = Column(String, ForeignKey("datacenters.id"), nullable=True, index=True)
    rack_id = Column(String, ForeignKey("racks.id"), nullable=True, index=True)

    scans = relationship("Scan", back_populates="device", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    status = Column(String, default="uploaded")  # uploaded/parsed/normalized/evaluated/completed/failed/paused/stopped
    framework = Column(String, default="CIS")
    raw_config_path = Column(String)  # MinIO object key
    raw_config_hash = Column(String)
    # Original file name for config uploads (single + bulk). Ad-hoc uploads
    # all share one sandbox Device, so without this every row in the
    # Validation list is just "Ad-Hoc Config Uploads" and can't be told apart.
    source_filename = Column(String, nullable=True)
    parsed_json = Column(JSON, nullable=True)
    baseline_json = Column(JSON, nullable=True)
    compliance_score = Column(Float, nullable=True)
    error = Column(Text, nullable=True)

    # Pipeline pause/stop/resume control (see services/pipeline.py). An
    # operator can request a pause or stop via the API at any time;
    # run_pipeline() checks control_state at each stage boundary and, on
    # the next checkpoint it reaches, persists enough state to resume and
    # unwinds cleanly rather than continuing or being killed mid-write.
    control_state = Column(String, default="RUNNING")  # RUNNING/PAUSE_REQUESTED/PAUSED/STOP_REQUESTED/STOPPED
    pipeline_stage = Column(String, nullable=True)  # last-completed/current stage name -- see pipeline.STAGE_ORDER
    paused_at = Column(DateTime, nullable=True)
    resumed_at = Column(DateTime, nullable=True)
    stopped_at = Column(DateTime, nullable=True)
    # Per-stage timing for bottleneck analysis. JSON dict keyed by stage name,
    # e.g. {"normalize": {"started_at": "...", "completed_at": "...", "duration_ms": 4321}}.
    # Written by pipeline._checkpoint(); never cleared on resume so a full
    # timing history across multiple resume attempts is preserved.
    stage_timings = Column(JSON, nullable=True)


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
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False, index=True)
    framework = Column(String)
    control_id = Column(String)
    title = Column(String)
    severity = Column(String)  # CRITICAL/HIGH/MEDIUM/LOW
    expected_value = Column(String)
    actual_value = Column(String)
    result = Column(String)  # PASS/FAIL/NOT_APPLICABLE/UNVERIFIED (see policies/common/evaluate.rego)
    parameter = Column(String)
    reason = Column(Text, nullable=True)  # human-readable OPA reason_for() string
    policy_version = Column(String, nullable=True)  # exact policy revision that produced this finding
    vendor = Column(String, nullable=True, index=True)  # denormalized from Scan/Device for direct filtering
    evidence_line = Column(Text)
    remediation = Column(Text)
    # Cached AI-generated CLI remediation steps (list[str]). Populated the
    # first time /remediation/generate-cli runs for this finding; returned on
    # every subsequent call without re-invoking the LLM (prevents token waste
    # on page refresh). NULL = not yet generated. Cleared automatically if the
    # finding row is recreated by a new scan (the scan is a new Scan row, so
    # Finding rows are fresh).
    ai_cli_cache = Column(JSON, nullable=True)
    # Trust-boundary provenance for the Evidence Trace view: which engine
    # produced the raw_line -> normalized_parameter mapping this finding was
    # evaluated against. 'parser' = deterministic vendor parser (no AI
    # involved); 'ai' = RAG/LLM interpretation (see NormalizedParameter in
    # models/baseline.py) with a confidence score. Null for findings with no
    # single-parameter provenance (e.g. Batfish reachability findings).
    source = Column(String, nullable=True)  # 'parser' | 'ai'
    confidence = Column(Float, nullable=True)
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
    vendor = Column(String, index=True)
    raw_command_pattern = Column(Text)
    normalized_parameter = Column(String)
    example_value = Column(String)
    ai_suggested_meaning = Column(Text)
    confidence = Column(Float)
    status = Column(String, default="pending", index=True)  # pending/approved/rejected
    embedding = Column(JSON, nullable=True)  # stored as list[float]; pgvector column in real PG migration
    model_version = Column(String, nullable=True)
    embedding_backend = Column(String, nullable=True)  # "minilm"/"minilm-remote"/None if no vector was stored
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
    scan_id = Column(String, ForeignKey("scans.id"), nullable=True)  # NULL for deploy/rollback events that never reached a scan
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
    last_verified_at = Column(DateTime, nullable=True)
    last_verification_status = Column(String, nullable=True)
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
    secret_data = Column(JSON, nullable=True)
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
    raw_command = Column(Text, nullable=True)
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
    """System-of-record for the Section 12 audit trail.

    Every mutating / sensitive action in the app should produce exactly one
    row here via `app.services.audit_service`, capturing the fields called
    for by the spec: who, tenant, what, when, source IP, object, old value,
    new value, result. `actor`/`action`/`resource`/`details` are the
    original (pre-Section-12) columns, kept for backward compatibility with
    any existing readers/writers (e.g. routers/training.py); new code should
    populate the richer columns below via audit_service instead of writing
    to this model directly.
    """
    __tablename__ = "audit_log"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=True, index=True)

    # --- legacy columns (pre-Section-12) ---
    actor = Column(String)
    action = Column(String)
    resource = Column(String)
    details = Column(JSON, nullable=True)

    # --- Section 12 columns ---
    user_id = Column(String, nullable=True, index=True)       # who: token subject
    username = Column(String, nullable=True)                   # who: human-readable
    source_ip = Column(String, nullable=True)                  # source IP
    object_type = Column(String, nullable=True, index=True)    # object: kind (scan, credential, ...)
    object_id = Column(String, nullable=True, index=True)      # object: id
    old_value = Column(JSON, nullable=True)                    # old value
    new_value = Column(JSON, nullable=True)                    # new value
    result = Column(String, nullable=True, index=True)         # SUCCESS / FAILURE / DENIED

    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class GatewayJobRecord(Base):
    """Device Gateway job ledger (Part 1/7/13).

    One row per signed job envelope the gateway has EVER accepted for
    validation, keyed by `job_id` (also unique, together with `nonce`,
    which is what makes replay detection a DB constraint rather than an
    in-memory set -- safe across gateway restarts/replicas). Never stores
    credential material or raw device output; large output lives in MinIO
    under `result_object_key` and this row only holds the reference.
    """
    __tablename__ = "gateway_jobs"
    job_id = Column(String, primary_key=True)
    nonce = Column(String, nullable=False, unique=True, index=True)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    requester_id = Column(String, nullable=False)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False, index=True)
    operation = Column(String, nullable=False)
    protocol = Column(String, nullable=False)
    approval_id = Column(String, nullable=True)
    status = Column(String, default="RECEIVED")  # RECEIVED/VALIDATED/REJECTED/RUNNING/SUCCEEDED/FAILED
    error_code = Column(String, nullable=True)
    error_message = Column(Text, nullable=True)
    result_object_key = Column(String, nullable=True)  # MinIO key for large raw output, if any
    normalized_data = Column(JSON, nullable=True)
    duration_ms = Column(Float, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    completed_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)


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
    switchport_mode = Column(String, nullable=True)  # ACCESS / TRUNK / NONE (Batfish-derived)
    allowed_vlans = Column(String, nullable=True)    # trunk allowed-vlan spec, e.g. "10,20,30-40"
    source = Column(String, nullable=True)           # "batfish" | "config" (regex extractor)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=True)  # scan that produced this snapshot
    created_at = Column(DateTime, default=datetime.utcnow)


class VLAN(Base):
    __tablename__ = "vlans"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False, index=True)
    vlan_id = Column(String, nullable=False)
    name = Column(String, nullable=True)
    interfaces = Column(JSON, nullable=True)  # member interfaces (Batfish switchedVlanProperties + SVIs)
    source = Column(String, nullable=True)    # "batfish" | "config"
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
    time_of_day = Column(String, nullable=True)  # "HH:MM", 24h UTC -- anchors daily/weekly runs to a clock time
    enabled = Column(Boolean, default=True)
    framework = Column(String, default="ALL")
    created_by = Column(String, nullable=True)
    last_run = Column(DateTime, nullable=True)
    next_run = Column(DateTime, nullable=True, index=True)
    last_run_status = Column(String, nullable=True)
    last_run_detail = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class BaselineApproval(Base):
    """Golden/approved security baseline (Part 6). Points at an existing
    Scan row -- the Scan already carries `baseline_json` (SecurityBaseline
    Model), `raw_config_path` (MinIO), and `raw_config_hash`, so it IS the
    "snapshot" concept; this table adds nothing but the approval act
    itself. Only one row per device should be the *current* approved
    baseline at a time -- enforced by the service layer (most recent
    `approved_at` wins), not a DB constraint, since history is kept.
    """
    __tablename__ = "baseline_approvals"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False, index=True)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)  # the approved snapshot
    approved_by = Column(String, nullable=False)
    approved_at = Column(DateTime, default=datetime.utcnow)
    approval_reason = Column(Text, nullable=True)


class SecurityDriftFinding(Base):
    """Persistent, per-parameter normalized security drift finding
    (Part 7). Distinct from `DriftEvent` (Phase 11's per-scan-pair raw
    line diff + keyword triage, still used for the raw-diff view) --
    this is the normalized-baseline-level finding with its own status
    workflow, one row per drifted SecurityBaselineModel parameter.
    `compliance_controls`/severity/drift_type are the drift ENGINE's own
    directional triage (see services/security_baseline_drift.py) and are
    never a compliance verdict; the authoritative PASS/FAIL for any
    control still lives on the Finding rows OPA produced for each scan.
    """
    __tablename__ = "security_drift_findings"
    drift_id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False, index=True)
    previous_scan_id = Column(String, ForeignKey("scans.id"), nullable=True)  # null when compared against a baseline with no prior scan
    current_scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    baseline_parameter = Column(String, nullable=False, index=True)  # dotted path, e.g. management.ssh.version
    previous_value = Column(JSON, nullable=True)
    current_value = Column(JSON, nullable=True)
    drift_type = Column(String, nullable=False)  # NO_CHANGE/CONFIGURATION_CHANGE/SECURITY_IMPROVEMENT/SECURITY_DEGRADATION/COMPLIANCE_IMPACT/UNKNOWN_IMPACT
    severity = Column(String, nullable=True)  # CRITICAL/HIGH/MEDIUM/LOW, from the matching control if any
    compliance_controls = Column(JSON, nullable=True)  # list of control_ids from policies/controls.py this parameter maps to
    evidence_reference = Column(String, nullable=True)  # MinIO raw_config_path of the current scan
    detected_at = Column(DateTime, default=datetime.utcnow, index=True)
    status = Column(String, default="OPEN")  # OPEN/ACKNOWLEDGED/REVIEWED/RESOLVED/ACCEPTED_RISK/FALSE_POSITIVE
    status_updated_by = Column(String, nullable=True)
    status_updated_at = Column(DateTime, nullable=True)


class NetworkScanJob(Base):
    """Phase 2 (enterprise UI pass) -- an orchestrated, multi-stage network
    scan: optional discovery over a CIDR, then collection + the existing
    compliance pipeline (see services/pipeline.run_pipeline, RULE 11 -- no
    second compliance implementation) for every target device.

    Execution never happens inside a FastAPI request handler: POST
    /api/network-scans only inserts this row with status=PENDING; the
    background worker (app/workers/network_scan_worker.py) polls for
    PENDING rows and calls services/network_scan_service.execute_scan_job(),
    the same pattern already used for AuditSchedule /
    app/workers/scheduler_worker.py.

    `stages` is the source of truth the UI polls for real (non-fabricated)
    progress -- each key is only ever set to a value once that stage has
    actually run against the real backend for at least one device.
    """
    __tablename__ = "network_scan_jobs"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    name = Column(String, nullable=True)
    target_cidr = Column(String, nullable=True)  # set when run_discovery is true
    run_discovery = Column(Boolean, default=False)
    discovery_ports = Column(String, nullable=True)
    requested_device_ids = Column(JSON, nullable=True)  # explicit device selection, if any
    framework = Column(String, default="ALL")
    include_batfish = Column(Boolean, default=True)

    status = Column(String, default="PENDING", index=True)  # PENDING/RUNNING/COMPLETED/PARTIAL/FAILED
    # Per-stage status: {"discovery": {"status": "...", "detail": "..."}, ...}
    # status values: PENDING/RUNNING/DONE/SKIPPED/FAILED
    stages = Column(JSON, nullable=False, default=dict)
    discovered_hosts = Column(JSON, nullable=True)  # raw discovery output, for the review step
    resolved_device_ids = Column(JSON, nullable=True)  # devices actually targeted for scan
    scan_ids = Column(JSON, nullable=True)  # Scan rows created by this job
    device_results = Column(JSON, nullable=True)  # per-device outcome summary
    error = Column(Text, nullable=True)

    created_by = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)


class RagDocument(Base):
    """A chunk of retrievable knowledge for the RAG chat feature: findings,
    device facts, Batfish results, evidence summaries, or externally
    ingested docs (policies, runbooks) get indexed here as they're
    created/updated.

    `embedding` is intentionally nullable and unused today -- retrieval
    currently runs on `content`/`title` via a keyword/BM25-style match in
    services/rag_service.py. Once a real embedding model + vector store
    (e.g. pgvector) is wired in, this column carries the vector and the
    same row shape keeps working; no migration of the retrieval call sites
    is needed, only rag_service.search()'s internals.
    """
    __tablename__ = "rag_documents"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    source_type = Column(String, nullable=False, index=True)  # finding | device | scan | batfish_group | evidence | manual_upload
    source_id = Column(String, nullable=True, index=True)
    title = Column(String, nullable=False)
    content = Column(Text, nullable=False)
    doc_metadata = Column(JSON, nullable=True)
    embedding = Column(JSON, nullable=True)  # placeholder for a future vector; JSON list[float] until pgvector is adopted
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class RagQueryLog(Base):
    """Every question asked through the dashboard's RAG chat, the sources
    retrieved for it, and the answer returned -- gives an audit trail and a
    ready-made eval set for when a real LLM answer-generation step is
    plugged in behind services/rag_service.answer_query()."""
    __tablename__ = "rag_query_logs"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    question = Column(Text, nullable=False)
    answer = Column(Text, nullable=True)
    source_document_ids = Column(JSON, nullable=True)
    asked_by = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


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
    snapshot_diff = Column(JSON, nullable=True)
    approval_required = Column(Boolean, default=True)
    approved_by = Column(String, nullable=True)
    approved_at = Column(DateTime, nullable=True)
    rejected_by = Column(String, nullable=True)
    rejected_at = Column(DateTime, nullable=True)
    rejection_reason = Column(Text, nullable=True)
    
    # Merge metadata for remediation snippets (Phase 10 / UI Preview)
    snippet = Column(Text, nullable=True)
    merge_style = Column(String, nullable=True)
    merge_confidence = Column(String, nullable=True)  # HIGH / MEDIUM / LOW (merge engine output)
    merge_applied = Column(JSON, nullable=True)
    merge_warnings = Column(JSON, nullable=True)
    merge_commands = Column(JSON, nullable=True)
    edited_by = Column(String, nullable=True)
    edited_at = Column(DateTime, nullable=True)
    revision = Column(Integer, nullable=False, default=1, server_default="1")

    # Human-in-the-loop binding (see change_request_service.approve/reject).
    # An approval is only valid for the exact revision/hash the reviewer was
    # shown; `review_events` is the append-only trail of every human decision
    # (created / edited / approved / rejected / override / deploy / rollback).
    approved_revision = Column(Integer, nullable=True)
    approved_hash = Column(String, nullable=True)
    review_comment = Column(Text, nullable=True)
    override_justification = Column(Text, nullable=True)
    review_events = Column(JSON, nullable=True)

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
    # Whether this deployment has been rolled back (set True by rollback_service
    # only after a VERIFIED rollback -- so dr.rolled_back=True is a confirmed
    # revert, never speculation). Starts False so older rows are unaffected.
    rolled_back = Column(Boolean, nullable=False, default=False)
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
    # Ordered per-stage progress (credentials -> connect -> precheck -> plan ->
    # commit -> verify -> postval); see services/stage_tracker.py. Lets the UI
    # show exactly where a deployment stopped.
    stages = Column(JSON, nullable=True)
    # Post-validation: did the controls this change targeted actually flip to
    # PASS, and what did a real Batfish before/after diff say about the
    # device's behaviour? (columns match alembic b4c5d6e7f8a9)
    target_control_ids = Column(JSON, nullable=True)
    target_controls_result = Column(JSON, nullable=True)
    target_controls_passed = Column(Boolean, nullable=True)
    batfish_diff_status = Column(String, nullable=True)
    batfish_diff_summary = Column(Text, nullable=True)
    batfish_diff_detail = Column(JSON, nullable=True)


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


class TrainingExample(Base):
    """Loop 1 / 2: Human-in-the-loop training example.
    Captures the full normalized interpretation approved by a human, rather than
    just a single field. Forms the basis for both immediate RAG mappings and
    offline model training datasets."""
    __tablename__ = "training_examples"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=True, index=True)
    source_scan_id = Column(String, ForeignKey("scans.id"), nullable=True)
    source_device_id = Column(String, ForeignKey("devices.id"), nullable=True)
    source_mapping_id = Column(String, ForeignKey("command_mappings.id"), nullable=True)
    raw_config_hash = Column(String, nullable=False)
    raw_config_redacted = Column(Text, nullable=False)
    vendor = Column(String, nullable=True)
    intent = Column(String, nullable=True)
    normalized_facts = Column(JSON, nullable=False, default=dict)
    human_action = Column(String, nullable=False)  # APPROVED/CORRECTED/REJECTED
    correction_reason = Column(Text, nullable=True)
    created_by = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    dataset_version = Column(String, nullable=True)
    embedding_id = Column(String, nullable=True)
    validation_status = Column(String, default="PENDING")  # PENDING/VALIDATED/EXCLUDED


class DatasetVersion(Base):
    """Loop 2: Immutable dataset snapshot for training."""
    __tablename__ = "dataset_versions"
    id = Column(String, primary_key=True, default=gen_uuid)
    version = Column(String, nullable=False, unique=True, index=True)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=True, index=True)
    created_by = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    example_count = Column(Integer, nullable=False, default=0)
    label_distribution = Column(JSON, nullable=False, default=dict)
    vendor_distribution = Column(JSON, nullable=False, default=dict)
    source_distribution = Column(JSON, nullable=False, default=dict)
    validation_status = Column(String, nullable=True)
    training_status = Column(String, nullable=True)
    dataset_hash = Column(String, nullable=False)
    is_immutable = Column(Boolean, default=True)
    # DRAFT versions are mutable (examples can be added/removed) until an
    # admin calls Finalize, which freezes membership, computes the final
    # content-addressable hash, and sets is_immutable=True. Clone starts a
    # new DRAFT from a finalized version's membership so trained models
    # remain traceable to an immutable snapshot.
    status = Column(String, nullable=False, default="FINALIZED", index=True)  # DRAFT/FINALIZED
    parent_version = Column(String, nullable=True)  # id of the DatasetVersion this was cloned from
    finalized_at = Column(DateTime, nullable=True)


class DatasetItem(Base):
    """Explicit membership of a TrainingExample in a DatasetVersion.

    Replaces the old TrainingExample.dataset_version string column, which a
    later snapshot could silently overwrite (making earlier "immutable"
    datasets non-reproducible, since a job re-querying by that string would
    pick up whatever the column currently says instead of the original
    membership). Membership here is a append-only join row scoped to one
    DatasetVersion, so cloning/creating a new draft never mutates an older,
    finalized version's rows.
    """
    __tablename__ = "dataset_items"
    id = Column(String, primary_key=True, default=gen_uuid)
    dataset_version_id = Column(String, ForeignKey("dataset_versions.id"), nullable=False, index=True)
    training_example_id = Column(String, ForeignKey("training_examples.id"), nullable=False, index=True)
    added_at = Column(DateTime, default=datetime.utcnow)


class TrainingJob(Base):
    """Loop 2: Training job abstraction."""
    __tablename__ = "training_jobs"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=True, index=True)
    dataset_version_id = Column(String, ForeignKey("dataset_versions.id"), nullable=False)
    base_model_version = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String, default="QUEUED", index=True)  # QUEUED/RUNNING/COMPLETED/FAILED/CANCELLED
    artifact_path = Column(String, nullable=True)
    metrics = Column(JSON, nullable=True)
    error = Column(Text, nullable=True)
    created_by = Column(String, nullable=False)


class ModelRegistryEntry(Base):
    """Loop 2: Production model lifecycle management."""
    __tablename__ = "model_registry_entries"
    id = Column(String, primary_key=True, default=gen_uuid)
    model_name = Column(String, nullable=False)
    model_type = Column(String, nullable=False)  # classifier/embedder
    dataset_version = Column(String, nullable=False)
    base_model_version = Column(String, nullable=True)
    artifact_path = Column(String, nullable=True)
    model_hash = Column(String, nullable=True)
    metrics = Column(JSON, nullable=True, default=dict)
    training_timestamp = Column(DateTime, nullable=True)
    status = Column(String, default="CANDIDATE", index=True)  # CANDIDATE/APPROVED/PRODUCTION/REJECTED/ARCHIVED
    created_by = Column(String, nullable=False)
    approved_by = Column(String, nullable=True)
    approved_at = Column(DateTime, nullable=True)
    training_job_id = Column(String, ForeignKey("training_jobs.id"), nullable=True)

class Gns3Server(Base):
    """Database model to track registered GNS3 emulation environments."""
    __tablename__ = "gns3_servers"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    name = Column(String, nullable=False)
    url = Column(String, nullable=False)
    username = Column(String, nullable=True)
    password = Column(String, nullable=True)
    initialized_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


# ---------------------------------------------------------------------------
# Unified Control Layer (Part 1) — SCF/UCF/OSCAL-inspired control knowledge
# base.  These tables are purely additive: they enrich OPA policy outputs and
# generate/update Rego files in the OPA policy directory.  The OPA engine
# itself is never replaced or bypassed (RULE 1/2/14).
# ---------------------------------------------------------------------------

class UnifiedControl(Base):
    """One normalized security control drawn from CIS, NIST, ISO 27001, DISA
    STIGs, or a vendor hardening guide.  `status` starts as 'pending_review'
    and advances to 'approved' after a security engineer confirms the LLM
    extraction.  A row here drives both the Rego policy compiler and the
    multi-framework compliance matrix in audit reports.
    """
    __tablename__ = "unified_controls"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    name = Column(String, nullable=False)
    objective = Column(Text, nullable=True)
    domain = Column(String, nullable=True, index=True)  # management/logging/aaa/snmp/password/…
    source_text = Column(Text, nullable=True)
    normalized_description = Column(Text, nullable=True)
    status = Column(String, default="pending_review", nullable=False, index=True)  # pending_review/approved
    source_document = Column(String, nullable=True)
    created_by = Column(String, nullable=True)
    approved_by = Column(String, nullable=True)
    approved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    framework_mappings = relationship("FrameworkMapping", back_populates="control", cascade="all, delete-orphan")
    config_concepts = relationship("ConfigConcept", back_populates="control", cascade="all, delete-orphan")
    reviews = relationship("ControlReview", back_populates="control", cascade="all, delete-orphan")


class FrameworkMapping(Base):
    """Maps one UnifiedControl to an external framework control ID (e.g.
    NIST AC-17, CIS L1-SSH-001, DISA-STIG-NET-001).  A single UnifiedControl
    commonly maps to IDs in multiple frameworks simultaneously.
    """
    __tablename__ = "framework_mappings"
    id = Column(String, primary_key=True, default=gen_uuid)
    control_id = Column(String, ForeignKey("unified_controls.id"), nullable=False, index=True)
    framework = Column(String, nullable=False, index=True)  # NIST-800-53/CIS/ISO-27001/DISA-STIG
    external_id = Column(String, nullable=False)
    confidence = Column(Float, nullable=True)   # 0-1, LLM extraction confidence
    created_at = Column(DateTime, default=datetime.utcnow)

    control = relationship("UnifiedControl", back_populates="framework_mappings")


class ConfigConcept(Base):
    """An abstract security-parameter concept tied to a UnifiedControl —
    e.g. `mgmt_protocol`, `idle_timeout`, `logging_server`.
    ConfigConcepts are vendor-agnostic; vendor-specific regexes live in
    VendorConfigPattern.
    """
    __tablename__ = "config_concepts"
    id = Column(String, primary_key=True, default=gen_uuid)
    control_id = Column(String, ForeignKey("unified_controls.id"), nullable=False, index=True)
    concept_name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    control = relationship("UnifiedControl", back_populates="config_concepts")
    vendor_patterns = relationship("VendorConfigPattern", back_populates="concept", cascade="all, delete-orphan")


class VendorConfigPattern(Base):
    """The learnable mapping layer: a vendor-specific regex/pattern for one
    ConfigConcept.  Engineers add rows here as new device configs are ingested;
    the policy compiler uses these to generate Rego rules.
    """
    __tablename__ = "vendor_config_patterns"
    id = Column(String, primary_key=True, default=gen_uuid)
    concept_id = Column(String, ForeignKey("config_concepts.id"), nullable=False, index=True)
    vendor = Column(String, nullable=False, index=True)
    pattern = Column(String, nullable=False)    # Python re-compatible regex
    example_snippet = Column(Text, nullable=True)
    created_by = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    concept = relationship("ConfigConcept", back_populates="vendor_patterns")


class ControlReview(Base):
    """Audit trail of human corrections to LLM-extracted controls and
    mappings.  `correction_json` stores the diff between the original
    LLM proposal and the human-corrected value, usable as few-shot examples
    for future LLM prompts (never used to change OPA outcomes — RULE 1).
    """
    __tablename__ = "control_reviews"
    id = Column(String, primary_key=True, default=gen_uuid)
    control_id = Column(String, ForeignKey("unified_controls.id"), nullable=False, index=True)
    reviewer = Column(String, nullable=False)
    original_text = Column(Text, nullable=True)
    proposed_change = Column(Text, nullable=True)
    decision = Column(String, nullable=False)      # approved/rejected/corrected
    correction_json = Column(JSON, nullable=True)  # structured diff for few-shot reuse
    created_at = Column(DateTime, default=datetime.utcnow)

    control = relationship("UnifiedControl", back_populates="reviews")


class CustomControl(Base):
    """Part 2 §10 "custom policy": a tenant-defined control expressed in the
    SAME parameter/operator/expected/severity shape as the built-in catalog
    (app/policies/controls.py), evaluated against the SAME flattened
    SecurityBaselineModel every built-in control is — no vendor parser
    change, no OPA bundle rebuild/reload required.

    This is deliberately a narrower, simpler mechanism than the
    UnifiedControl/VendorConfigPattern subsystem above: UnifiedControl is
    for extracting a full control (including vendor-specific detection
    regexes) out of a hardening-guide document via LLM, then compiling it
    into its own generated Rego package — powerful, but today that compiled
    package is never queried by policies/baseline.rego's actual decision
    entrypoint, so it can't yet produce a live Finding/score (see
    IMPLEMENTATION_AUDIT.md §C). CustomControl rows, by contrast, are read
    at evaluation time and passed to OPA as input.custom_controls
    (see services/custom_control_service.py and
    policies/common/custom.rego) — approved rows are live on the very next
    scan, with framework="CUSTOM" findings that flow through the exact same
    Finding/score/dashboard path as every other control.

    A CustomControl and a compiled UnifiedControl can coexist; unifying them
    into one authoring workflow is a reasonable follow-up (see audit §C)
    but is out of scope here.
    """
    __tablename__ = "custom_controls"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    control_id = Column(String, nullable=False)  # e.g. "CUSTOM-SSH-001"; unique per tenant
    title = Column(String, nullable=False)
    parameter = Column(String, nullable=False)  # dotted path on the flattened baseline
    operator = Column(String, nullable=False)   # eq/ne/gte/lte/in/exists/not_true — same vocabulary as controls.py
    expected_json = Column(JSON, nullable=False)  # JSON-encoded `expected` value (any JSON type)
    severity = Column(String, nullable=False, default="MEDIUM")  # CRITICAL/HIGH/MEDIUM/LOW
    remediation = Column(Text, nullable=True)
    status = Column(String, default="pending_review", nullable=False, index=True)  # pending_review/approved/rejected
    created_by = Column(String, nullable=True)
    approved_by = Column(String, nullable=True)
    approved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ---------------------------------------------------------------------------
# Vulnerability Management Layer (Part 2) — CVE/NVD/KEV/PSIRT driven.
# ---------------------------------------------------------------------------

class Vulnerability(Base):
    """One CVE record, upserted by the daily vuln_sync_worker from NVD,
    CISA KEV, and vendor PSIRT feeds.  `cve_id` is the primary key so
    upserts are idempotent.  `affected_cpe_ranges` is a JSON list of
    CPE 2.3 strings / version-range dicts matching NVD's schema.
    """
    __tablename__ = "vulnerabilities"
    cve_id = Column(String, primary_key=True)
    cvss_score = Column(Float, nullable=True)
    severity = Column(String, nullable=True, index=True)  # CRITICAL/HIGH/MEDIUM/LOW/NONE
    description = Column(Text, nullable=True)
    affected_cpe_ranges = Column(JSON, nullable=True)     # list[str | dict]
    kev_flag = Column(Boolean, default=False, nullable=False)
    published_date = Column(DateTime, nullable=True)
    last_modified_date = Column(DateTime, nullable=True)
    source = Column(String, default="nvd", nullable=False)  # nvd/cisa_kev/cisco_psirt/juniper_jsa/paloalto
    remediation_advice = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    device_matches = relationship("DeviceVulnerabilityMatch", back_populates="vulnerability")


class DeviceVulnerabilityMatch(Base):
    """One potential CVE/device intersection created by the correlation task.
    `status` starts as 'open' and advances through the review workflow.
    `linked_control_id` ties the remediation to a UnifiedControl when one
    exists (e.g. 'disable SNMPv1' → control enforcing SNMPv3).  Historical
    rows are never deleted — status changes ARE the audit trail (RULE 15).
    """
    __tablename__ = "device_vulnerability_matches"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False, index=True)
    cve_id = Column(String, ForeignKey("vulnerabilities.cve_id"), nullable=False, index=True)
    matched_via = Column(String, nullable=False)    # cpe/keyword/psirt
    risk_priority_score = Column(Float, nullable=True)  # CVSS × KEV boost × exposure factor
    status = Column(String, default="open", nullable=False, index=True)  # open/mitigated/accepted_risk/false_positive
    evidence = Column(JSON, nullable=True)
    justification = Column(Text, nullable=True)
    reviewed_by = Column(String, nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    linked_control_id = Column(String, ForeignKey("unified_controls.id"), nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    vulnerability = relationship("Vulnerability", back_populates="device_matches")
    linked_control = relationship("UnifiedControl")


class DocumentIngestionJob(Base):
    """Tracks one async document_ingestion_service run so the upload
    endpoint can return immediately (parsing/LLM extraction can take a
    while) and the UI can poll status via GET
    /api/controls/ingest-document/{job_id}, matching the TrainingJob /
    NetworkScanJob polling pattern already used elsewhere in this API.
    """
    __tablename__ = "document_ingestion_jobs"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    filename = Column(String, nullable=False)
    source_path = Column(String, nullable=True)
    status = Column(String, default="queued", nullable=False, index=True)  # queued/parsing/extracting/completed/failed
    llm_used = Column(Boolean, default=False, nullable=False)
    controls_created = Column(Integer, default=0, nullable=False)
    sections_found = Column(Integer, default=0, nullable=False)
    warning = Column(Text, nullable=True)
    error = Column(Text, nullable=True)
    created_by = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)


class DeviceMetricSnapshot(Base):
    """One polled health/performance sample for a device (Phase 15 --
    metrics history & trending). Populated by
    app.workers.metrics_poller_worker on a fixed interval, independent of
    on-demand gateway-get-health-metrics calls used by the Device Detail
    "live" panel. Storing snapshots (instead of only the live value) is
    what makes interface *utilization* possible -- ifHCIn/OutOctets are
    cumulative counters, so utilization needs the delta between two
    samples and the elapsed time, not a single point-in-time read -- and
    is what powers CPU/memory/traffic trend charts and threshold alerting.
    """
    __tablename__ = "device_metric_snapshots"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False, index=True)
    collected_at = Column(DateTime, default=datetime.utcnow, index=True)
    source = Column(String, nullable=False, default="snmp")  # snmp/gnmi/restconf -- transport that produced this sample
    success = Column(Boolean, nullable=False, default=True)
    error = Column(Text, nullable=True)
    cpu_average_pct = Column(Float, nullable=True)
    memory_used_pct = Column(Float, nullable=True)
    memory_total_bytes = Column(Float, nullable=True)
    memory_used_bytes = Column(Float, nullable=True)
    # Raw per-interface counters straight from the collector, keyed by
    # if_index -- kept so utilization can always be recomputed against any
    # prior snapshot, not just the immediately-preceding one.
    interface_counters = Column(JSON, nullable=True)
    # Derived per-interface utilization (%) computed against the previous
    # snapshot for this device at insert time -- precomputed so the API/UI
    # never needs to walk history to render a chart.
    interface_utilization = Column(JSON, nullable=True)
    environmental = Column(JSON, nullable=True)  # temperature/fan/power sensor readings, when the device exposes them

    device = relationship("Device")


class TenantSetting(Base):
    """Generic per-tenant key/value config store (Phase 15's first user is
    metrics alert thresholds; deliberately generic -- rather than a
    single-purpose thresholds table -- so later per-tenant settings don't
    each need their own table + migration)."""
    __tablename__ = "tenant_settings"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    key = Column(String, nullable=False, index=True)
    value = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Datacenter(Base):
    """Top level of the physical/logical topology hierarchy: Datacenter ->
    Rack -> Device. Purely organizational (site modeling for Batfish
    grouping and UI navigation) — does not affect scan/compliance logic."""
    __tablename__ = "datacenters"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    name = Column(String, nullable=False)
    location = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    racks = relationship("Rack", back_populates="datacenter")


class Rack(Base):
    """A rack within a Datacenter. Devices are optionally assigned to a rack
    for physical/topology organization and as a convenient unit to group
    into a NetworkGroup for Batfish analysis."""
    __tablename__ = "racks"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    datacenter_id = Column(String, ForeignKey("datacenters.id"), nullable=False, index=True)
    name = Column(String, nullable=False)
    row = Column(String, nullable=True)
    unit_count = Column(Integer, nullable=True)  # e.g. 42U
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    datacenter = relationship("Datacenter", back_populates="racks")


class NetworkGroup(Base):
    """A user-defined 'block'/topology grouping of devices that should be
    analyzed together as a single Batfish network snapshot -- e.g. "DC1
    Core Fabric", "Branch-42 Edge", or an arbitrary logical topology that
    spans racks/datacenters. A device may belong to at most one group at a
    time (see NetworkGroupMember); a group may span multiple racks/DCs.
    """
    __tablename__ = "network_groups"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    datacenter_id = Column(String, ForeignKey("datacenters.id"), nullable=True)
    rack_id = Column(String, ForeignKey("racks.id"), nullable=True)
    last_batfish_status = Column(String, nullable=True)
    last_batfish_run_at = Column(DateTime, nullable=True)
    last_batfish_result = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    members = relationship("NetworkGroupMember", back_populates="group", cascade="all, delete-orphan")
    questions = relationship("BatfishQuestion", back_populates="group", cascade="all, delete-orphan")


class NetworkGroupMember(Base):
    """Join table: which devices belong to a NetworkGroup / topology."""
    __tablename__ = "network_group_members"
    id = Column(String, primary_key=True, default=gen_uuid)
    group_id = Column(String, ForeignKey("network_groups.id"), nullable=False, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    group = relationship("NetworkGroup", back_populates="members")


class BatfishQuestion(Base):
    """An admin-authored 'desired network behaviour' check for Batfish to
    evaluate against a NetworkGroup's uploaded configs, e.g. "Guest VLAN
    must never reach Management" or "Core-A must always reach Core-B".
    `question_type` selects which Batfish question batfish_service runs;
    `params` supplies its arguments. Kept structured (not free-text/eval)
    so results stay deterministic and auditable, matching the rest of the
    app's Batfish-is-authoritative design.
    """
    __tablename__ = "batfish_questions"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    group_id = Column(String, ForeignKey("network_groups.id"), nullable=False, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String, nullable=False, default="MEDIUM")
    enabled = Column(Boolean, nullable=False, default=True)
    # question_type: reachability | acl_reachability | filter_line_reachability
    #   | ip_owners | subnet_multipath | traceroute | bgp_session_status
    #   | undefined_references | node_properties
    question_type = Column(String, nullable=False)
    params = Column(JSON, nullable=True)  # e.g. {"start_location": "...", "end_location": "...", "expected_reachable": false}
    created_by = Column(String, nullable=True)
    last_status = Column(String, nullable=True)
    last_result = Column(JSON, nullable=True)
    last_run_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    group = relationship("NetworkGroup", back_populates="questions")


class EventTrigger(Base):
    """Phase 16 -- user-configurable event-driven pipeline trigger.

    Lets a tenant say "when <event_type> happens (optionally matching
    <filter>), do <action_type>" without touching code -- e.g. "when
    metrics.threshold_breached fires for a device tagged 'core', run
    schedule X" or "when compliance.scan.completed fires with a FAIL
    decision, create a CRITICAL alert". Evaluated by
    app.services.event_trigger_service.dispatch(), called from
    app.events.publish() itself (not a separate NATS consumer process) so
    triggers fire identically whether or not a live NATS broker is present
    -- the same offline-safe pattern app.gateway.publisher already uses
    for job submission.
    """
    __tablename__ = "event_triggers"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    enabled = Column(Boolean, nullable=False, default=True)
    event_type = Column(String, nullable=False, index=True)  # e.g. "metrics.threshold_breached", "compliance.scan.completed"
    # Simple, safe (non-eval) condition matcher: {"field": "decision", "op":
    # "eq", "value": "FAIL"} or a list of such clauses (AND-ed together).
    # See event_trigger_service._matches() for the supported operators.
    filter = Column(JSON, nullable=True)
    action_type = Column(String, nullable=False)  # run_schedule | create_alert
    action_config = Column(JSON, nullable=True)  # {"schedule_id": "..."} or {"category","severity","title_template"}
    cooldown_seconds = Column(Integer, nullable=False, default=0)  # suppress re-firing within this window
    last_triggered_at = Column(DateTime, nullable=True)
    trigger_count = Column(Integer, nullable=False, default=0)
    created_by = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class EventTriggerLog(Base):
    """One firing (or skipped/failed evaluation) of an EventTrigger --
    audit trail for "why did this schedule run at 3am" style questions."""
    __tablename__ = "event_trigger_logs"
    id = Column(String, primary_key=True, default=gen_uuid)
    trigger_id = Column(String, ForeignKey("event_triggers.id"), nullable=False, index=True)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    event_type = Column(String, nullable=False)
    event_payload = Column(JSON, nullable=True)
    outcome = Column(String, nullable=False)  # fired | skipped_filter | skipped_cooldown | failed
    action_result = Column(JSON, nullable=True)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class RollbackRecord(Base):
    """Phase 15b -- one rollback attempt for a DRIFTED or VERIFIED
    DeploymentRecord. A rollback is only ever initiated by an authenticated
    human (RULE 4/5, same as deployment_service). Never reports success
    without re-collecting and re-hashing the device's actual configuration
    (section 12 of the Part 3 integration brief).

    `status` lifecycle:
      PENDING  -> ROLLED_BACK (push succeeded) -> VERIFIED (hash matches)
                                                -> CRITICAL_MANUAL_INTERVENTION_REQUIRED (hash mismatch)
               -> CRITICAL_MANUAL_INTERVENTION_REQUIRED (push failed / no config / no creds)
    """
    __tablename__ = "rollback_records"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    deployment_record_id = Column(String, ForeignKey("deployment_records.id"), nullable=False, index=True)
    change_request_id = Column(String, ForeignKey("change_requests.id"), nullable=False, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False, index=True)
    initiated_by = Column(String, nullable=True)
    reason = Column(Text, nullable=True)
    transport = Column(String, nullable=True)   # ssh/netconf/gnmi -- inherited from the original deployment
    # The configuration hash we are rolling BACK TO (cr.current_config_hash).
    # Stored here so the verification step has a target that is immutable
    # once the rollback row is created, even if the CR row is later updated.
    target_config_hash = Column(String, nullable=True)
    status = Column(String, default="PENDING", nullable=False, index=True)
    # Result of re-collecting the device config after the rollback push.
    post_rollback_hash = Column(String, nullable=True)
    post_rollback_verified = Column(Boolean, nullable=True)
    # Scan created by re-running the compliance pipeline on the post-rollback
    # config (same evidence-trail pattern as deployment_service).
    post_rollback_scan_id = Column(String, ForeignKey("scans.id"), nullable=True)
    error = Column(Text, nullable=True)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    # Ordered per-stage progress, same shape as DeploymentRecord.stages.
    stages = Column(JSON, nullable=True)


class User(Base):
    """Local username/password account, used when AUTH_ENABLED=true and no
    Keycloak token is presented (see auth/local.py, auth/passwords.py).

    Coexists with Keycloak: auth/dependencies.py tries a local HS256 token
    first (by checking the unverified header's `alg`/issuer) and falls back
    to Keycloak RS256 validation, so a deployment can use either or both.
    """
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    username = Column(String, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    # Comma-free JSON list, e.g. ["admin"], ["viewer", "auditor"].
    roles = Column(JSON, nullable=False, default=list)
    is_active = Column(Boolean, nullable=False, default=True)
    # Bumped on password change / forced logout so previously issued tokens
    # (which embed the version they were minted with) stop validating
    # without needing a revocation list.
    token_version = Column(Integer, nullable=False, default=0)
    failed_login_count = Column(Integer, nullable=False, default=0)
    locked_until = Column(DateTime, nullable=True)
    last_login_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("tenant_id", "username", name="uq_users_tenant_username"),
    )