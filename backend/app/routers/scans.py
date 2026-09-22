from typing import Any, Dict, List, Optional
from datetime import datetime
import asyncio
import logging
import os

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile, BackgroundTasks
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.db import BatfishAnalysis, Device, Finding, Scan, Tenant
from app.routers.devices import get_or_create_demo_tenant
from app.schemas import ScanDetailOut, ScanOut
from app.services import audit_service, scan_deletion, scan_runner
from app.services.pipeline import STAGE_LABELS, mark_resuming, validate_resumable
from app.services.scan_runner import TERMINAL_SCAN_STATUSES, has_live_task, scan_phase
from app.services.vendor_detect import detect_vendor

from app.auth.dependencies import CurrentUser, get_current_user, require_role

logger = logging.getLogger("scans")

router = APIRouter(prefix="/api/scans", tags=["scans"], dependencies=[Depends(get_current_user)])

MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5MB safety cap for uploaded config files
# Bulk-upload guard rails. Queued scans hold their config text in memory
# until they get a pipeline slot, so bound the batch.
MAX_BULK_FILES = int(os.getenv("SCAN_BULK_MAX_FILES", "50"))
MAX_BULK_TOTAL_BYTES = int(os.getenv("SCAN_BULK_MAX_TOTAL_BYTES", str(50 * 1024 * 1024)))

# Kept as module-level names: other modules/tests import these from here.
RUNNING_SCAN_TASKS = scan_runner.RUNNING_SCAN_TASKS

_ANY_WRITE_ROLES = ("admin", "operator", "security_analyst")


def _detail(scan: Scan, db: Session) -> ScanDetailOut:
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    return ScanDetailOut(**ScanOut.model_validate(scan).model_dump(), baseline_json=scan.baseline_json, findings=findings)


def _tenant_for(db: Session, user: CurrentUser) -> Tenant:
    tenant = db.get(Tenant, user.tenant_id) if getattr(user, "tenant_id", None) else None
    return tenant or get_or_create_demo_tenant(db)


def _adhoc_device(db: Session, tenant: Tenant) -> Device:
    """The shared 'Ad-Hoc Config Uploads' sandbox device (reused so uploads
    don't clutter the inventory with one device per file)."""
    device = db.query(Device).filter(
        Device.tenant_id == tenant.id, Device.hostname == "Ad-Hoc Config Uploads", Device.vendor == "Ad-Hoc",
    ).first()
    if not device:
        device = Device(
            tenant_id=tenant.id, hostname="Ad-Hoc Config Uploads", vendor="Ad-Hoc", os=None,
            description="Sandbox device for config uploads", enabled=False,
        )
        db.add(device)
        db.commit()
        db.refresh(device)
    return device


def _scan_or_404(db: Session, scan_id: str, user: CurrentUser) -> Scan:
    scan = db.get(Scan, scan_id)
    if not scan or (getattr(user, "tenant_id", None) and scan.tenant_id != user.tenant_id):
        raise HTTPException(404, "Scan not found")
    return scan


def _clean_filename(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    return os.path.basename(name.replace("\\", "/"))[:255] or None


def _upload_problem(raw: bytes) -> Optional[str]:
    """Reason a file can't be scanned as a text config, else None."""
    if len(raw) > MAX_UPLOAD_BYTES:
        return f"Configuration file too large (max {MAX_UPLOAD_BYTES // (1024 * 1024)}MB)"
    if not raw.strip():
        return "Configuration file is empty"
    if b"\x00" in raw[:8192]:
        return "File is binary, not a text configuration"
    return None


@router.post("/upload", response_model=ScanDetailOut)
async def upload_config(
    file: UploadFile = File(...),
    framework: str = Form("ALL"),
    hostname: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_role(*_ANY_WRITE_ROLES)),
):
    raw_bytes = await file.read(MAX_UPLOAD_BYTES + 1)
    problem = _upload_problem(raw_bytes)
    if problem:
        raise HTTPException(413 if "too large" in problem else 400, problem)
    raw_text = raw_bytes.decode("utf-8", errors="replace")

    guess = detect_vendor(raw_text)
    tenant = _tenant_for(db, user)

    # SECURITY/spec section 4: do NOT assign vendor/os from the raw guess
    # here -- a review_required guess (low confidence, or a vendor outside
    # the six supported ones) must never become a confident device identity.
    # run_pipeline() re-runs detect_vendor() and is the single place that
    # gates vendor/os assignment on review_required.
    if not hostname:
        device = _adhoc_device(db, tenant)
    else:
        device = Device(
            tenant_id=tenant.id,
            hostname=hostname,
            vendor=None if guess.review_required else guess.vendor,
            os=None if guess.review_required else guess.os,
        )
        db.add(device)
        db.commit()
        db.refresh(device)

    scan = Scan(
        tenant_id=tenant.id, device_id=device.id, framework=framework, status="uploaded",
        source_filename=_clean_filename(file.filename),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # The pipeline runs in the background (never inside this request): the
    # call returns as soon as the Scan row exists and the frontend polls
    # for progress. scan_runner registers the task so it can be stopped.
    scan_runner.start_scan_task(scan.id, raw_text, framework)
    return _detail(scan, db)


@router.post("/bulk-upload", response_model=List[ScanDetailOut])
async def bulk_upload(
    files: List[UploadFile] = File(...),
    framework: str = Form("ALL"),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_role(*_ANY_WRITE_ROLES)),
):
    """Queue many configuration files at once.

    Returns immediately with one scan per file (status ``queued``); pipelines
    then run in the background, at most SCAN_PIPELINE_CONCURRENCY at a time,
    so a big batch can't flood the LLM / Batfish / DB pool. One bad file
    never sinks the batch: it becomes a visible ``failed`` scan with the
    reason instead (untrusted input is never silently discarded).
    """
    if not files:
        raise HTTPException(400, "No files were uploaded")
    if len(files) > MAX_BULK_FILES:
        raise HTTPException(413, f"Too many files: {len(files)} (max {MAX_BULK_FILES} per batch)")

    # Read everything first (bounded per file and in total) so an over-limit
    # batch is rejected before any scan rows exist.
    payloads: List[tuple] = []
    total = 0
    for f in files:
        raw = await f.read(MAX_UPLOAD_BYTES + 1)
        total += min(len(raw), MAX_UPLOAD_BYTES)
        if total > MAX_BULK_TOTAL_BYTES:
            raise HTTPException(413, f"Batch too large (max {MAX_BULK_TOTAL_BYTES // (1024 * 1024)}MB in total)")
        payloads.append((_clean_filename(f.filename) or "config", raw))

    tenant = _tenant_for(db, user)
    device = _adhoc_device(db, tenant)

    created: List[tuple] = []  # (Scan, raw_bytes | None)
    for name, raw in payloads:
        problem = _upload_problem(raw)
        scan = Scan(
            tenant_id=tenant.id, device_id=device.id, framework=framework, source_filename=name,
            status="failed" if problem else "queued", error=problem,
        )
        db.add(scan)
        created.append((scan, None if problem else raw))
    db.commit()  # one transaction for the whole batch
    for scan, _ in created:
        db.refresh(scan)

    to_archive = []
    for scan, raw in created:
        if raw is None:
            continue
        scan_runner.start_scan_task(scan.id, raw.decode("utf-8", errors="replace"), framework)
        to_archive.append((scan.id, scan.tenant_id, scan.device_id, raw))
    scan_runner.archive_raw_configs_in_background(to_archive)

    return [_detail(scan, db) for scan, _ in created]


@router.get("", response_model=List[ScanOut])
def list_scans(
    device_id: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    q = db.query(Scan)
    if device_id:
        q = q.filter(Scan.device_id == device_id)
    return q.order_by(Scan.created_at.desc()).limit(limit).all()


@router.get("/running", response_model=List[ScanOut])
def list_running_scans(db: Session = Depends(get_db)):
    """Scans whose pipeline is still in flight, queued, paused, or has a
    pending pause/stop request -- i.e. anything not in a terminal state.
    Backs the 'Running Pipelines' panel.

    Lazily repairs scans whose pipeline no longer exists (stuck
    *_REQUESTED) so they can't linger here forever.

    NOTE: must stay declared before GET /{scan_id} below -- otherwise
    scan_id="running" would be matched by the dynamic route and 404.
    """
    try:
        scan_runner.reconcile_stale(db)
    except Exception:  # noqa: BLE001 - never let repair break the listing
        logger.exception("reconcile_stale failed")
        db.rollback()
    return (
        db.query(Scan)
        .filter(~Scan.status.in_(TERMINAL_SCAN_STATUSES))
        .order_by(Scan.created_at.desc())
        .limit(100)
        .all()
    )


# ---- bulk actions (declared before /{scan_id} routes) ------------------------

class BulkStopRequest(BaseModel):
    scan_ids: List[str] = Field(min_length=1, max_length=500)
    immediate: bool = True


class BulkDeleteRequest(BaseModel):
    scan_ids: List[str] = Field(min_length=1, max_length=500)
    force: bool = False


@router.post("/bulk-stop")
async def bulk_stop_scans(
    payload: BulkStopRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_role(*_ANY_WRITE_ROLES)),
):
    """Stop many scans in one call. All live tasks are cancelled together and
    every scan is finalized before this returns (see scan_runner.stop_scans)."""
    ids = list(dict.fromkeys(payload.scan_ids))
    scans = db.query(Scan).filter(Scan.id.in_(ids), Scan.tenant_id == user.tenant_id).all()
    found = {s.id for s in scans}
    outcomes = await scan_runner.stop_scans(db, scans, immediate=payload.immediate)
    stopped = [i for i, o in outcomes.items() if o in ("stopped", "already_stopped", "stopping")]
    skipped = [{"id": i, "detail": "Scan has already finished; nothing to stop"} for i, o in outcomes.items() if o == "finished"]
    skipped += [{"id": i, "detail": "Scan not found"} for i in ids if i not in found]
    audit_service.record_from_user(
        db, user, action="scan.bulk_stop", request=request, result="SUCCESS", object_type="scan", object_id=None,
        new_value={"requested": len(ids), "stopped": stopped, "immediate": payload.immediate},
    )
    return {"stopped": stopped, "skipped": skipped}


@router.post("/bulk-delete")
async def bulk_delete_scans(
    payload: BulkDeleteRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_role("admin", "operator")),
):
    """Delete many scans. Partial success is normal: the response lists what
    was ``deleted`` and, for everything that wasn't, a ``failed`` entry with
    the reason (still running, golden baseline, not found). ``force`` stops
    running scans first and overrides the golden-baseline protection."""
    deleted, failed = await _delete_scans(db, list(dict.fromkeys(payload.scan_ids)), payload.force, user)
    audit_service.record_from_user(
        db, user, action="scan.bulk_delete", request=request, result="SUCCESS" if deleted else "FAILURE",
        object_type="scan", object_id=None,
        new_value={"requested": len(payload.scan_ids), "deleted": deleted, "failed": [f["id"] for f in failed], "force": payload.force},
    )
    return {"deleted": deleted, "failed": [{"id": f["id"], "detail": f["detail"]} for f in failed]}


async def _delete_scans(db: Session, ids: List[str], force: bool, user: CurrentUser):
    scans = {s.id: s for s in db.query(Scan).filter(Scan.id.in_(ids), Scan.tenant_id == user.tenant_id).all()}
    failed: List[Dict[str, Any]] = []
    doomed: List[str] = []
    golden = set(scan_deletion.golden_baseline_scan_ids(db, list(scans)))
    to_stop: List[Scan] = []

    for sid in ids:
        scan = scans.get(sid)
        if scan is None:
            failed.append({"id": sid, "status": 404, "detail": "Scan not found"})
            continue
        live = scan_phase(scan) == "live" or has_live_task(sid)
        if live and not force:
            failed.append({"id": sid, "status": 409, "detail": "Scan is still running. Stop it first, or force delete."})
            continue
        if sid in golden and not force:
            failed.append({
                "id": sid, "status": 409,
                "detail": "This scan is the approved golden baseline for its device. Deleting it removes that baseline.",
            })
            continue
        if live:
            to_stop.append(scan)
        doomed.append(sid)

    if to_stop:
        # Cancel first so no pipeline task is still writing rows we're about to delete.
        await scan_runner.stop_scans(db, to_stop, immediate=True)

    deleted: List[str] = []

    def _purge(batch: List[str]) -> None:
        scan_deletion.purge_scans(db, batch)
        db.commit()

    try:
        if doomed:
            _purge(doomed)
        deleted = list(doomed)
    except Exception:  # noqa: BLE001 - isolate the offender, keep the rest
        db.rollback()
        logger.exception("bulk scan delete failed; retrying one by one")
        for sid in doomed:
            try:
                _purge([sid])
                deleted.append(sid)
            except Exception as exc:  # noqa: BLE001
                db.rollback()
                logger.exception("delete of scan %s failed", sid)
                failed.append({"id": sid, "status": 500, "detail": f"Delete failed: {exc.__class__.__name__}"})
    return deleted, failed


@router.delete("/{scan_id}")
async def delete_scan(
    scan_id: str,
    request: Request,
    force: bool = Query(False, description="Stop a running scan first and override the golden-baseline protection."),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_role("admin", "operator")),
):
    """Delete one scan and its findings / OPA / Batfish / AI results. Evidence
    records and topology snapshots are kept but detached from it."""
    deleted, failed = await _delete_scans(db, [scan_id], force, user)
    audit_service.record_from_user(
        db, user, action="scan.delete", request=request, result="SUCCESS" if deleted else "FAILURE",
        object_type="scan", object_id=scan_id, new_value={"force": force},
    )
    if failed:
        raise HTTPException(failed[0]["status"], failed[0]["detail"])
    return {"deleted": scan_id}


@router.get("/{scan_id}", response_model=ScanDetailOut)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return _detail(scan, db)


@router.post("/{scan_id}/rerun", response_model=ScanDetailOut)
async def rerun_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    _user=Depends(require_role("admin", "operator", "security_analyst")),
):
    """Re-evaluate a scan — used in the demo to show that after training an
    unknown command, re-running recognizes it via the pgvector-backed
    knowledge base.

    Per problem-statement section 23, a rerun re-executes OPA, Batfish,
    risk, correlation, and evidence generation (not just a raw finding
    refresh), and produces a NEW evidence record rather than overwriting the
    old one — every scan's evidence history is immutable (RULE 15)."""
    import hashlib

    from app.models.baseline import SecurityBaselineModel
    from app.models.db import OPAAnalysis
    from app.services import evidence_service, risk_engine
    from app.services.change_validation_service import correlate
    from app.services.compliance import compute_score, evaluate_baseline_via_opa, opa_decision_to_findings

    scan = db.query(Scan).get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    device = db.query(Device).get(scan.device_id)
    db.query(Finding).filter(Finding.scan_id == scan_id).delete()
    db.commit()

    baseline = SecurityBaselineModel(**scan.baseline_json)
    opa_decision = await evaluate_baseline_via_opa(scan.id, baseline, scan.framework, db=db, tenant_id=scan.tenant_id)
    db.add(OPAAnalysis(
        scan_id=scan.id, policy_version=opa_decision.policy_version, decision=opa_decision.decision,
        decision_id=opa_decision.decision_id, source=opa_decision.source, result_json=opa_decision.to_dict(),
    ))
    scan.opa_decision = opa_decision.decision
    scan.opa_policy_version = opa_decision.policy_version
    scan.opa_decision_id = opa_decision.decision_id

    findings = opa_decision_to_findings(opa_decision, baseline)
    for f in findings:
        db.add(Finding(scan_id=scan.id, **f))

    # Note: the original raw configuration text isn't persisted verbatim on
    # the scan row (only its SHA-256 is, by design — see raw_config_hash);
    # a rerun therefore re-evaluates OPA/risk/correlation against the stored
    # baseline and reuses the last Batfish behavioral result rather than
    # re-uploading bytes it doesn't have. A fresh Batfish run happens on the
    # next full upload of a changed candidate configuration.
    last_batfish = (
        db.query(BatfishAnalysis)
        .filter(BatfishAnalysis.scan_id == scan_id)
        .order_by(BatfishAnalysis.created_at.desc())
        .first()
    )
    batfish_status = (last_batfish.status if last_batfish else scan.batfish_status) or "NOT_INTEGRATED"
    batfish_critical = bool(last_batfish and last_batfish.critical_violation)
    batfish_result_json = (last_batfish.result_json if last_batfish else {"status": batfish_status})
    batfish_findings = (batfish_result_json or {}).get("reachability_checks", [])

    score = compute_score(findings)

    risk = risk_engine.calculate_risk(opa_decision.findings, batfish_findings=batfish_findings)
    scan.risk_score = risk.risk_score
    scan.risk_level = risk.risk_level

    decision = correlate(
        syntax_ok=True, opa_decision=opa_decision, risk=risk, batfish_status=batfish_status,
        batfish_critical_violation=batfish_critical,
    )
    scan.final_decision = decision.decision
    scan.final_reason = decision.reason
    scan.batfish_status = batfish_status

    evidence = evidence_service.build_evidence(
        scan_id=scan.id, device_id=scan.device_id, tenant_id=scan.tenant_id,
        event_type="scan.rerun", actor="system:rerun", vendor=baseline.device.vendor or "Unknown",
        config_hash=scan.raw_config_hash,
        baseline_hash=hashlib.sha256(evidence_service.canonicalize_evidence(scan.baseline_json).encode()).hexdigest(),
        opa_result=opa_decision.to_dict(), batfish_result=batfish_result_json,
        risk_result=risk.to_dict(), final_decision=decision.decision, framework=scan.framework,
        control_ids=[f["control_id"] for f in findings], finding_ids=[],
    )
    canonical = evidence_service.canonicalize_evidence(evidence)
    evidence_hash = evidence_service.hash_evidence(canonical)
    record = evidence_service.store_evidence(db, evidence, evidence_hash)
    scan.evidence_id = record.evidence_id

    scan.compliance_score = score
    scan.status = {"PASS": "completed", "REVIEW": "review", "BLOCK": "blocked"}[decision.decision]
    db.commit()
    db.refresh(scan)
    findings_out = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    return ScanDetailOut(**ScanOut.model_validate(scan).model_dump(), baseline_json=scan.baseline_json, findings=findings_out)


@router.post("/{scan_id}/pause", response_model=ScanDetailOut)
async def pause_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_role(*_ANY_WRITE_ROLES)),
):
    """Request that a running scan's pipeline pause at its next stage
    checkpoint. If no pipeline is actually alive for it (orphaned by a
    restart) there is no checkpoint to wait for, so it is paused directly."""
    scan = _scan_or_404(db, scan_id, user)
    if scan_phase(scan) != "live" or scan.control_state not in ("RUNNING", "PAUSE_REQUESTED", None):
        raise HTTPException(409, f"Scan is not running (status={scan.status}, control_state={scan.control_state}); nothing to pause")
    if has_live_task(scan_id):
        scan.control_state = "PAUSE_REQUESTED"
    else:
        scan.status, scan.control_state, scan.paused_at = "paused", "PAUSED", datetime.utcnow()
    db.commit()
    db.refresh(scan)
    return _detail(scan, db)


@router.post("/{scan_id}/stop", response_model=ScanDetailOut)
async def stop_scan(
    scan_id: str,
    immediate: bool = Query(
        False,
        description="Force stop: cancel the in-flight pipeline task now instead of waiting for its next stage "
        "checkpoint. Whatever the current stage had already committed is kept; it can be resumed later.",
    ),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_role(*_ANY_WRITE_ROLES)),
):
    """Stop a scan. A stopped scan is not discarded -- its checkpoint is kept
    and /{scan_id}/resume can restart it from there.

    Idempotent and always terminal: with immediate=True the scan is STOPPED
    when this returns, even if no pipeline task existed for it (queued,
    orphaned by a reload, already paused). Stopping an already-stopped scan
    just returns it; only a scan that already *finished* is a 409.
    """
    scan = _scan_or_404(db, scan_id, user)
    outcomes = await scan_runner.stop_scans(db, [scan], immediate=immediate)
    if outcomes.get(scan_id) == "finished":
        raise HTTPException(409, f"Scan has already finished (status={scan.status}); nothing to stop")
    db.refresh(scan)
    return _detail(scan, db)


@router.post("/{scan_id}/resume", response_model=ScanDetailOut)
async def resume_scan(
    scan_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_role(*_ANY_WRITE_ROLES)),
):
    """Resume a PAUSED or STOPPED scan from its last checkpointed stage.

    Returns immediately (status ``resuming``); the pipeline continues in the
    background like the original upload, so it shows up in the running list
    and can be paused/stopped again."""
    scan = _scan_or_404(db, scan_id, user)
    if scan.control_state not in ("PAUSED", "STOPPED"):
        raise HTTPException(409, f"Scan is not paused or stopped (control_state={scan.control_state}); nothing to resume")

    # If it's a device-based scan that crashed before it even finished collecting and archiving
    # its configuration to MinIO, a normal pipeline resume would fail. Instead, gracefully restart collection.
    if not scan.raw_config_path and not scan.source_filename and scan.device_id:
        scan.control_state = "RUNNING"
        scan.status = "resuming"
        scan.error = None
        db.commit()

        from app.routers.devices import _background_collect_and_scan
        background_tasks.add_task(
            _background_collect_and_scan,
            scan_id=scan.id,
            device_id=scan.device_id,
            tenant_id=scan.tenant_id,
            framework=scan.framework or "ALL",
            user_subject=user.subject,
        )
        db.refresh(scan)
        return _detail(scan, db)

    try:
        validate_resumable(scan)
    except ValueError as e:
        raise HTTPException(400, str(e))
    mark_resuming(db, scan)
    scan_runner.start_resume_task(scan.id)
    db.refresh(scan)
    return _detail(scan, db)


@router.get("/{scan_id}/pipeline-status")
def get_pipeline_status(scan_id: str, db: Session = Depends(get_db)):
    """Lightweight polling endpoint for a pause/resume UI: current stage,
    control_state, and a human label, without the full scan/findings
    payload get_scan() returns."""
    scan = db.query(Scan).get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return {
        "scan_id": scan.id,
        "status": scan.status,
        "control_state": scan.control_state,
        "pipeline_stage": scan.pipeline_stage,
        "pipeline_stage_label": STAGE_LABELS.get(scan.pipeline_stage or "", scan.pipeline_stage),
        "paused_at": scan.paused_at.isoformat() if scan.paused_at else None,
        "resumed_at": scan.resumed_at.isoformat() if scan.resumed_at else None,
        "stopped_at": scan.stopped_at.isoformat() if scan.stopped_at else None,
        "can_pause": scan.control_state == "RUNNING",
        "can_stop": scan.control_state in ("RUNNING", "PAUSE_REQUESTED", "PAUSED"),
        "can_resume": scan.control_state in ("PAUSED", "STOPPED"),
    }


@router.get("/{scan_id}/batfish")
def get_batfish_analysis(scan_id: str, db: Session = Depends(get_db)):
    """Latest Batfish behavioral-analysis result for this scan (nodes,
    interfaces, routes, reachability checks, init issues) — powers the
    Batfish Analysis UI page."""
    scan = db.query(Scan).get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    analysis = (
        db.query(BatfishAnalysis)
        .filter(BatfishAnalysis.scan_id == scan_id)
        .order_by(BatfishAnalysis.created_at.desc())
        .first()
    )
    if not analysis:
        return {"status": "NOT_INTEGRATED", "scan_id": scan_id}
    return {
        "scan_id": scan_id,
        "status": analysis.status,
        "network_name": analysis.network_name,
        "snapshot_name": analysis.snapshot_name,
        "critical_violation": analysis.critical_violation,
        "init_issues": analysis.init_issues,
        "created_at": analysis.created_at,
        **(analysis.result_json or {}),
    }


@router.get("/{scan_id}/opa")
def get_opa_analysis(scan_id: str, db: Session = Depends(get_db)):
    """Latest OPA policy-evaluation result for this scan — powers the
    Policy Evaluation UI page."""
    from app.models.db import OPAAnalysis

    scan = db.query(Scan).get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    analysis = (
        db.query(OPAAnalysis)
        .filter(OPAAnalysis.scan_id == scan_id)
        .order_by(OPAAnalysis.created_at.desc())
        .first()
    )
    if not analysis:
        return {"status": "OPA_UNAVAILABLE", "scan_id": scan_id}
    return {
        "scan_id": scan_id,
        "policy_version": analysis.policy_version,
        "decision": analysis.decision,
        "decision_id": analysis.decision_id,
        "source": analysis.source,
        "created_at": analysis.created_at,
        **(analysis.result_json or {}),
    }


@router.get("/{scan_id}/remediation/generate-cli")
async def get_remediation_suggestions(scan_id: str, db: Session = Depends(get_db)):
    """Phase 14 AI Feature Extension: Retrieve or LLM-synthesize remediation CLI recommendations.

    Deliberately namespaced under /generate-cli (not the bare
    /{scan_id}/remediation path) so it reads as the opt-in, AI-assisted
    action it is -- the unmarked, default-trust path is
    /{scan_id}/remediation-suggestions below, which never invents
    configuration. See that endpoint's docstring and
    tests/test_change_requests.py::test_remediation_suggestions_never_invents_config.
    """
    from app.services.remediation_service import generate_remediation_cli_for_scan
    scan = db.query(Scan).get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    
    # Asynchronously invoke the LLM proxy
    return await generate_remediation_cli_for_scan(db, scan)


@router.get("/{scan_id}/remediation-suggestions")
def get_stored_remediation_suggestions(scan_id: str, db: Session = Depends(get_db)):
    """Deterministic, anti-fabrication counterpart to /{scan_id}/remediation
    (RULE 12): surfaces each FAIL finding's already-stored `remediation`
    guidance text verbatim -- the same string an OPA control author wrote
    into policies/common/controls.rego -- and never asks an LLM to invent
    CLI configuration. Use this endpoint when a human just needs "what do
    I fix and why", not synthesized commands to paste onto a device (see
    tests/test_change_requests.py::test_remediation_suggestions_never_invents_config).
    """
    scan = db.query(Scan).get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id, Finding.result == "FAIL")
        .order_by(Finding.severity)
        .all()
    )
    suggestions = [
        {
            "control_id": f.control_id,
            "title": f.title,
            "severity": f.severity,
            "parameter": f.parameter,
            "guidance": f.remediation,
        }
        for f in findings
    ]
    return {
        "scan_id": scan_id,
        "finding_count": len(findings),
        "suggestions": suggestions,
        "note": "Guidance text authored on each control; this endpoint has not generated configuration.",
    }