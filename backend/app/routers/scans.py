from typing import Dict, List, Optional
from datetime import datetime
import asyncio

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from sqlalchemy.orm import Session

from app.db import SessionLocal, get_db
from app.models.db import BatfishAnalysis, Device, Finding, Scan
from app.routers.devices import get_or_create_demo_tenant
from app.schemas import ScanDetailOut, ScanOut
from app.services.pipeline import STAGE_LABELS, resume_pipeline, run_pipeline
from app.services.vendor_detect import detect_vendor

from app.auth.dependencies import get_current_user, require_role

router = APIRouter(prefix="/api/scans", tags=["scans"], dependencies=[Depends(get_current_user)])

MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5MB safety cap for uploaded config files

# Scan statuses a pipeline never leaves once reached -- everything else
# means it's queued, actively running, or paused/stop-requested and
# therefore belongs in the "running pipelines" list below.
TERMINAL_SCAN_STATUSES = {"completed", "review", "blocked", "failed", "stopped"}

# Tracks the live asyncio.Task for each scan currently being processed in
# the background, so an "immediate" stop can cancel it directly instead of
# only flipping control_state and waiting for run_pipeline's own
# checkpoint to notice (see stop_scan(..., immediate=True) below). Populated
# in upload_config/bulk_upload, cleared by _run_scan_pipeline_in_own_session
# itself once it finishes (normally, on failure, or on cancellation).
RUNNING_SCAN_TASKS: Dict[str, asyncio.Task] = {}


async def _run_scan_pipeline_in_own_session(scan_id: str, raw_text: str, framework: str) -> None:
    """Runs off the request's async context (which is gone by the time this
    executes) -- open a fresh session here, matching how
    document_ingestion's _run_job_in_own_session handles the same problem.

    run_pipeline() already persists status="failed" + scan.error on a
    genuine failure (see services/pipeline.py) before re-raising, so a plain
    Exception here just needs to be swallowed -- the scan row already
    recorded it. asyncio.CancelledError (from stop_scan(..., immediate=True)
    cancelling this task directly) is handled separately: it isn't an
    Exception subclass, so it isn't caught below, and run_pipeline's own
    stage-boundary checkpoints never got a chance to see it -- this is the
    one place that persists the STOPPED state for that path.
    """
    db = SessionLocal()
    try:
        scan = db.query(Scan).get(scan_id)
        if not scan:
            return
        try:
            await run_pipeline(db, scan, raw_text, framework=framework)
        except asyncio.CancelledError:
            try:
                db.rollback()
                scan = db.query(Scan).get(scan_id)
                if scan and scan.control_state != "STOPPED":
                    scan.status = "stopped"
                    scan.control_state = "STOPPED"
                    scan.stopped_at = datetime.utcnow()
                    db.commit()
            except Exception:
                pass
            raise
        except Exception:
            pass
    finally:
        RUNNING_SCAN_TASKS.pop(scan_id, None)
        db.close()


@router.post("/upload", response_model=ScanDetailOut)
async def upload_config(
    file: UploadFile = File(...),
    framework: str = Form("ALL"),
    hostname: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _user=Depends(require_role("admin", "operator", "security_analyst")),
):
    raw_bytes = await file.read()
    if len(raw_bytes) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "Configuration file too large (max 5MB)")
    try:
        raw_text = raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(400, "Unable to decode configuration file as text")

    guess = detect_vendor(raw_text)
    tenant = get_or_create_demo_tenant(db)

    # SECURITY/spec section 4: do NOT assign vendor/os from the raw guess
    # here -- a review_required guess (low confidence, or a vendor outside
    # the six supported ones) must never become a confident device identity.
    # run_pipeline() below re-runs detect_vendor() and is the single place
    # that gates vendor/os assignment on review_required; setting it here
    # first would silently defeat that gate (device.vendor would already be
    # populated by the time pipeline.py's `device.vendor or guess.vendor`
    # check runs).
    guest_hostname = hostname or "Ad-Hoc Config Uploads"
    
    # Try to reuse the Ad-Hoc Config Uploads device to avoid cluttering the inventory
    if not hostname:
        device = db.query(Device).filter(
            Device.tenant_id == tenant.id, 
            Device.hostname == guest_hostname,
            Device.vendor == "Ad-Hoc"
        ).first()
        if not device:
            device = Device(
                tenant_id=tenant.id,
                hostname=guest_hostname,
                vendor="Ad-Hoc",
                os=None,
                description="Sandbox device for config uploads",
                enabled=False,
            )
            db.add(device)
            db.commit()
            db.refresh(device)
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

    scan = Scan(tenant_id=tenant.id, device_id=device.id, framework=framework, status="uploaded")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Run the actual pipeline (parse/normalize/OPA/Batfish/risk/correlate/
    # evidence) as a background task instead of awaiting it here. It used
    # to run synchronously inside this request, so the upload call itself
    # blocked for however long the whole pipeline took -- on a slow config
    # (or one that hit a flaky downstream service) that meant a long-hanging
    # HTTP request the browser could time out on, which is what made a
    # config upload occasionally look like it "bugs out the app". Now the
    # request returns as soon as the Scan row exists (status="uploaded",
    # control_state="RUNNING" by default) and the frontend's existing
    # scan-detail polling picks up progress from there -- same shape it
    # already treats a scan as being in-progress.
    task = asyncio.create_task(_run_scan_pipeline_in_own_session(scan.id, raw_text, framework))
    RUNNING_SCAN_TASKS[scan.id] = task

    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    return ScanDetailOut(
        **ScanOut.model_validate(scan).model_dump(),
        baseline_json=scan.baseline_json,
        findings=findings,
    )


@router.post("/bulk-upload", response_model=List[ScanDetailOut])
async def bulk_upload(
    files: List[UploadFile] = File(...),
    framework: str = Form("ALL"),
    db: Session = Depends(get_db),
    _user=Depends(require_role("admin", "operator", "security_analyst")),
):
    results = []
    for file in files:
        raw_bytes = await file.read()
        tenant = get_or_create_demo_tenant(db)
        if len(raw_bytes) > MAX_UPLOAD_BYTES:
            # Never silently discard untrusted input (spec section 3/16):
            # record a failed device+scan pair so an oversized upload is
            # still visible in the audit trail instead of vanishing.
            device = Device(tenant_id=tenant.id, hostname=file.filename, vendor=None, os=None)
            db.add(device)
            db.commit()
            db.refresh(device)
            scan = Scan(
                tenant_id=tenant.id, device_id=device.id, framework=framework,
                status="failed", error=f"Configuration file too large (max {MAX_UPLOAD_BYTES} bytes)",
            )
            db.add(scan)
            db.commit()
            db.refresh(scan)
            results.append(ScanDetailOut(**ScanOut.model_validate(scan).model_dump(), baseline_json=None, findings=[]))
            continue
        raw_text = raw_bytes.decode("utf-8", errors="replace")
        guess = detect_vendor(raw_text)
        guest_hostname = "Ad-Hoc Config Uploads"
        
        # See upload_config() above -- reuse ad-hoc device.
        device = db.query(Device).filter(
            Device.tenant_id == tenant.id, 
            Device.hostname == guest_hostname,
            Device.vendor == "Ad-Hoc"
        ).first()
        if not device:
            device = Device(
                tenant_id=tenant.id,
                hostname=guest_hostname,
                vendor="Ad-Hoc",
                os=None,
                description="Sandbox device for config uploads",
                enabled=False,
            )
            db.add(device)
            db.commit()
            db.refresh(device)
            
        # Since it's a bulk upload without assigned hostnames per file, we link them all here.
        db.commit()
        db.refresh(device)
        scan = Scan(tenant_id=tenant.id, device_id=device.id, framework=framework, status="uploaded")
        db.add(scan)
        db.commit()
        db.refresh(scan)
        # Same fix as upload_config() above: don't block this loop (and the
        # whole request) on the pipeline for every file in the batch.
        task = asyncio.create_task(_run_scan_pipeline_in_own_session(scan.id, raw_text, framework))
        RUNNING_SCAN_TASKS[scan.id] = task
        findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
        results.append(ScanDetailOut(**ScanOut.model_validate(scan).model_dump(), baseline_json=scan.baseline_json, findings=findings))
    return results


@router.get("", response_model=List[ScanOut])
def list_scans(db: Session = Depends(get_db)):
    return db.query(Scan).order_by(Scan.created_at.desc()).limit(100).all()


@router.get("/running", response_model=List[ScanOut])
def list_running_scans(db: Session = Depends(get_db)):
    """Scans whose pipeline is still in flight, paused, or has a pending
    pause/stop request -- i.e. anything not in a terminal state. Backs the
    'Running Pipelines' panel so an operator can see and stop these without
    hunting through the full scan list.

    NOTE: this must stay declared before GET /{scan_id} below -- a route
    here that fell after the dynamic path would have scan_id="running"
    matched by /{scan_id} instead of this one, 404ing every time.
    """
    return (
        db.query(Scan)
        .filter(~Scan.status.in_(TERMINAL_SCAN_STATUSES))
        .order_by(Scan.created_at.desc())
        .limit(100)
        .all()
    )


@router.get("/{scan_id}", response_model=ScanDetailOut)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    return ScanDetailOut(**ScanOut.model_validate(scan).model_dump(), baseline_json=scan.baseline_json, findings=findings)


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
    _user=Depends(require_role("admin", "operator", "security_analyst")),
):
    """Request that a running scan's pipeline pause at its next stage
    checkpoint (services/pipeline.py::_checkpoint). This only *requests*
    the pause -- the pipeline coroutine itself (which may be another
    in-flight request, e.g. the original /upload call) is what actually
    stops and persists control_state=PAUSED once it reaches a safe point;
    that's usually near-instant, but isn't guaranteed synchronous with
    this call returning."""
    scan = db.query(Scan).get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.control_state not in ("RUNNING", "PAUSE_REQUESTED"):
        raise HTTPException(409, f"Scan is not running (control_state={scan.control_state}); nothing to pause")
    scan.control_state = "PAUSE_REQUESTED"
    db.commit()
    db.refresh(scan)
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    return ScanDetailOut(**ScanOut.model_validate(scan).model_dump(), baseline_json=scan.baseline_json, findings=findings)


@router.post("/{scan_id}/stop", response_model=ScanDetailOut)
async def stop_scan(
    scan_id: str,
    immediate: bool = Query(
        False,
        description="Cancel the in-flight pipeline task right away instead of waiting for its next "
        "stage checkpoint. Whatever the current stage had already committed is kept; anything it "
        "was mid-write on when cancelled is not.",
    ),
    db: Session = Depends(get_db),
    _user=Depends(require_role("admin", "operator", "security_analyst")),
):
    """Request that a running scan's pipeline stop. By default this stops at
    its next stage checkpoint (usually near-instant, but not guaranteed
    synchronous with this call returning) -- a stopped scan is not discarded,
    its checkpoint (raw config in MinIO, baseline once normalization has
    completed, findings already persisted) is kept, and it can be restarted
    later via /{scan_id}/resume from wherever it stopped.

    With immediate=True, the backing asyncio task is cancelled directly
    (see RUNNING_SCAN_TASKS) rather than waiting for run_pipeline to reach
    its own checkpoint -- for the 'Stop now' action on a Running Pipelines
    panel, where the operator wants the pipeline to actually die right now,
    not at its own convenience.
    """
    scan = db.query(Scan).get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.control_state not in ("RUNNING", "PAUSE_REQUESTED", "PAUSED"):
        raise HTTPException(409, f"Scan is not running or paused (control_state={scan.control_state}); nothing to stop")
    was_paused = scan.control_state == "PAUSED"
    scan.control_state = "STOP_REQUESTED"
    db.commit()

    if immediate:
        task = RUNNING_SCAN_TASKS.get(scan_id)
        if task and not task.done():
            task.cancel()
            # Give the cancelled task a moment to persist STOPPED itself
            # (see _run_scan_pipeline_in_own_session's CancelledError
            # handler) before we read the scan back below -- best-effort;
            # if it doesn't finish in time control_state is at least
            # already STOP_REQUESTED and the next poll will pick up STOPPED
            # once it lands.
            try:
                await asyncio.wait_for(task, timeout=2)
            except (Exception, asyncio.CancelledError):
                pass

    if was_paused:
        # A PAUSED scan has no in-flight coroutine left to reach a
        # checkpoint and flip this to STOPPED for us -- do it directly.
        scan.status = "stopped"
        scan.control_state = "STOPPED"
        scan.stopped_at = datetime.utcnow()
        db.commit()
    db.refresh(scan)
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    return ScanDetailOut(**ScanOut.model_validate(scan).model_dump(), baseline_json=scan.baseline_json, findings=findings)


@router.post("/{scan_id}/resume", response_model=ScanDetailOut)
async def resume_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    _user=Depends(require_role("admin", "operator", "security_analyst")),
):
    """Resume a PAUSED or STOPPED scan's pipeline from its last checkpointed
    stage (services/pipeline.py::resume_pipeline). Runs synchronously, same
    as the original /upload call -- the response only comes back once the
    pipeline completes or hits another pause/stop."""
    scan = db.query(Scan).get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.control_state not in ("PAUSED", "STOPPED"):
        raise HTTPException(409, f"Scan is not paused or stopped (control_state={scan.control_state}); nothing to resume")
    try:
        scan = await resume_pipeline(db, scan)
    except ValueError as e:
        raise HTTPException(400, str(e))
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    return ScanDetailOut(**ScanOut.model_validate(scan).model_dump(), baseline_json=scan.baseline_json, findings=findings)


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