from typing import List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.db import BatfishAnalysis, Device, Finding, Scan
from app.routers.devices import get_or_create_demo_tenant
from app.schemas import ScanDetailOut, ScanOut
from app.services.pipeline import run_pipeline
from app.services.vendor_detect import detect_vendor

from app.auth.dependencies import get_current_user

router = APIRouter(prefix="/api/scans", tags=["scans"], dependencies=[Depends(get_current_user)])

MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5MB safety cap for uploaded config files


@router.post("/upload", response_model=ScanDetailOut)
async def upload_config(
    file: UploadFile = File(...),
    framework: str = Form("ALL"),
    hostname: Optional[str] = Form(None),
    db: Session = Depends(get_db),
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

    device = Device(
        tenant_id=tenant.id,
        hostname=hostname or f"{guess.vendor}-DEVICE",
        vendor=guess.vendor,
        os=guess.os,
    )
    db.add(device)
    db.commit()
    db.refresh(device)

    scan = Scan(tenant_id=tenant.id, device_id=device.id, framework=framework, status="uploaded")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    await run_pipeline(db, scan, raw_text, framework=framework)

    db.refresh(scan)
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
):
    results = []
    for file in files:
        raw_bytes = await file.read()
        if len(raw_bytes) > MAX_UPLOAD_BYTES:
            continue
        raw_text = raw_bytes.decode("utf-8", errors="replace")
        guess = detect_vendor(raw_text)
        tenant = get_or_create_demo_tenant(db)
        device = Device(tenant_id=tenant.id, hostname=file.filename, vendor=guess.vendor, os=guess.os)
        db.add(device)
        db.commit()
        db.refresh(device)
        scan = Scan(tenant_id=tenant.id, device_id=device.id, framework=framework, status="uploaded")
        db.add(scan)
        db.commit()
        db.refresh(scan)
        await run_pipeline(db, scan, raw_text, framework=framework)
        db.refresh(scan)
        findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
        results.append(ScanDetailOut(**ScanOut.model_validate(scan).model_dump(), baseline_json=scan.baseline_json, findings=findings))
    return results


@router.get("", response_model=List[ScanOut])
def list_scans(db: Session = Depends(get_db)):
    return db.query(Scan).order_by(Scan.created_at.desc()).limit(100).all()


@router.get("/{scan_id}", response_model=ScanDetailOut)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    return ScanDetailOut(**ScanOut.model_validate(scan).model_dump(), baseline_json=scan.baseline_json, findings=findings)


@router.post("/{scan_id}/rerun", response_model=ScanDetailOut)
async def rerun_scan(scan_id: str, db: Session = Depends(get_db)):
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
    opa_decision = await evaluate_baseline_via_opa(scan.id, baseline, scan.framework)
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
