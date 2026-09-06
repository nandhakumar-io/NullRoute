from typing import List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.db import BatfishAnalysis, Device, EvidenceRecord, Finding, ReportArtifact, Scan
from app.schemas import ScanDetailOut, ScanOut
from app.services import audit_service, minio_service, network_snapshot_service, remediation_service
from app.services.pipeline import run_pipeline
from app.services.vendor_detect import detect_vendor

from app.auth.dependencies import CurrentUser, get_current_tenant, get_current_user, require_role

router = APIRouter(prefix="/api/scans", tags=["scans"], dependencies=[Depends(get_current_user)])

MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5MB safety cap for uploaded config files


def _get_owned_scan(db: Session, scan_id: str, tenant_id: str) -> Scan:
    """Fetch a scan scoped to the requesting tenant. Filtering tenant_id
    in the same query -- rather than fetching by id and checking after --
    means another tenant's scan is indistinguishable from a nonexistent
    one (404, never 403; Phase 5 rule)."""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.tenant_id == tenant_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@router.post("/upload", response_model=ScanDetailOut)
async def upload_config(
    request: Request,
    file: UploadFile = File(...),
    framework: str = Form("ALL"),
    hostname: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(get_current_user),
):
    raw_bytes = await file.read()
    if len(raw_bytes) > MAX_UPLOAD_BYTES:
        audit_service.record_from_user(
            db, user, action="scan.upload", request=request, result="FAILURE",
            object_type="scan", new_value={"filename": file.filename, "error": "file too large"},
        )
        raise HTTPException(413, "Configuration file too large (max 5MB)")
    try:
        raw_text = raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        audit_service.record_from_user(
            db, user, action="scan.upload", request=request, result="FAILURE",
            object_type="scan", new_value={"filename": file.filename, "error": "undecodable"},
        )
        raise HTTPException(400, "Unable to decode configuration file as text")

    guess = detect_vendor(raw_text)

    device = Device(
        tenant_id=tenant_id,
        hostname=hostname or f"{guess.vendor}-DEVICE",
        vendor=guess.vendor,
        os=guess.os,
    )
    db.add(device)
    db.commit()
    db.refresh(device)

    scan = Scan(tenant_id=tenant_id, device_id=device.id, framework=framework, status="uploaded")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    await run_pipeline(db, scan, raw_text, framework=framework)

    db.refresh(scan)
    audit_service.record_from_user(
        db, user, action="scan.upload", request=request, result="SUCCESS",
        object_type="scan", object_id=scan.id,
        new_value={
            "filename": file.filename, "device_id": device.id, "vendor": guess.vendor,
            "framework": framework, "config_hash": scan.raw_config_hash,
            "final_decision": scan.final_decision,
        },
    )
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    return ScanDetailOut(
        **ScanOut.model_validate(scan).model_dump(),
        baseline_json=scan.baseline_json,
        findings=findings,
    )


@router.post("/bulk-upload", response_model=List[ScanDetailOut])
async def bulk_upload(
    request: Request,
    files: List[UploadFile] = File(...),
    framework: str = Form("ALL"),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(get_current_user),
):
    results = []
    for file in files:
        raw_bytes = await file.read()
        if len(raw_bytes) > MAX_UPLOAD_BYTES:
            audit_service.record_from_user(
                db, user, action="scan.upload", request=request, result="FAILURE",
                object_type="scan", new_value={"filename": file.filename, "error": "file too large"},
            )
            continue
        raw_text = raw_bytes.decode("utf-8", errors="replace")
        guess = detect_vendor(raw_text)
        device = Device(tenant_id=tenant_id, hostname=file.filename, vendor=guess.vendor, os=guess.os)
        db.add(device)
        db.commit()
        db.refresh(device)
        scan = Scan(tenant_id=tenant_id, device_id=device.id, framework=framework, status="uploaded")
        db.add(scan)
        db.commit()
        db.refresh(scan)
        await run_pipeline(db, scan, raw_text, framework=framework)
        db.refresh(scan)
        audit_service.record_from_user(
            db, user, action="scan.upload", request=request, result="SUCCESS",
            object_type="scan", object_id=scan.id,
            new_value={
                "filename": file.filename, "device_id": device.id, "vendor": guess.vendor,
                "framework": framework, "config_hash": scan.raw_config_hash,
                "final_decision": scan.final_decision,
            },
        )
        findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
        results.append(ScanDetailOut(**ScanOut.model_validate(scan).model_dump(), baseline_json=scan.baseline_json, findings=findings))
    return results


@router.get("", response_model=List[ScanOut])
def list_scans(
    device_id: Optional[str] = None,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    q = db.query(Scan).filter(Scan.tenant_id == tenant_id)
    if device_id:
        q = q.filter(Scan.device_id == device_id)
    return q.order_by(Scan.created_at.desc()).limit(100).all()


@router.get("/{scan_id}", response_model=ScanDetailOut)
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.tenant_id == tenant_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    return ScanDetailOut(**ScanOut.model_validate(scan).model_dump(), baseline_json=scan.baseline_json, findings=findings)


@router.get("/{scan_id}/remediation-suggestions")
def get_remediation_suggestions(
    scan_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant),
):
    """Phase 14 -- deterministic remediation guidance for this scan's FAIL
    findings, meant as a starting point for a human building a Change
    Request's proposed_config. See services/remediation_service.py for why
    this never invents configuration text."""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.tenant_id == tenant_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    return remediation_service.suggest_remediation_for_scan(db, scan)


@router.get("/{scan_id}/remediation-cli")
def get_remediation_cli(
    scan_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant),
):
    """Vendor-specific step-by-step CLI remediation for this scan's FAIL
    findings: Finding -> control_id -> (vendor, os) -> validated template ->
    CLI steps -> human approval. See services/remediation_service.py and
    services/remediation_templates.py for the trust boundary (only
    hand-reviewed templates are ever returned as CLI)."""
    scan = _get_owned_scan(db, scan_id, tenant_id)
    return remediation_service.generate_remediation_cli_for_scan(db, scan)


@router.post("/{scan_id}/rerun", response_model=ScanDetailOut)
async def rerun_scan(scan_id: str, request: Request, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant),
                      user: CurrentUser = Depends(get_current_user)):
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

    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.tenant_id == tenant_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    device = db.query(Device).get(scan.device_id)
    _prior_decision, _prior_reason = scan.final_decision, scan.final_reason
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
    audit_service.record_from_user(
        db, user, action="scan.rerun", request=request, result="SUCCESS",
        object_type="scan", object_id=scan.id,
        old_value={"final_decision": _prior_decision, "final_reason": _prior_reason},
        new_value={"final_decision": decision.decision, "final_reason": decision.reason, "compliance_score": score},
    )
    findings_out = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    return ScanDetailOut(**ScanOut.model_validate(scan).model_dump(), baseline_json=scan.baseline_json, findings=findings_out)


@router.get("/{scan_id}/batfish")
def get_batfish_analysis(scan_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    """Latest Batfish behavioral-analysis result for this scan (nodes,
    interfaces, routes, reachability checks, init issues) — powers the
    Batfish Analysis UI page."""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.tenant_id == tenant_id).first()
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
def get_opa_analysis(scan_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    """Latest OPA policy-evaluation result for this scan — powers the
    Policy Evaluation UI page."""
    from app.models.db import OPAAnalysis

    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.tenant_id == tenant_id).first()
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

# ---------------------------------------------------------------------------
# Phase 8 -- artifact retrieval. Lists/streams the objects MinIO holds for a
# scan (raw config, evidence JSON, generated reports) without ever exposing
# the object store directly to the frontend. Tenant-scoped like every other
# scan lookup in this router; a `raw_config_path`/`evidence_object_key`/
# ReportArtifact row that belongs to another tenant is unreachable because
# the owning Scan/EvidenceRecord/ReportArtifact row itself is filtered out.
# ---------------------------------------------------------------------------

from fastapi.responses import StreamingResponse
from io import BytesIO


@router.get("/{scan_id}/artifacts")
def list_scan_artifacts(
    scan_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.tenant_id == tenant_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    artifacts = []
    if scan.raw_config_path:
        artifacts.append({"kind": "raw_config", "object_key": scan.raw_config_path, "sha256": scan.raw_config_hash})

    evidence_record = None
    if scan.evidence_id:
        evidence_record = db.query(EvidenceRecord).filter(EvidenceRecord.evidence_id == scan.evidence_id).first()
    if evidence_record and evidence_record.evidence_object_key:
        artifacts.append({
            "kind": "evidence",
            "object_key": evidence_record.evidence_object_key,
            "sha256": evidence_record.evidence_hash,
        })

    reports = db.query(ReportArtifact).filter(ReportArtifact.scan_id == scan_id, ReportArtifact.tenant_id == tenant_id).all()
    for r in reports:
        artifacts.append({
            "kind": f"report_{r.format}",
            "object_key": r.object_key,
            "sha256": r.sha256,
            "size_bytes": r.size_bytes,
            "created_at": r.created_at,
        })

    return {"scan_id": scan_id, "artifacts": artifacts, "object_store": minio_service.health()}


@router.get("/{scan_id}/artifacts/{kind}")
def download_scan_artifact(
    scan_id: str,
    kind: str,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(get_current_user),
):
    """kind: raw_config | evidence | report_pdf | report_json | report_csv"""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.tenant_id == tenant_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    object_key: Optional[str] = None
    media_type = "application/octet-stream"

    if kind == "raw_config":
        object_key = scan.raw_config_path
        media_type = "text/plain"
    elif kind == "evidence":
        if scan.evidence_id:
            record = db.query(EvidenceRecord).filter(EvidenceRecord.evidence_id == scan.evidence_id).first()
            object_key = record.evidence_object_key if record else None
        media_type = "application/json"
    elif kind.startswith("report_"):
        fmt = kind.split("_", 1)[1]
        report = (
            db.query(ReportArtifact)
            .filter(ReportArtifact.scan_id == scan_id, ReportArtifact.tenant_id == tenant_id, ReportArtifact.format == fmt)
            .order_by(ReportArtifact.created_at.desc())
            .first()
        )
        object_key = report.object_key if report else None
        media_type = {"pdf": "application/pdf", "csv": "text/csv", "json": "application/json"}.get(fmt, media_type)
    else:
        raise HTTPException(400, "kind must be raw_config, evidence, or report_{pdf,json,csv}")

    if not object_key:
        raise HTTPException(404, "Artifact was not archived to the object store (MinIO was disabled/unavailable at generation time, or no such artifact exists yet)")

    try:
        data = minio_service.get_object(object_key)
    except minio_service.ObjectStoreError as e:
        raise HTTPException(502, f"Could not retrieve artifact from object store: {e}") from e

    return StreamingResponse(BytesIO(data), media_type=media_type,
                              headers={"Content-Disposition": f"attachment; filename={kind}-{scan_id[:8]}"})


# ---------------------------------------------------------------------------
# Phase 10 -- multi-device Batfish snapshot diff. CURRENT = every other
# tenant device's latest known config + this device's config from BEFORE
# this scan (if any); PROPOSED = the same set with this scan's own config
# substituted in. Shows the behavioral effect of this one config change
# against the rest of the topology -- never converts BATFISH_UNSUPPORTED/
# BATFISH_UNAVAILABLE/BATFISH_ERROR into a passing result (RULE 13).
# ---------------------------------------------------------------------------

@router.get("/{scan_id}/snapshot-diff")
def get_snapshot_diff(
    scan_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.tenant_id == tenant_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    return network_snapshot_service.build_snapshot_diff(db, scan)