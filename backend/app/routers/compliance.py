from collections import defaultdict
from io import BytesIO
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.db import CommandMapping, Device, EvidenceRecord, Finding, Scan
from app.schemas import DashboardStats, DashboardMetrics, DashboardMetricPoint, FindingOut, ScanOut
from app.services import evidence_service
from app.services.reports import (build_csv_report, build_json_report,
                                   build_pdf_report)

from app.auth.dependencies import get_current_user

router = APIRouter(tags=["compliance"], dependencies=[Depends(get_current_user)])


@router.get("/api/findings", response_model=List[FindingOut])
def list_findings(scan_id: Optional[str] = None, severity: Optional[str] = None,
                   result: Optional[str] = None, db: Session = Depends(get_db)):
    q = db.query(Finding)
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)
    if severity:
        q = q.filter(Finding.severity == severity.upper())
    if result:
        q = q.filter(Finding.result == result.upper())
    return q.order_by(Finding.created_at.desc()).limit(500).all()


@router.get("/api/dashboard", response_model=DashboardStats)
def dashboard(db: Session = Depends(get_db)):
    devices = db.query(Device).all()
    scans = db.query(Scan).all()
    completed = [s for s in scans if s.status == "completed"]
    scores = [s.compliance_score for s in completed if s.compliance_score is not None]
    overall = round(sum(scores) / len(scores), 1) if scores else 0.0

    findings = db.query(Finding).all()
    sev_counts = defaultdict(int)
    for f in findings:
        if f.result == "FAIL":
            sev_counts[f.severity] += 1

    fw_scores: dict = {}
    fw_groups = defaultdict(list)
    for f in findings:
        fw_groups[f.framework].append(f)
    for fw, items in fw_groups.items():
        applicable = [i for i in items if i.result != "NOT_APPLICABLE"]
        if applicable:
            fw_scores[fw] = round(100.0 * sum(1 for i in applicable if i.result == "PASS") / len(applicable), 1)

    recent = db.query(Scan).order_by(Scan.created_at.desc()).limit(10).all()
    pending = db.query(CommandMapping).filter(CommandMapping.status == "pending").count()

    # --- Section 32 additions: OPA/Batfish/risk/evidence/Fabric metrics ---
    opa_violations = db.query(Scan).filter(Scan.opa_decision == "BLOCK").count()
    batfish_violations = db.query(Scan).filter(
        Scan.batfish_status.in_(["BATFISH_FAIL"])
    ).count()
    # "Unknown configuration": AI-normalized parameters never resolved to a
    # known control (low-confidence / pending training-center mappings) —
    # tracked via pending CommandMapping rows, matching the Training Center
    # workflow in section 40.
    unknown_configurations = pending
    high_risk_devices = db.query(Device).filter(
        Device.last_compliance_score.isnot(None), Device.last_compliance_score < 60
    ).count()

    evidence_records = db.query(EvidenceRecord).all()
    evidence_anchors = sum(1 for e in evidence_records if e.fabric_status == "ANCHORED")
    fabric_failures = sum(1 for e in evidence_records if e.fabric_status == "FABRIC_UNAVAILABLE")

    # Integrity failures: recompute each evidence record's hash live (no
    # separate verification-history table exists yet — see
    # routers/evidence.py). Cheap at demo/dev scale; if this becomes a
    # bottleneck at larger scale, persist VerifyResultOut on each POST
    # /verify call instead of recomputing here.
    integrity_failures = 0
    for e in evidence_records:
        result = evidence_service.verify_evidence(e.evidence_hash, e.evidence_json)
        if not result["match"]:
            integrity_failures += 1

    opa_vs_batfish = {
        "opa_violations": opa_violations,
        "batfish_violations": batfish_violations,
    }
    risk_counts = defaultdict(int)
    for s in scans:
        if s.risk_level:
            risk_counts[s.risk_level] += 1
    evidence_anchoring_status = defaultdict(int)
    for e in evidence_records:
        evidence_anchoring_status[e.fabric_status or "NOT_ANCHORED"] += 1

    return DashboardStats(
        total_devices=len(devices),
        devices_scanned=len(completed),
        overall_compliance_score=overall,
        critical_findings=sev_counts["CRITICAL"],
        high_findings=sev_counts["HIGH"],
        medium_findings=sev_counts["MEDIUM"],
        low_findings=sev_counts["LOW"],
        framework_scores=fw_scores,
        recent_scans=recent,
        pending_ai_mappings=pending,
        opa_violations=opa_violations,
        batfish_violations=batfish_violations,
        unknown_configurations=unknown_configurations,
        high_risk_devices=high_risk_devices,
        evidence_anchors=evidence_anchors,
        fabric_failures=fabric_failures,
        integrity_failures=integrity_failures,
        opa_vs_batfish=dict(opa_vs_batfish),
        risk_distribution=dict(risk_counts),
        evidence_anchoring_status=dict(evidence_anchoring_status),
    )

@router.get("/api/dashboard/metrics", response_model=DashboardMetrics)
def dashboard_metrics(range: str = "30d", db: Session = Depends(get_db)):
    # Local developer fallback: providing an empty timeseries structure.
    return DashboardMetrics(
        range=range,
        compliance_score=0.0,
        critical_findings=0,
        high_findings=0,
        medium_findings=0,
        low_findings=0,
        open_findings=0,
        resolved_findings=0,
        timeseries=[]
    )


@router.get("/api/reports/{scan_id}/{fmt}")
def get_report(scan_id: str, fmt: str, db: Session = Depends(get_db)):
    if fmt not in ("pdf", "json", "csv"):
        raise HTTPException(400, "format must be pdf, json, or csv")
    scan = db.query(Scan).get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    device = db.query(Device).get(scan.device_id)
    findings = [FindingOut.model_validate(f).model_dump() for f in db.query(Finding).filter(Finding.scan_id == scan_id).all()]
    scan_dict = ScanOut.model_validate(scan).model_dump()
    device_dict = {c.name: getattr(device, c.name) for c in device.__table__.columns} if device else {}

    evidence_dict: dict = {}
    if scan.evidence_id:
        record = db.query(EvidenceRecord).filter(EvidenceRecord.evidence_id == scan.evidence_id).first()
        if record:
            evidence_dict = {
                "evidence_id": record.evidence_id,
                "evidence_hash": record.evidence_hash,
                "fabric_status": record.fabric_status,
                "fabric_tx_id": record.fabric_tx_id,
                "fabric_block_number": record.fabric_block_number,
            }

    if fmt == "pdf":
        data = build_pdf_report(scan_dict, device_dict, findings, evidence_dict)
        media = "application/pdf"
    elif fmt == "csv":
        data = build_csv_report(findings)
        media = "text/csv"
    else:
        data = build_json_report(scan_dict, device_dict, findings, evidence_dict)
        media = "application/json"

    filename = f"compliance-report-{scan_id[:8]}.{fmt}"
    return StreamingResponse(BytesIO(data), media_type=media,
                              headers={"Content-Disposition": f"attachment; filename={filename}"})
