from collections import defaultdict
from io import BytesIO
from typing import List, Optional
import hashlib

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.db import CommandMapping, Device, EvidenceRecord, Finding, ReportArtifact, Scan
from app.schemas import DashboardStats, FindingOut, ScanOut
from app.services import evidence_service, exception_service, minio_service
from app.services.reports import (build_csv_report, build_json_report,
                                   build_pdf_report)

from app.auth.dependencies import get_current_tenant, get_current_user

router = APIRouter(tags=["compliance"], dependencies=[Depends(get_current_user)])


@router.get("/api/findings", response_model=List[FindingOut])
def list_findings(scan_id: Optional[str] = None, severity: Optional[str] = None,
                   result: Optional[str] = None, db: Session = Depends(get_db),
                   tenant_id: str = Depends(get_current_tenant)):
    # Findings have no tenant_id of their own -- scope via a join to Scan,
    # which does (Phase 5 rule: tenant isolation on every resource, findings
    # included, even when the row itself doesn't carry the column).
    q = (
        db.query(Finding, Scan.device_id)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.tenant_id == tenant_id)
    )
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)
    if severity:
        q = q.filter(Finding.severity == severity.upper())
    if result:
        q = q.filter(Finding.result == result.upper())
    rows = q.order_by(Finding.created_at.desc()).limit(500).all()

    # Phase 16: overlay EXCEPTION_ACCEPTED for FAIL findings covered by an
    # active exception -- the underlying `result` (OPA's, untouched) is
    # still returned alongside it.
    exception_index = exception_service.active_exceptions_index(db, tenant_id)
    out: List[FindingOut] = []
    for finding, device_id in rows:
        fo = FindingOut.model_validate(finding)
        fo.presentation_result = exception_service.presentation_result(
            finding.result, device_id, finding.control_id, exception_index,
        )
        out.append(fo)
    return out


@router.get("/api/dashboard", response_model=DashboardStats)
def dashboard(db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    devices = db.query(Device).filter(Device.tenant_id == tenant_id).all()
    scans = db.query(Scan).filter(Scan.tenant_id == tenant_id).all()
    completed = [s for s in scans if s.status == "completed"]
    scores = [s.compliance_score for s in completed if s.compliance_score is not None]
    overall = round(sum(scores) / len(scores), 1) if scores else 0.0

    findings = (
        db.query(Finding).join(Scan, Finding.scan_id == Scan.id).filter(Scan.tenant_id == tenant_id).all()
    )
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

    recent = db.query(Scan).filter(Scan.tenant_id == tenant_id).order_by(Scan.created_at.desc()).limit(10).all()
    pending = db.query(CommandMapping).filter(
        CommandMapping.status == "pending", CommandMapping.tenant_id == tenant_id
    ).count()

    # --- Section 32 additions: OPA/Batfish/risk/evidence/Fabric metrics ---
    opa_violations = db.query(Scan).filter(Scan.tenant_id == tenant_id, Scan.opa_decision == "BLOCK").count()
    batfish_violations = db.query(Scan).filter(
        Scan.tenant_id == tenant_id, Scan.batfish_status.in_(["BATFISH_FAIL"])
    ).count()
    # "Unknown configuration": AI-normalized parameters never resolved to a
    # known control (low-confidence / pending training-center mappings) —
    # tracked via pending CommandMapping rows, matching the Training Center
    # workflow in section 40.
    unknown_configurations = pending
    high_risk_devices = db.query(Device).filter(
        Device.tenant_id == tenant_id, Device.last_compliance_score.isnot(None), Device.last_compliance_score < 60
    ).count()

    evidence_records = db.query(EvidenceRecord).filter(EvidenceRecord.tenant_id == tenant_id).all()
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


@router.get("/api/reports/{scan_id}/{fmt}")
def get_report(
    scan_id: str,
    fmt: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    if fmt not in ("pdf", "json", "csv"):
        raise HTTPException(400, "format must be pdf, json, or csv")
    # Tenant-scoped lookup (Phase 5/20 rule: reports must be tenant-scoped) --
    # filtering by tenant_id in the same query means another tenant's scan
    # is indistinguishable from a nonexistent one (404, never 403).
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.tenant_id == tenant_id).first()
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

    # Phase 8: best-effort durable copy in MinIO + a Postgres reference row.
    # A storage outage never blocks report delivery -- the bytes are still
    # streamed to the caller below regardless of whether this succeeded.
    put_result = minio_service.put_object(
        minio_service.object_key(tenant_id, scan.device_id, scan.id, f"report.{fmt}"), data,
    )
    db.add(ReportArtifact(
        tenant_id=tenant_id,
        scan_id=scan.id,
        format=fmt,
        object_key=put_result.object_key if put_result else None,
        object_bucket=put_result.bucket if put_result else None,
        sha256=put_result.sha256 if put_result else hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
    ))
    db.commit()

    filename = f"compliance-report-{scan_id[:8]}.{fmt}"
    return StreamingResponse(BytesIO(data), media_type=media,
                              headers={"Content-Disposition": f"attachment; filename={filename}"})