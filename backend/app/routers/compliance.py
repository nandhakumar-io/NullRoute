from collections import defaultdict
from datetime import datetime, timedelta
from io import BytesIO
from typing import List, Optional
import hashlib

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.db import CommandMapping, Device, EvidenceRecord, Finding, ReportArtifact, Scan
from app.schemas import DashboardMetricsOut, DashboardMetricPoint, DashboardStats, FindingOut, ScanOut
from app.services import audit_service, evidence_service, exception_service, minio_service
from app.services.reports import (build_csv_report, build_json_report,
                                   build_pdf_report)
from app.auth.rbac import Permission

from app.auth.dependencies import get_current_tenant, get_current_user, require_permission

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


@router.get("/api/dashboard/metrics", response_model=DashboardMetricsOut)
def dashboard_metrics(
    window: str = Query("7d", alias="range", pattern="^(24h|7d|30d|90d)$"),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    """Section 12 'security improvements': compliance % and findings by
    severity/open/resolved, over a selectable window (24h/7d/30d/90d), plus
    a bucketed timeseries so the frontend can render trend graphs instead
    of static bars.

    Heuristics (no separate finding-lifecycle table exists yet):
    - "Open" = FAIL findings on each device's MOST RECENT scan (i.e. the
      device's current state), restricted to devices whose most recent
      scan falls inside the window.
    - "Resolved" = FAIL findings from scans inside the window whose
      (device, control_id) pair is NOT failing on that device's most
      recent scan -- i.e. a later scan showed it fixed.
    """
    window_deltas = {
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30),
        "90d": timedelta(days=90),
    }
    delta = window_deltas[window]
    now = datetime.utcnow()
    since = now - delta

    scans = (
        db.query(Scan)
        .filter(Scan.tenant_id == tenant_id)
        .order_by(Scan.created_at.asc())
        .all()
    )
    scan_ids_in_window = [s.id for s in scans if s.created_at and s.created_at >= since]

    # Latest scan per device -- defines "current state" for open/resolved.
    latest_scan_by_device: dict = {}
    for s in scans:
        if s.device_id not in latest_scan_by_device or (
            s.created_at and s.created_at > latest_scan_by_device[s.device_id].created_at
        ):
            latest_scan_by_device[s.device_id] = s
    latest_scan_ids = {s.id for s in latest_scan_by_device.values()}
    latest_scan_in_window_ids = {
        s.id for s in latest_scan_by_device.values() if s.created_at and s.created_at >= since
    }

    all_findings = (
        db.query(Finding, Scan.device_id, Scan.id.label("scan_id"), Scan.created_at.label("scan_created_at"))
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.tenant_id == tenant_id)
        .all()
    )

    # (device_id, control_id) -> result on that device's latest scan, used
    # to tell whether an older FAIL has since been resolved.
    current_result = {}
    for finding, device_id, scan_id, _created in all_findings:
        if scan_id in latest_scan_ids:
            current_result[(device_id, finding.control_id)] = finding.result

    sev_counts = defaultdict(int)
    open_findings = 0
    resolved_findings = 0
    for finding, device_id, scan_id, scan_created_at in all_findings:
        if scan_id not in scan_ids_in_window and scan_id not in latest_scan_in_window_ids:
            continue
        if finding.result != "FAIL":
            continue
        if scan_id in latest_scan_in_window_ids:
            sev_counts[finding.severity] += 1
            open_findings += 1
        elif scan_id in scan_ids_in_window:
            if current_result.get((device_id, finding.control_id)) == "PASS":
                resolved_findings += 1

    completed_in_window = [s for s in scans if s.id in scan_ids_in_window and s.compliance_score is not None]
    if completed_in_window:
        compliance_score = round(sum(s.compliance_score for s in completed_in_window) / len(completed_in_window), 1)
    else:
        # Fall back to all-time so the widget isn't blank the first time a
        # short window (e.g. 24h) has no completed scans in it.
        all_scores = [s.compliance_score for s in scans if s.compliance_score is not None]
        compliance_score = round(sum(all_scores) / len(all_scores), 1) if all_scores else 0.0

    # --- Timeseries: bucket by hour for 24h, by day otherwise ---
    bucket_is_hourly = window == "24h"
    n_buckets = 24 if bucket_is_hourly else delta.days
    bucket_size = timedelta(hours=1) if bucket_is_hourly else timedelta(days=1)

    def bucket_key(ts: datetime) -> int:
        offset = ts - since
        idx = int(offset.total_seconds() // bucket_size.total_seconds())
        return max(0, min(n_buckets - 1, idx))

    bucket_scores: dict = defaultdict(list)
    bucket_sev: dict = defaultdict(lambda: defaultdict(int))
    bucket_open: dict = defaultdict(int)
    bucket_resolved: dict = defaultdict(int)

    for s in scans:
        if s.created_at and s.created_at >= since and s.compliance_score is not None:
            bucket_scores[bucket_key(s.created_at)].append(s.compliance_score)

    for finding, device_id, scan_id, scan_created_at in all_findings:
        if not scan_created_at or scan_created_at < since:
            continue
        if finding.result != "FAIL":
            continue
        b = bucket_key(scan_created_at)
        bucket_sev[b][finding.severity] += 1
        if scan_id in latest_scan_ids:
            bucket_open[b] += 1
        elif current_result.get((device_id, finding.control_id)) == "PASS":
            bucket_resolved[b] += 1

    timeseries: List[DashboardMetricPoint] = []
    for i in range(n_buckets):
        bucket_start = since + i * bucket_size
        scores = bucket_scores.get(i, [])
        timeseries.append(DashboardMetricPoint(
            bucket=bucket_start.isoformat(),
            compliance_score=round(sum(scores) / len(scores), 1) if scores else None,
            critical_findings=bucket_sev[i].get("CRITICAL", 0),
            high_findings=bucket_sev[i].get("HIGH", 0),
            medium_findings=bucket_sev[i].get("MEDIUM", 0),
            low_findings=bucket_sev[i].get("LOW", 0),
            open_findings=bucket_open.get(i, 0),
            resolved_findings=bucket_resolved.get(i, 0),
        ))

    return DashboardMetricsOut(
        range=window,
        compliance_score=compliance_score,
        critical_findings=sev_counts["CRITICAL"],
        high_findings=sev_counts["HIGH"],
        medium_findings=sev_counts["MEDIUM"],
        low_findings=sev_counts["LOW"],
        open_findings=open_findings,
        resolved_findings=resolved_findings,
        timeseries=timeseries,
    )


@router.get("/api/reports/{scan_id}/{fmt}")
def get_report(
    scan_id: str,
    fmt: str,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user=Depends(require_permission(Permission.EXPORT)),
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

    audit_service.record_from_user(
        db, user, action="report.download", request=request, result="SUCCESS",
        object_type="report", object_id=scan_id,
        new_value={"format": fmt, "size_bytes": len(data)},
    )

    filename = f"compliance-report-{scan_id[:8]}.{fmt}"
    return StreamingResponse(BytesIO(data), media_type=media,
                              headers={"Content-Disposition": f"attachment; filename={filename}"})