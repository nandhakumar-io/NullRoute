from collections import defaultdict
import builtins as _builtins
from datetime import datetime, timedelta
from io import BytesIO
from typing import List, Optional
import hashlib
import uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.db import (ChangeRequest, CommandMapping, Device, DeploymentRecord,
                            DeviceVulnerabilityMatch, DriftEvent, EvidenceRecord,
                            Finding, ReportArtifact, Scan)
from app.schemas import (ComplianceMatrix, DashboardStats, DashboardMetrics,
                          DashboardMetricPoint, FindingOut, ScanOut)
from app.services import control_service, evidence_service, minio_service
from app.services.reports import (build_csv_report, build_json_report,
                                   build_pdf_report)

from app.auth.dependencies import get_current_user

# A scan that finished the pipeline ends as completed / review / blocked
# (pipeline.py maps the PASS/REVIEW/BLOCK decision onto the status). A low
# score is exactly what produces review/blocked, so filtering on "completed"
# alone silently dropped every failing scan: the dashboard showed 0% and the
# trend charts stayed empty while the scan itself showed e.g. 32%.
SCORED_SCAN_STATUSES = ("completed", "review", "blocked")

router = APIRouter(tags=["compliance"], dependencies=[Depends(get_current_user)])


@router.get("/api/findings", response_model=List[FindingOut])
def list_findings(scan_id: Optional[str] = None, severity: Optional[str] = None,
                   result: Optional[str] = None, vendor: Optional[str] = None,
                   db: Session = Depends(get_db)):
    q = db.query(Finding)
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)
    if severity:
        q = q.filter(Finding.severity == severity.upper())
    if result:
        q = q.filter(Finding.result == result.upper())
    if vendor:
        q = q.filter(Finding.vendor == vendor)
    return q.order_by(Finding.created_at.desc()).limit(500).all()


@router.get("/api/findings/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: str, db: Session = Depends(get_db)):
    """Single-finding lookup backing the Finding Detail / traceability view
    (Phase 1 security-audit experience, SIH26155). Reuses FindingOut as-is —
    no new model or duplicate finding representation."""
    finding = db.query(Finding).get(finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")
    return finding


@router.get("/api/dashboard", response_model=DashboardStats)
def dashboard(db: Session = Depends(get_db)):
    devices = db.query(Device).all()
    scans = db.query(Scan).all()
    completed = [s for s in scans if s.status in SCORED_SCAN_STATUSES]
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
        applicable = [i for i in items if i.result not in ("NOT_APPLICABLE", "UNVERIFIED")]
        if applicable:
            fw_scores[fw] = round(100.0 * sum(1 for i in applicable if i.result == "PASS") / len(applicable), 1)

    # Per-vendor score: the direct dashboard-level proof of "same control
    # catalog, evaluated the same way, across every vendor" (§9/§14) — reads
    # straight off Finding.vendor, denormalized at write time (§F), no join
    # through Scan -> Device required.
    vendor_scores: dict = {}
    vendor_groups = defaultdict(list)
    for f in findings:
        if f.vendor:
            vendor_groups[f.vendor].append(f)
    for vendor, items in vendor_groups.items():
        applicable = [i for i in items if i.result not in ("NOT_APPLICABLE", "UNVERIFIED")]
        if applicable:
            vendor_scores[vendor] = round(100.0 * sum(1 for i in applicable if i.result == "PASS") / len(applicable), 1)

    recent = db.query(Scan).order_by(Scan.created_at.desc()).limit(10).all()
    pending = db.query(CommandMapping).filter(CommandMapping.status == "pending").count()

    # --- Section 32 additions: OPA/Batfish/risk/evidence/Fabric metrics ---
    opa_violations = db.query(Scan).filter(Scan.opa_decision == "BLOCK").count()
    review_scans = db.query(Scan).filter(Scan.opa_decision == "REVIEW").count()
    unverified_findings_count = sum(1 for f in findings if f.result == "UNVERIFIED")
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

    configuration_drift_count = db.query(DriftEvent).count()

    # --- Unified-dashboard KPIs -------------------------------------------
    # Devices out of baseline: distinct devices whose MOST RECENT completed
    # scan has at least one open CRITICAL finding -- deliberately scoped to
    # the latest scan per device (via a max(created_at) subquery) so a
    # device that was critical two scans ago but has since been remediated
    # doesn't still count.
    from sqlalchemy import func as _func
    latest_scan_subq = (
        db.query(Scan.device_id, _func.max(Scan.created_at).label("max_created"))
        .filter(Scan.status.in_(SCORED_SCAN_STATUSES))
        .group_by(Scan.device_id)
        .subquery()
    )
    latest_scan_ids = {
        row.id
        for row in db.query(Scan.id).join(
            latest_scan_subq,
            (Scan.device_id == latest_scan_subq.c.device_id)
            & (Scan.created_at == latest_scan_subq.c.max_created),
        ).all()
    }
    devices_out_of_baseline = (
        db.query(Finding.scan_id)
        .filter(Finding.scan_id.in_(latest_scan_ids), Finding.severity == "CRITICAL", Finding.result == "FAIL")
        .distinct()
        .count()
        if latest_scan_ids else 0
    )

    # Mean-Time-to-Remediate: created_at of the ChangeRequest -> completed_at
    # of its first successful deployment, for every change request that has
    # actually been deployed. Real deployment history only -- no synthetic
    # numbers. mttr_improvement_pct compares the first half of that history
    # to the second half chronologically so the KPI shows whether the team
    # is getting faster, not just a snapshot average.
    deployed_pairs = (
        db.query(DeploymentRecord, ChangeRequest)
        .join(ChangeRequest, DeploymentRecord.change_request_id == ChangeRequest.id)
        .filter(DeploymentRecord.status.in_(["DEPLOYED", "VERIFIED"]), DeploymentRecord.completed_at.isnot(None))
        .order_by(ChangeRequest.created_at.asc())
        .all()
    )
    durations_hours = [
        (dr.completed_at - cr.created_at).total_seconds() / 3600.0
        for dr, cr in deployed_pairs
        if dr.completed_at and cr.created_at
    ]
    mttr_hours = round(sum(durations_hours) / len(durations_hours), 2) if durations_hours else None
    mttr_improvement_pct = None
    if len(durations_hours) >= 4:
        mid = len(durations_hours) // 2
        first_half_avg = sum(durations_hours[:mid]) / mid
        second_half_avg = sum(durations_hours[mid:]) / (len(durations_hours) - mid)
        if first_half_avg > 0:
            mttr_improvement_pct = round(100.0 * (first_half_avg - second_half_avg) / first_half_avg, 1)

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
        review_scans=review_scans,
        unverified_findings=unverified_findings_count,
        vendor_scores=vendor_scores,
        total_findings=len(findings),
        configuration_drift_count=configuration_drift_count,
        devices_out_of_baseline=devices_out_of_baseline,
        mttr_hours=mttr_hours,
        mttr_improvement_pct=mttr_improvement_pct,
    )


@router.get("/api/dashboard/compliance-matrix", response_model=ComplianceMatrix)
def compliance_matrix(db: Session = Depends(get_db)):
    """Cross-vendor compliance matrix -- the direct visual proof that the
    same control catalog is evaluated natively against every vendor's own
    syntax (no per-vendor code fork): rows are controls, columns are
    vendors, cells are PASS rate. Read straight off Finding.control_id /
    Finding.vendor, same denormalized fields vendor_scores above already
    uses -- no new write path."""
    findings = db.query(Finding).filter(Finding.vendor.isnot(None), Finding.control_id.isnot(None)).all()
    vendors = sorted({f.vendor for f in findings if f.vendor})
    cells: dict = defaultdict(lambda: {"pass": 0, "total": 0})
    titles: dict = {}
    for f in findings:
        if f.result in ("NOT_APPLICABLE", "UNVERIFIED"):
            continue
        key = (f.control_id, f.vendor)
        cells[key]["total"] += 1
        if f.result == "PASS":
            cells[key]["pass"] += 1
        titles.setdefault(f.control_id, f.title or f.control_id)

    rows = []
    for control_id in sorted(titles.keys()):
        vendor_cells: dict = {}
        for v in vendors:
            cell = cells.get((control_id, v))
            vendor_cells[v] = round(100.0 * cell["pass"] / cell["total"], 1) if cell and cell["total"] else None
        rows.append({"control_id": control_id, "title": titles[control_id], "vendors": vendor_cells})

    return {"vendors": vendors, "rows": rows}

RANGE_TO_DAYS = {"24h": 1, "7d": 7, "30d": 30, "90d": 90}


@router.get("/api/dashboard/metrics", response_model=DashboardMetrics)
def dashboard_metrics(range: str = "30d", db: Session = Depends(get_db)):
    cutoff = datetime.utcnow() - timedelta(days=RANGE_TO_DAYS.get(range, 30))

    # Findings currently open, restricted to scans that ran inside the
    # selected window.
    open_in_range = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Finding.result == "FAIL", Scan.created_at >= cutoff)
        .all()
    )
    sev_counts = defaultdict(int)
    for f in open_in_range:
        sev_counts[f.severity] += 1

    # "Resolved in this window": no finding-lifecycle table exists yet, so
    # this is derived from consecutive scans instead of a stored status.
    # For each device, compare its two most recent completed scans — a
    # control_id that FAILed on the earlier one and PASSes on the later
    # one is a real remediation, counted if the later scan landed in range.
    resolved = 0
    for device in db.query(Device).all():
        last_two = (
            db.query(Scan)
            .filter(Scan.device_id == device.id, Scan.status.in_(SCORED_SCAN_STATUSES))
            .order_by(Scan.created_at.desc())
            .limit(2)
            .all()
        )
        if len(last_two) < 2:
            continue
        latest, previous = last_two
        if latest.created_at < cutoff:
            continue
        prev_fails = {
            f.control_id for f in db.query(Finding).filter(Finding.scan_id == previous.id, Finding.result == "FAIL")
        }
        if not prev_fails:
            continue
        latest_results = {f.control_id: f.result for f in db.query(Finding).filter(Finding.scan_id == latest.id)}
        resolved += sum(1 for cid in prev_fails if latest_results.get(cid) == "PASS")

    scores_in_range = [
        s.compliance_score
        for s in db.query(Scan).filter(Scan.status.in_(SCORED_SCAN_STATUSES), Scan.created_at >= cutoff).all()
        if s.compliance_score is not None
    ]
    compliance_score = round(sum(scores_in_range) / len(scores_in_range), 1) if scores_in_range else 0.0

    # --- Time-series buckets (Task 4) --------------------------------------
    # This previously always returned `timeseries=[]`, which is why the
    # "Compliance Score Over Time" and "Findings by Severity Over Time"
    # charts on Dashboard.tsx rendered "No scans in this window yet." even
    # with real data present -- the charts and the Recharts wiring already
    # existed on the frontend; only this computation was missing.
    #
    # Bucketing: hourly for 24h (24 buckets), daily otherwise (7/30/90
    # buckets) -- matches formatBucketLabel()'s hour-vs-day formatting on
    # the frontend. A bucket with no completed scan gets
    # compliance_score=None (charted as a gap via Recharts `connectNulls`
    # on the compliance line), not 0 -- a flat 0% would misreport "no data"
    # as "total failure", which is a meaningfully different, false signal.
    if range == "24h":
        bucket_count, bucket_delta = 24, timedelta(hours=1)
    else:
        bucket_count, bucket_delta = RANGE_TO_DAYS.get(range, 30), timedelta(days=1)

    now = datetime.utcnow()
    bucket_starts = [now - bucket_delta * (bucket_count - i) for i in _builtins.range(bucket_count)]
    bucket_ends = bucket_starts[1:] + [now]

    window_scans = (
        db.query(Scan)
        .filter(Scan.status.in_(SCORED_SCAN_STATUSES), Scan.created_at >= bucket_starts[0])
        .all()
    )
    window_scan_ids = [s.id for s in window_scans]
    window_findings = (
        db.query(Finding)
        .filter(Finding.scan_id.in_(window_scan_ids), Finding.result == "FAIL")
        .all()
        if window_scan_ids
        else []
    )
    findings_by_scan: dict = defaultdict(list)
    for f in window_findings:
        findings_by_scan[f.scan_id].append(f)

    timeseries: List[DashboardMetricPoint] = []
    for start, end in zip(bucket_starts, bucket_ends):
        bucket_scans = [s for s in window_scans if start <= s.created_at < end]
        bucket_scores = [s.compliance_score for s in bucket_scans if s.compliance_score is not None]
        bucket_sev = defaultdict(int)
        for s in bucket_scans:
            for f in findings_by_scan.get(s.id, []):
                bucket_sev[f.severity] += 1
        timeseries.append(DashboardMetricPoint(
            bucket=start.isoformat(),
            compliance_score=round(sum(bucket_scores) / len(bucket_scores), 1) if bucket_scores else None,
            critical_findings=bucket_sev["CRITICAL"],
            high_findings=bucket_sev["HIGH"],
            medium_findings=bucket_sev["MEDIUM"],
            low_findings=bucket_sev["LOW"],
            open_findings=sum(bucket_sev.values()),
            resolved_findings=0,  # per-bucket resolution isn't tracked; see `resolved` above for the window total
        ))

    return DashboardMetrics(
        range=range,
        compliance_score=compliance_score,
        critical_findings=sev_counts["CRITICAL"],
        high_findings=sev_counts["HIGH"],
        medium_findings=sev_counts["MEDIUM"],
        low_findings=sev_counts["LOW"],
        open_findings=sum(sev_counts.values()),
        resolved_findings=resolved,
        timeseries=timeseries,
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

    # Unified Control Library + Vulnerability Management extensions: pull
    # the multi-framework matrix for this scan's findings and this
    # device's CVE matches, so the compliance-matrix and vulnerability
    # panel report sections have data to render (both degrade to empty
    # sections gracefully -- see reports.build_compliance_matrix_section /
    # build_vulnerability_panel_section -- if the tenant hasn't populated
    # the Unified Control Library or run a vuln sync/correlation yet).
    framework_matrix: dict = {}
    vuln_matches_out: list = []
    if scan.tenant_id:
        control_ids = list({f.get("control_id") for f in findings if f.get("control_id")})
        framework_matrix = control_service.get_framework_matrix(db, scan.tenant_id, control_ids or None)

        matches = (
            db.query(DeviceVulnerabilityMatch)
            .filter(
                DeviceVulnerabilityMatch.device_id == scan.device_id,
                DeviceVulnerabilityMatch.tenant_id == scan.tenant_id,
            )
            .order_by(DeviceVulnerabilityMatch.risk_priority_score.desc().nullslast())
            .all()
        )
        for m in matches:
            vuln = m.vulnerability
            vuln_matches_out.append({
                "cve_id": m.cve_id,
                "status": m.status,
                "risk_priority_score": m.risk_priority_score,
                "linked_control_id": m.linked_control_id,
                "vulnerability": {
                    "cvss_score": vuln.cvss_score if vuln else None,
                    "severity": vuln.severity if vuln else None,
                    "kev_flag": vuln.kev_flag if vuln else False,
                } if vuln else None,
            })

    if fmt == "pdf":
        data = build_pdf_report(scan_dict, device_dict, findings, evidence_dict, framework_matrix, vuln_matches_out)
        media = "application/pdf"
    elif fmt == "csv":
        data = build_csv_report(findings)
        media = "text/csv"
    else:
        data = build_json_report(scan_dict, device_dict, findings, evidence_dict, framework_matrix, vuln_matches_out)
        media = "application/json"

    filename = f"compliance-report-{scan_id[:8]}.{fmt}"

    # Archive the exact bytes just generated (Phase 8 / report_artifacts —
    # see migration a7b8c9d0e1f2). This is what makes tamper detection on
    # an uploaded report possible later: report_verification.py compares an
    # uploaded file's SHA-256 against the row written here, and — for the
    # on-chain layer — cross-checks the scan's Fabric-anchored evidence
    # hash too. Best-effort: a MinIO outage must not block a report
    # download (minio_service.put_object never raises), but the SHA-256 +
    # size are always recorded in Postgres even if the object body upload
    # fails, per ReportArtifact's docstring. Each call gets its own
    # artifact id/object key (never overwritten) so re-downloading after a
    # rerun preserves every prior version rather than silently replacing
    # the archived copy a report-verification lookup might depend on.
    try:
        artifact_id = str(uuid.uuid4())
        sha256_hex = hashlib.sha256(data).hexdigest()
        put_result = minio_service.put_object(
            minio_service.object_key(scan.tenant_id, scan.device_id, scan_id, f"report_{artifact_id}.{fmt}"),
            data,
            content_type=media,
            immutable=True,
        )
        artifact = ReportArtifact(
            id=artifact_id,
            tenant_id=scan.tenant_id,
            scan_id=scan_id,
            format=fmt,
            object_key=put_result.object_key if put_result else None,
            object_bucket=put_result.bucket if put_result else None,
            sha256=sha256_hex,
            size_bytes=len(data),
        )
        db.add(artifact)
        db.commit()
    except Exception:
        # Archival is never allowed to break the report download itself.
        db.rollback()

    return StreamingResponse(BytesIO(data), media_type=media,
                              headers={"Content-Disposition": f"attachment; filename={filename}"})