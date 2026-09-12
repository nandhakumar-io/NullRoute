"""Report Verification -- "did someone tamper with this downloaded report?"

Two independent checks, mirroring the two-layer integrity model used
elsewhere in this app (see services/evidence_service.py and
services/minio_service.py's module docstring):

  1. Off-chain: recompute SHA-256 of the uploaded file and compare it
     against the ReportArtifact row(s) archived in Postgres at the moment
     the report was originally generated (see routers/compliance.py::
     get_report). A mismatch means the bytes changed since download.

  2. On-chain cross-check: if the scan's evidence package is anchored on
     Hyperledger Fabric, re-verify that evidence's hash against the
     immutable ledger (same call as routers/evidence.py::verify_evidence).
     This catches the harder case where an attacker with Postgres write
     access edited the report_artifacts row *and* the archived bytes
     together -- Fabric sits outside Postgres' reach, so it still
     disagrees.

Recovery: when a report is TAMPERED, GET /api/reports/artifact/{id}/download
streams back the untouched original from MinIO (Object-Lock protected --
see minio_service.py) when it's still there. If the original bytes are
gone (MinIO outage at generation time, retention expiry, MinIO disabled),
but the underlying scan/findings are still in the system, the report is
regenerated fresh from current data instead. That fallback is NOT
byte-identical to what was originally downloaded (timestamps, any
findings added since) and the endpoint tells the caller so via the
X-Report-Source response header, which the UI surfaces to the user.

Every verify/recovery action is written to the audit trail (Section 12)
via app.services.audit_service, same as every other sensitive action in
this app.
"""
from __future__ import annotations

import hashlib
import json
import logging
from io import BytesIO
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.auth.dependencies import CurrentUser, get_current_tenant, get_current_user
from app.db import get_db
from app.models.db import Device, EvidenceRecord, Finding, ReportArtifact, Scan
from app.schemas import FindingOut, ReportArtifactOut, ReportVerifyResultOut, ScanOut
from app.services import audit_service, control_service, evidence_service, fabric_service, minio_service
from app.services.reports import build_csv_report, build_json_report, build_pdf_report

logger = logging.getLogger("report_verification")

router = APIRouter(prefix="/api/reports", tags=["report-verification"], dependencies=[Depends(get_current_user)])

# Reports are small (findings + a matrix); this is a generous ceiling that
# still blocks someone using the upload as a DoS/storage-abuse vector.
MAX_UPLOAD_BYTES = 25 * 1024 * 1024

_MEDIA_TYPES = {"pdf": "application/pdf", "csv": "text/csv", "json": "application/json"}


def _extract_scan_id_from_json(data: bytes) -> Optional[str]:
    """Best-effort: our own JSON reports embed the scan under "scan":
    {"id": ...} (see services/reports.py::build_json_report), so a JSON
    upload doesn't strictly need scan_id typed in by hand."""
    try:
        obj = json.loads(data)
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    scan_obj = obj.get("scan")
    if isinstance(scan_obj, dict) and scan_obj.get("id"):
        return str(scan_obj["id"])
    return None


@router.post("/verify", response_model=ReportVerifyResultOut)
async def verify_report(
    request: Request,
    file: UploadFile = File(...),
    scan_id: Optional[str] = Form(None),
    fmt: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(get_current_user),
):
    data = await file.read()
    if not data:
        raise HTTPException(400, "Uploaded file is empty")
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "File is too large to be a generated report")

    resolved_fmt = (fmt or "").lower().strip() or None
    if not resolved_fmt and file.filename and "." in file.filename:
        ext = file.filename.lower().rsplit(".", 1)[-1]
        if ext in ("pdf", "json", "csv"):
            resolved_fmt = ext
    if resolved_fmt not in ("pdf", "json", "csv"):
        raise HTTPException(
            400, "Could not determine the report format -- pass fmt explicitly or upload a .pdf/.json/.csv file"
        )

    resolved_scan_id = (scan_id or "").strip() or None
    if not resolved_scan_id and resolved_fmt == "json":
        resolved_scan_id = _extract_scan_id_from_json(data)
    if not resolved_scan_id:
        raise HTTPException(400, "scan_id is required for this format")

    calculated_hash = hashlib.sha256(data).hexdigest()

    scan = db.query(Scan).filter(Scan.id == resolved_scan_id, Scan.tenant_id == tenant_id).first()
    artifacts = (
        db.query(ReportArtifact)
        .filter(
            ReportArtifact.scan_id == resolved_scan_id,
            ReportArtifact.tenant_id == tenant_id,
            ReportArtifact.format == resolved_fmt,
        )
        .order_by(ReportArtifact.created_at.desc())
        .all()
    )

    if scan is None or not artifacts:
        audit_service.record_from_user(
            db, user=user, action="VERIFY_REPORT", request=request,
            object_type="report", object_id=resolved_scan_id,
            new_value={"format": resolved_fmt, "calculated_hash": calculated_hash, "status": "UNKNOWN_REPORT"},
            result="FAILURE",
        )
        return ReportVerifyResultOut(
            status="UNKNOWN_REPORT",
            match=False,
            calculated_hash=calculated_hash,
            scan_id=resolved_scan_id,
            format=resolved_fmt,
            downloadable=False,
            message=(
                "No archived report was found for this scan ID and format, so there is nothing on "
                "file to compare it against. Double-check the scan ID, or generate/download the "
                "report from the Scan Detail or Reports page first so an archived copy exists."
            ),
        )

    matched = next((a for a in artifacts if a.sha256 == calculated_hash), None)

    # On-chain cross-check (independent of whether the off-chain hash
    # matched): re-verify the scan's linked evidence against Fabric, when
    # anchored. A disagreement here means the archive itself may have
    # been compromised even if the uploaded file's hash happens to match
    # our (potentially altered) Postgres row.
    fabric_checked = False
    fabric_match: Optional[bool] = None
    fabric_status: Optional[str] = None
    if scan.evidence_id:
        record = db.query(EvidenceRecord).filter(EvidenceRecord.evidence_id == scan.evidence_id).first()
        if record and fabric_service.FABRIC_ENABLED and record.fabric_status == "ANCHORED":
            ev_result = evidence_service.verify_evidence(record.evidence_hash, record.evidence_json)
            try:
                fabric_result = await fabric_service.verify_evidence(record.evidence_id, ev_result["calculated_hash"])
                fabric_checked = True
                fabric_match = bool(fabric_result.get("match")) and ev_result["match"]
                fabric_status = fabric_result.get("status")
            except fabric_service.FabricUnavailableError:
                fabric_status = "FABRIC_UNAVAILABLE"

    if matched and fabric_match is not False:
        status = "VERIFIED"
        message = "This report's contents exactly match the copy archived when it was generated. It has not been modified."
    elif matched and fabric_match is False:
        status = "TAMPERED"
        message = (
            "The uploaded file's hash matches our archived copy, but that scan's evidence no longer "
            "matches the immutable Fabric-anchored hash -- the archive itself appears to have been "
            "altered. Treat this report as untrustworthy."
        )
    else:
        status = "TAMPERED"
        message = "This report's hash does not match our archived copy for this scan -- the file has been modified since it was generated."

    latest = artifacts[0]
    has_stored_copy = bool(latest.object_key)
    # "downloadable" means we can hand back an authentic copy: either the
    # exact original bytes (has_stored_copy) or, failing that, a fresh
    # regeneration from the scan's current data (possible as long as the
    # scan row itself still exists, which it does here).
    downloadable = status == "TAMPERED"

    audit_service.record_from_user(
        db, user=user, action="VERIFY_REPORT", request=request,
        object_type="report", object_id=resolved_scan_id,
        new_value={
            "format": resolved_fmt, "calculated_hash": calculated_hash, "status": status,
            "artifact_id": latest.id, "fabric_checked": fabric_checked, "fabric_match": fabric_match,
        },
        result="SUCCESS" if status == "VERIFIED" else "FAILURE",
    )

    return ReportVerifyResultOut(
        status=status,
        match=matched is not None,
        calculated_hash=calculated_hash,
        scan_id=resolved_scan_id,
        format=resolved_fmt,
        artifact=ReportArtifactOut(
            id=latest.id, scan_id=latest.scan_id, format=latest.format, sha256=latest.sha256,
            size_bytes=latest.size_bytes, created_at=latest.created_at, has_stored_copy=has_stored_copy,
        ),
        fabric_checked=fabric_checked,
        fabric_match=fabric_match,
        fabric_status=fabric_status,
        downloadable=downloadable,
        message=message,
    )


@router.get("/artifact/{artifact_id}/download")
def download_original_report(
    artifact_id: str,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(get_current_user),
):
    artifact = (
        db.query(ReportArtifact)
        .filter(ReportArtifact.id == artifact_id, ReportArtifact.tenant_id == tenant_id)
        .first()
    )
    if not artifact:
        raise HTTPException(404, "Report artifact not found")

    media = _MEDIA_TYPES[artifact.format]
    filename = f"compliance-report-{artifact.scan_id[:8]}.{artifact.format}"
    source = "archived"
    data: Optional[bytes] = None

    if artifact.object_key:
        try:
            data = minio_service.get_object(artifact.object_key)
        except minio_service.ObjectStoreError as e:
            logger.warning("Could not fetch archived report %s (%s): %s -- falling back to regeneration",
                            artifact.id, artifact.object_key, e)
            data = None

    if data is None:
        scan = db.query(Scan).filter(Scan.id == artifact.scan_id, Scan.tenant_id == tenant_id).first()
        if not scan:
            raise HTTPException(410, "The original report bytes are gone and the underlying scan no longer exists")
        device = db.query(Device).get(scan.device_id)
        findings = [
            FindingOut.model_validate(f).model_dump()
            for f in db.query(Finding).filter(Finding.scan_id == scan.id).all()
        ]
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

        framework_matrix: dict = {}
        if scan.tenant_id:
            control_ids = list({f.get("control_id") for f in findings if f.get("control_id")})
            framework_matrix = control_service.get_framework_matrix(db, scan.tenant_id, control_ids or None)

        if artifact.format == "pdf":
            data = build_pdf_report(scan_dict, device_dict, findings, evidence_dict, framework_matrix, [])
        elif artifact.format == "csv":
            data = build_csv_report(findings)
        else:
            data = build_json_report(scan_dict, device_dict, findings, evidence_dict, framework_matrix, [])
        source = "regenerated"

    audit_service.record_from_user(
        db, user=user, action="DOWNLOAD_RECOVERED_REPORT", request=request,
        object_type="report_artifact", object_id=artifact.id,
        new_value={"scan_id": artifact.scan_id, "format": artifact.format, "source": source},
        result="SUCCESS",
    )

    return StreamingResponse(
        BytesIO(data),
        media_type=media,
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "X-Report-Source": source,
        },
    )
