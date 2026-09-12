"""Enterprise config-backup & NCO management API.

Three concerns live here, all under the "Backups" enterprise page:

1. Snapshots  -- GET /api/devices/{id}/snapshots[/{snapshot_id}[/download]],
   POST /api/devices/{id}/baselines/{snapshot_id}/approve
   A "snapshot" is an already-collected+archived Scan row (raw_config_path
   set, see routers/devices.py::run_scan) -- this is intentionally NOT a
   second data model (RULE 11): it's a read view over Scan +
   BaselineApproval.

2. Backup destinations -- CRUD + test-connection for backup targets
   (AWS S3 / Azure Blob / SFTP-remote-server / local filesystem). Secrets never touch this
   router's request/response bodies beyond the initial write-through to
   OpenBao (RULE 6, mirrors routers/credentials.py).

3. Export jobs -- POST .../export pushes one snapshot to one or more
   destinations and returns per-destination job results; GET
   /api/backup-jobs is the fleet-wide job history/status feed.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.auth.dependencies import CurrentUser, get_current_tenant, get_current_user, require_role
from app.db import get_db
from app.models.backup import BackupDestination, BackupJob
from app.models.db import BaselineApproval, Device, Scan
from app.services import audit_service, backup_destination_service as bkp_svc
from app.services import minio_service

router = APIRouter(tags=["backups"], dependencies=[Depends(get_current_user)])

MANAGE_DESTINATIONS = require_role("admin", "operator")


def _device_or_404(db: Session, device_id: str, tenant_id: str) -> Device:
    device = db.query(Device).filter(Device.id == device_id, Device.tenant_id == tenant_id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    return device


def _destination_or_404(db: Session, destination_id: str, tenant_id: str) -> BackupDestination:
    dest = (
        db.query(BackupDestination)
        .filter(BackupDestination.id == destination_id, BackupDestination.tenant_id == tenant_id)
        .first()
    )
    if not dest:
        raise HTTPException(404, "Backup destination not found")
    return dest


# ---------------------------------------------------------------------------
# Snapshots (config backup history)
# ---------------------------------------------------------------------------

def _snapshot_dict(scan: Scan, golden_scan_id: Optional[str]) -> Dict[str, Any]:
    return {
        "snapshot_id": scan.id,
        "scan_id": scan.id,
        "tenant_id": scan.tenant_id,
        "device_id": scan.device_id,
        "vendor": None,
        "platform": None,
        "collected_at": scan.created_at.isoformat() if scan.created_at else None,
        "source": "collection",
        "configuration_hash": scan.raw_config_hash,
        "raw_config_reference": scan.raw_config_path,
        "parser_version": "v1",
        "normalization_version": "v1",
        "compliance_score": scan.compliance_score,
        "final_decision": scan.final_decision,
        "is_approved_baseline": scan.id == golden_scan_id,
    }


@router.get("/api/devices/{device_id}/snapshots")
def list_device_snapshots(
    device_id: str,
    limit: int = 100,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    device = _device_or_404(db, device_id, tenant_id)
    scans = (
        db.query(Scan)
        .filter(Scan.device_id == device.id, Scan.tenant_id == tenant_id, Scan.raw_config_path.isnot(None))
        .order_by(Scan.created_at.desc())
        .limit(min(limit, 500))
        .all()
    )
    golden = (
        db.query(BaselineApproval)
        .filter(BaselineApproval.device_id == device.id, BaselineApproval.tenant_id == tenant_id)
        .order_by(BaselineApproval.approved_at.desc())
        .first()
    )
    golden_scan_id = golden.scan_id if golden else None
    return {
        "device_id": device.id,
        "count": len(scans),
        "snapshots": [_snapshot_dict(s, golden_scan_id) for s in scans],
    }


@router.get("/api/devices/{device_id}/snapshots/{snapshot_id}")
def get_device_snapshot(
    device_id: str,
    snapshot_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    device = _device_or_404(db, device_id, tenant_id)
    scan = db.query(Scan).filter(Scan.id == snapshot_id, Scan.device_id == device.id, Scan.tenant_id == tenant_id).first()
    if not scan:
        raise HTTPException(404, "Snapshot not found")
    approval = (
        db.query(BaselineApproval)
        .filter(BaselineApproval.device_id == device.id, BaselineApproval.scan_id == scan.id)
        .order_by(BaselineApproval.approved_at.desc())
        .first()
    )
    golden = (
        db.query(BaselineApproval)
        .filter(BaselineApproval.device_id == device.id, BaselineApproval.tenant_id == tenant_id)
        .order_by(BaselineApproval.approved_at.desc())
        .first()
    )
    out = _snapshot_dict(scan, golden.scan_id if golden else None)
    out["baseline"] = scan.baseline_json
    if approval:
        out["approval"] = {
            "approved_by": approval.approved_by,
            "approved_at": approval.approved_at.isoformat() if approval.approved_at else None,
            "approval_reason": approval.approval_reason,
        }
    return out


@router.get("/api/devices/{device_id}/snapshots/{snapshot_id}/download")
def download_device_snapshot(
    device_id: str,
    snapshot_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    device = _device_or_404(db, device_id, tenant_id)
    scan = db.query(Scan).filter(Scan.id == snapshot_id, Scan.device_id == device.id, Scan.tenant_id == tenant_id).first()
    if not scan or not scan.raw_config_path:
        raise HTTPException(404, "Snapshot has no archived configuration")
    try:
        raw = minio_service.get_object(scan.raw_config_path)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"Failed to retrieve archived configuration: {e}")
    return {"snapshot_id": scan.id, "filename": f"{device.hostname or device.id}-{scan.id[:8]}.cfg", "content": raw.decode("utf-8", errors="replace")}


class BaselineApprovalIn(BaseModel):
    approval_reason: Optional[str] = None


@router.post("/api/devices/{device_id}/baselines/{snapshot_id}/approve")
def approve_snapshot_as_baseline(
    device_id: str,
    snapshot_id: str,
    payload: BaselineApprovalIn,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(MANAGE_DESTINATIONS),
):
    device = _device_or_404(db, device_id, tenant_id)
    scan = db.query(Scan).filter(Scan.id == snapshot_id, Scan.device_id == device.id, Scan.tenant_id == tenant_id).first()
    if not scan:
        raise HTTPException(404, "Snapshot not found")

    approval = BaselineApproval(
        tenant_id=tenant_id,
        device_id=device.id,
        scan_id=scan.id,
        approved_by=user.subject if user else "api",
        approval_reason=payload.approval_reason,
    )
    db.add(approval)
    db.commit()
    db.refresh(approval)

    audit_service.record_from_user(
        db, request=request, user=user, action="APPROVE_GOLDEN_CONFIG",
        object_type="device", object_id=device.id,
        new_value={"scan_id": scan.id, "reason": payload.approval_reason}, result="SUCCESS",
    )
    return {
        "id": approval.id,
        "device_id": device.id,
        "scan_id": scan.id,
        "approved_by": approval.approved_by,
        "approved_at": approval.approved_at.isoformat() if approval.approved_at else None,
    }


# ---------------------------------------------------------------------------
# Backup destinations
# ---------------------------------------------------------------------------

class DestinationSecret(BaseModel):
    """Free-form secret bag written straight through to OpenBao and never
    echoed back. Shape depends on destination_type -- see
    services/backup_destination_service.py for the recognized keys per
    type (access_key_id/secret_access_key for s3, connection_string/
    sas_token/account_key for azure_blob, password/private_key for sftp)."""
    values: Dict[str, Any] = Field(default_factory=dict)


class DestinationCreate(BaseModel):
    name: str
    destination_type: str  # s3 | azure_blob | sftp | local
    enabled: bool = True
    config: Dict[str, Any] = Field(default_factory=dict)
    secret: Optional[Dict[str, Any]] = None
    auto_export_enabled: bool = False
    auto_export_scope: Optional[Dict[str, Any]] = None
    retention_days: Optional[int] = None


class DestinationUpdate(BaseModel):
    name: Optional[str] = None
    enabled: Optional[bool] = None
    config: Optional[Dict[str, Any]] = None
    secret: Optional[Dict[str, Any]] = None
    auto_export_enabled: Optional[bool] = None
    auto_export_scope: Optional[Dict[str, Any]] = None
    retention_days: Optional[int] = None


def _destination_out(d: BackupDestination) -> Dict[str, Any]:
    return {
        "id": d.id,
        "name": d.name,
        "destination_type": d.destination_type,
        "enabled": d.enabled,
        "config": d.config or {},
        "has_credentials": bool(d.credential_ref),
        "auto_export_enabled": d.auto_export_enabled,
        "auto_export_scope": d.auto_export_scope,
        "retention_days": d.retention_days,
        "last_test_status": d.last_test_status,
        "last_test_at": d.last_test_at.isoformat() if d.last_test_at else None,
        "last_test_message": d.last_test_message,
        "last_export_status": d.last_export_status,
        "last_export_at": d.last_export_at.isoformat() if d.last_export_at else None,
        "created_by": d.created_by,
        "created_at": d.created_at.isoformat() if d.created_at else None,
        "updated_at": d.updated_at.isoformat() if d.updated_at else None,
    }


CREDENTIAL_TYPE_BY_DESTINATION = {"s3": "s3", "azure_blob": "azure_blob", "sftp": "sftp", "local": "local"}


@router.get("/api/backup-destinations")
def list_destinations(db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    dests = (
        db.query(BackupDestination)
        .filter(BackupDestination.tenant_id == tenant_id)
        .order_by(BackupDestination.created_at.desc())
        .all()
    )
    return {"count": len(dests), "destinations": [_destination_out(d) for d in dests]}


@router.post("/api/backup-destinations")
def create_destination(
    payload: DestinationCreate,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(MANAGE_DESTINATIONS),
):
    if payload.destination_type not in bkp_svc.SUPPORTED_TYPES:
        raise HTTPException(400, f"destination_type must be one of {bkp_svc.SUPPORTED_TYPES}")

    credential_ref = None
    if payload.secret:
        try:
            credential_ref = bkp_svc.store_destination_secret(
                tenant_id, CREDENTIAL_TYPE_BY_DESTINATION[payload.destination_type], payload.secret,
            )
        except bkp_svc.BackupDestinationError as e:
            raise HTTPException(502, str(e))

    dest = BackupDestination(
        tenant_id=tenant_id,
        name=payload.name,
        destination_type=payload.destination_type,
        enabled=payload.enabled,
        config=payload.config,
        credential_ref=credential_ref,
        auto_export_enabled=payload.auto_export_enabled,
        auto_export_scope=payload.auto_export_scope,
        retention_days=payload.retention_days,
        last_test_status="NEVER_TESTED",
        created_by=user.subject if user else "api",
    )
    db.add(dest)
    db.commit()
    db.refresh(dest)

    audit_service.record_from_user(
        db, request=request, user=user, action="CREATE_BACKUP_DESTINATION",
        object_type="backup_destination", object_id=dest.id,
        new_value={"name": dest.name, "type": dest.destination_type}, result="SUCCESS",
    )
    return _destination_out(dest)


@router.patch("/api/backup-destinations/{destination_id}")
def update_destination(
    destination_id: str,
    payload: DestinationUpdate,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(MANAGE_DESTINATIONS),
):
    dest = _destination_or_404(db, destination_id, tenant_id)
    data = payload.model_dump(exclude_unset=True, exclude={"secret"})
    for k, v in data.items():
        setattr(dest, k, v)

    if payload.secret is not None:
        try:
            if dest.credential_ref:
                bkp_svc.rotate_destination_secret(
                    tenant_id, dest.credential_ref, CREDENTIAL_TYPE_BY_DESTINATION[dest.destination_type], payload.secret,
                )
            else:
                dest.credential_ref = bkp_svc.store_destination_secret(
                    tenant_id, CREDENTIAL_TYPE_BY_DESTINATION[dest.destination_type], payload.secret,
                )
        except bkp_svc.BackupDestinationError as e:
            raise HTTPException(502, str(e))

    dest.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(dest)

    audit_service.record_from_user(
        db, request=request, user=user, action="UPDATE_BACKUP_DESTINATION",
        object_type="backup_destination", object_id=dest.id, result="SUCCESS",
    )
    return _destination_out(dest)


@router.delete("/api/backup-destinations/{destination_id}", status_code=204)
def delete_destination(
    destination_id: str,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(MANAGE_DESTINATIONS),
):
    dest = _destination_or_404(db, destination_id, tenant_id)
    if dest.credential_ref:
        bkp_svc.delete_destination_secret(tenant_id, dest.credential_ref)
    db.delete(dest)
    db.commit()
    audit_service.record_from_user(
        db, request=request, user=user, action="DELETE_BACKUP_DESTINATION",
        object_type="backup_destination", object_id=destination_id, result="SUCCESS",
    )
    return None


@router.post("/api/backup-destinations/{destination_id}/test")
def test_destination(
    destination_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(MANAGE_DESTINATIONS),
):
    dest = _destination_or_404(db, destination_id, tenant_id)
    try:
        message = bkp_svc.test_connection(
            tenant_id=tenant_id, destination_type=dest.destination_type,
            config=dest.config or {}, credential_ref=dest.credential_ref,
        )
        dest.last_test_status = "SUCCESS"
        dest.last_test_message = message
        success = True
    except bkp_svc.BackupDestinationError as e:
        dest.last_test_status = "FAILED"
        dest.last_test_message = str(e)[:2000]
        message = str(e)
        success = False
    dest.last_test_at = datetime.utcnow()
    db.commit()
    return {"success": success, "message": message}


# ---------------------------------------------------------------------------
# Export (push a snapshot to one or more destinations) + job history
# ---------------------------------------------------------------------------

class ExportRequest(BaseModel):
    destination_ids: List[str]


def _job_out(job: BackupJob, destination_name: Optional[str] = None, device_hostname: Optional[str] = None) -> Dict[str, Any]:
    return {
        "id": job.id,
        "destination_id": job.destination_id,
        "destination_name": destination_name,
        "device_id": job.device_id,
        "device_hostname": device_hostname,
        "scan_id": job.scan_id,
        "trigger": job.trigger,
        "status": job.status,
        "remote_path": job.remote_path,
        "bytes_written": job.bytes_written,
        "sha256": job.sha256,
        "error": job.error,
        "duration_ms": job.duration_ms,
        "triggered_by": job.triggered_by,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
    }


@router.post("/api/devices/{device_id}/snapshots/{snapshot_id}/export")
def export_snapshot(
    device_id: str,
    snapshot_id: str,
    payload: ExportRequest,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(MANAGE_DESTINATIONS),
):
    device = _device_or_404(db, device_id, tenant_id)
    scan = db.query(Scan).filter(Scan.id == snapshot_id, Scan.device_id == device.id, Scan.tenant_id == tenant_id).first()
    if not scan:
        raise HTTPException(404, "Snapshot not found")
    if not payload.destination_ids:
        raise HTTPException(400, "destination_ids is required")

    results = []
    for dest_id in payload.destination_ids:
        dest = _destination_or_404(db, dest_id, tenant_id)
        job = bkp_svc.run_export_job(
            db, dest, device, scan, trigger="manual", triggered_by=user.subject if user else "api",
        )
        results.append(_job_out(job, destination_name=dest.name, device_hostname=device.hostname))

    audit_service.record_from_user(
        db, request=request, user=user, action="EXPORT_BACKUP_SNAPSHOT",
        object_type="scan", object_id=scan.id,
        new_value={"destination_ids": payload.destination_ids}, result="SUCCESS",
    )
    return {"snapshot_id": scan.id, "results": results}


@router.get("/api/backup-jobs")
def list_backup_jobs(
    device_id: Optional[str] = None,
    destination_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    q = db.query(BackupJob).filter(BackupJob.tenant_id == tenant_id)
    if device_id:
        q = q.filter(BackupJob.device_id == device_id)
    if destination_id:
        q = q.filter(BackupJob.destination_id == destination_id)
    if status:
        q = q.filter(BackupJob.status == status.upper())
    jobs = q.order_by(BackupJob.created_at.desc()).limit(min(limit, 500)).all()

    dest_ids = {j.destination_id for j in jobs}
    dests = {d.id: d for d in db.query(BackupDestination).filter(BackupDestination.id.in_(dest_ids)).all()} if dest_ids else {}
    device_ids = {j.device_id for j in jobs}
    devices = {d.id: d for d in db.query(Device).filter(Device.id.in_(device_ids)).all()} if device_ids else {}

    return {
        "count": len(jobs),
        "jobs": [
            _job_out(
                j,
                destination_name=dests[j.destination_id].name if j.destination_id in dests else None,
                device_hostname=devices[j.device_id].hostname if j.device_id in devices else None,
            )
            for j in jobs
        ],
    }


@router.get("/api/backups/summary")
def backup_fleet_summary(db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    """Compliance-style rollup for the Backups page header cards: overall
    coverage (devices with at least one archived snapshot), golden-config
    coverage, destination health, and recent job success rate."""
    total_devices = db.query(Device).filter(Device.tenant_id == tenant_id, Device.enabled == True).count()  # noqa: E712
    devices_with_snapshot = (
        db.query(Scan.device_id)
        .filter(Scan.tenant_id == tenant_id, Scan.raw_config_path.isnot(None))
        .distinct()
        .count()
    )
    devices_with_golden = (
        db.query(BaselineApproval.device_id)
        .filter(BaselineApproval.tenant_id == tenant_id)
        .distinct()
        .count()
    )
    destinations = db.query(BackupDestination).filter(BackupDestination.tenant_id == tenant_id).all()
    recent_jobs = (
        db.query(BackupJob)
        .filter(BackupJob.tenant_id == tenant_id)
        .order_by(BackupJob.created_at.desc())
        .limit(200)
        .all()
    )
    recent_success = sum(1 for j in recent_jobs if j.status == "SUCCESS")
    recent_failed = sum(1 for j in recent_jobs if j.status == "FAILED")

    return {
        "total_devices": total_devices,
        "devices_with_snapshot": devices_with_snapshot,
        "devices_without_snapshot": max(total_devices - devices_with_snapshot, 0),
        "devices_with_golden_config": devices_with_golden,
        "destination_count": len(destinations),
        "destinations_healthy": sum(1 for d in destinations if d.last_test_status == "SUCCESS"),
        "destinations_failing": sum(1 for d in destinations if d.last_test_status == "FAILED"),
        "recent_jobs_evaluated": len(recent_jobs),
        "recent_jobs_success": recent_success,
        "recent_jobs_failed": recent_failed,
    }