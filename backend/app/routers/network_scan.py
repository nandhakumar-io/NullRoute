"""Enterprise Network Scan orchestration endpoints.

Creating a job only inserts a PENDING row -- execution happens in
app/workers/network_scan_worker.py (see services/network_scan_service.py
docstring for why), matching the existing AuditSchedule /
scheduler_worker.py pattern exactly (RULE: no long device scans inside a
request handler). The UI polls GET /{id} for real per-stage progress.
"""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.auth.dependencies import CurrentUser, get_current_tenant, get_current_user, require_role
from app.db import get_db
from app.models.db import Device, NetworkScanJob
from app.schemas import NetworkScanJobCreate, NetworkScanJobOut
from app.services.network_scan_service import init_stages

router = APIRouter(prefix="/api/network-scans", tags=["network-scans"], dependencies=[Depends(get_current_user)])


def _get_or_404(db: Session, job_id: str, tenant_id: str) -> NetworkScanJob:
    row = db.query(NetworkScanJob).filter(
        NetworkScanJob.id == job_id, NetworkScanJob.tenant_id == tenant_id
    ).first()
    if not row:
        raise HTTPException(404, "Network scan job not found")
    return row


@router.get("", response_model=List[NetworkScanJobOut])
def list_scan_jobs(
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    limit: int = Query(50, ge=1, le=200),
):
    return (
        db.query(NetworkScanJob)
        .filter(NetworkScanJob.tenant_id == tenant_id)
        .order_by(NetworkScanJob.created_at.desc())
        .limit(limit)
        .all()
    )


@router.get("/{job_id}", response_model=NetworkScanJobOut)
def get_scan_job(job_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    return _get_or_404(db, job_id, tenant_id)


@router.post("", response_model=NetworkScanJobOut)
def create_scan_job(
    payload: NetworkScanJobCreate,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_role("admin", "operator")),
):
    if not payload.run_discovery and not payload.device_ids:
        raise HTTPException(400, "Provide device_ids and/or run_discovery + target_cidr")
    if payload.run_discovery and not payload.target_cidr:
        raise HTTPException(400, "target_cidr is required when run_discovery is true")

    device_ids: Optional[List[str]] = payload.device_ids
    if device_ids:
        found = {
            d.id for d in db.query(Device.id).filter(
                Device.tenant_id == tenant_id, Device.id.in_(device_ids)
            ).all()
        }
        missing = set(device_ids) - found
        if missing:
            raise HTTPException(404, f"Unknown device id(s) for this tenant: {sorted(missing)}")

    job = NetworkScanJob(
        tenant_id=tenant_id,
        name=payload.name,
        run_discovery=payload.run_discovery,
        target_cidr=payload.target_cidr if payload.run_discovery else None,
        discovery_ports=payload.discovery_ports,
        requested_device_ids=device_ids or [],
        framework=payload.framework,
        include_batfish=payload.include_batfish,
        status="PENDING",
        stages=init_stages(),
        created_by=user.username if user else None,
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job
