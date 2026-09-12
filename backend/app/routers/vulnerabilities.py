"""Vulnerability Management API -- CVE listing, per-device matches, and the
manual correlation/sync trigger endpoints.

Auth follows the same pattern as routers/controls.py and backups.py:
Depends(get_current_user) at the router level, Depends(require_role(...))
on the admin-only full sync trigger.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth.dependencies import CurrentUser, get_current_tenant, get_current_user, require_role
from app.db import get_db
from app.models.db import Device, DeviceVulnerabilityMatch, Vulnerability
from app.services import vuln_correlation_service, vuln_sync_service

router = APIRouter(tags=["vulnerabilities"], dependencies=[Depends(get_current_user)])

ADMIN_ONLY = require_role("admin")


class MatchStatusUpdate(BaseModel):
    status: str  # mitigated/accepted_risk/false_positive/open
    justification: Optional[str] = None


def _vuln_dict(v: Vulnerability) -> Dict[str, Any]:
    return {
        "cve_id": v.cve_id,
        "cvss_score": v.cvss_score,
        "severity": v.severity,
        "description": v.description,
        "kev_flag": v.kev_flag,
        "published_date": v.published_date.isoformat() if v.published_date else None,
        "last_modified_date": v.last_modified_date.isoformat() if v.last_modified_date else None,
        "source": v.source,
        "remediation_advice": v.remediation_advice,
    }


def _match_dict(m: DeviceVulnerabilityMatch) -> Dict[str, Any]:
    return {
        "id": m.id,
        "device_id": m.device_id,
        "cve_id": m.cve_id,
        "matched_via": m.matched_via,
        "risk_priority_score": m.risk_priority_score,
        "status": m.status,
        "evidence": m.evidence,
        "justification": m.justification,
        "reviewed_by": m.reviewed_by,
        "reviewed_at": m.reviewed_at.isoformat() if m.reviewed_at else None,
        "linked_control_id": m.linked_control_id,
        "created_at": m.created_at.isoformat() if m.created_at else None,
        "vulnerability": _vuln_dict(m.vulnerability) if m.vulnerability else None,
    }


def _device_or_404(db: Session, device_id: str, tenant_id: str) -> Device:
    device = db.query(Device).filter(Device.id == device_id, Device.tenant_id == tenant_id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    return device


# ---------------------------------------------------------------------------
# CVE catalog
# ---------------------------------------------------------------------------

@router.get("/api/vulnerabilities")
def list_vulnerabilities(
    severity: Optional[str] = None,
    kev_flag: Optional[bool] = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    q = db.query(Vulnerability)
    if severity:
        q = q.filter(Vulnerability.severity == severity.upper())
    if kev_flag is not None:
        q = q.filter(Vulnerability.kev_flag == kev_flag)
    total = q.count()
    rows = q.order_by(Vulnerability.cvss_score.desc().nullslast()).offset(offset).limit(min(limit, 500)).all()
    return {"count": total, "vulnerabilities": [_vuln_dict(v) for v in rows]}


@router.get("/api/vulnerabilities/{cve_id}")
def get_vulnerability(cve_id: str, db: Session = Depends(get_db)):
    v = db.query(Vulnerability).filter(Vulnerability.cve_id == cve_id).first()
    if not v:
        raise HTTPException(404, "CVE not found")
    return _vuln_dict(v)


# ---------------------------------------------------------------------------
# Per-device matches
# ---------------------------------------------------------------------------

@router.get("/api/devices/{device_id}/vulns")
def device_vulns(
    device_id: str,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    device = _device_or_404(db, device_id, tenant_id)
    q = db.query(DeviceVulnerabilityMatch).filter(
        DeviceVulnerabilityMatch.device_id == device.id,
        DeviceVulnerabilityMatch.tenant_id == tenant_id,
    )
    if status:
        q = q.filter(DeviceVulnerabilityMatch.status == status)
    rows = q.order_by(DeviceVulnerabilityMatch.risk_priority_score.desc().nullslast()).all()
    return {"device_id": device.id, "count": len(rows), "matches": [_match_dict(m) for m in rows]}


@router.post("/api/devices/{device_id}/vulns/correlate")
def correlate_device(
    device_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    device = _device_or_404(db, device_id, tenant_id)
    result = vuln_correlation_service.correlate_device(db, tenant_id, device)
    return result


@router.patch("/api/devices/{device_id}/vulns/{match_id}")
def update_match_status(
    device_id: str,
    match_id: str,
    payload: MatchStatusUpdate,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(get_current_user),
):
    if payload.status not in ("open", "mitigated", "accepted_risk", "false_positive"):
        raise HTTPException(400, "status must be one of open/mitigated/accepted_risk/false_positive")

    match = (
        db.query(DeviceVulnerabilityMatch)
        .filter(
            DeviceVulnerabilityMatch.id == match_id,
            DeviceVulnerabilityMatch.device_id == device_id,
            DeviceVulnerabilityMatch.tenant_id == tenant_id,
        )
        .first()
    )
    if not match:
        raise HTTPException(404, "Match not found")

    from datetime import datetime

    match.status = payload.status
    if payload.justification is not None:
        match.justification = payload.justification
    match.reviewed_by = user.username
    match.reviewed_at = datetime.utcnow()
    db.commit()
    db.refresh(match)
    return _match_dict(match)


# ---------------------------------------------------------------------------
# Fleet-wide sync (admin only)
# ---------------------------------------------------------------------------

@router.post("/api/vulns/sync", dependencies=[Depends(ADMIN_ONLY)])
async def trigger_sync(db: Session = Depends(get_db)):
    """Manual trigger of the full NVD/KEV/PSIRT sync -- the same
    vuln_sync_service.sync_all() the background worker calls on its 24h
    poll loop. Runs synchronously and returns the per-feed results; NVD
    sync can take a while on a full catalog pull, so this is intended for
    operator-triggered "sync now" use, not routine polling from the UI.
    """
    return await vuln_sync_service.sync_all(db)