"""Phase 16 -- Compliance Exceptions.

POST /api/exceptions                request an exception (any authenticated tenant member)
GET  /api/exceptions                 list (auto-expires stale APPROVED rows on read)
POST /api/exceptions/{id}/approve    admin/security_analyst
POST /api/exceptions/{id}/reject     admin/security_analyst
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth.dependencies import (CurrentUser, get_current_tenant,
                                    get_current_user, require_role)
from app.db import get_db
from app.models.db import ComplianceException, Device
from app.services import exception_service

router = APIRouter(prefix="/api/exceptions", tags=["exceptions"],
                    dependencies=[Depends(get_current_user)])


def _get_owned(db: Session, tenant_id: str, exc_id: str) -> ComplianceException:
    exc = db.query(ComplianceException).filter(
        ComplianceException.id == exc_id, ComplianceException.tenant_id == tenant_id,
    ).first()
    if not exc:
        raise HTTPException(404, "Exception not found")
    return exc


@router.post("")
def request_exception(
    device_id: str = Body(...),
    control_id: str = Body(...),
    reason: str = Body(...),
    expires_at: datetime = Body(...),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(get_current_user),
):
    device = db.query(Device).filter(Device.id == device_id, Device.tenant_id == tenant_id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    if expires_at <= datetime.utcnow():
        raise HTTPException(422, "expires_at must be in the future")
    exc = exception_service.create_exception(
        db, tenant_id=tenant_id, device_id=device_id, control_id=control_id,
        reason=reason, expires_at=expires_at, created_by=user.username,
    )
    return exception_service.to_dict(exc)


@router.get("")
def list_exceptions(
    status: Optional[str] = None,
    device_id: Optional[str] = None,
    control_id: Optional[str] = None,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    exception_service.sweep_expired(db, tenant_id)
    q = db.query(ComplianceException).filter(ComplianceException.tenant_id == tenant_id)
    if status:
        q = q.filter(ComplianceException.status == status.upper())
    if device_id:
        q = q.filter(ComplianceException.device_id == device_id)
    if control_id:
        q = q.filter(ComplianceException.control_id == control_id)
    rows = q.order_by(ComplianceException.created_at.desc()).limit(500).all()
    return {"count": len(rows), "exceptions": [exception_service.to_dict(e) for e in rows]}


@router.post("/{exc_id}/approve")
def approve(
    exc_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_role("admin", "security_analyst")),
):
    exc = _get_owned(db, tenant_id, exc_id)
    try:
        exc = exception_service.approve_exception(db, exc, approved_by=user.username)
    except ValueError as e:
        raise HTTPException(409, str(e))
    return exception_service.to_dict(exc)


@router.post("/{exc_id}/reject")
def reject(
    exc_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_role("admin", "security_analyst")),
):
    exc = _get_owned(db, tenant_id, exc_id)
    try:
        exc = exception_service.reject_exception(db, exc, rejected_by=user.username)
    except ValueError as e:
        raise HTTPException(409, str(e))
    return exception_service.to_dict(exc)