"""Phase 14 -- Change Requests.

POST /api/change-requests               operator/admin: create + validate
GET  /api/change-requests                any authenticated tenant member
GET  /api/change-requests/{id}
POST /api/change-requests/{id}/approve   admin/security_analyst
POST /api/change-requests/{id}/reject    admin/security_analyst
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.auth.dependencies import (CurrentUser, get_current_tenant,
                                    get_current_user, require_permission, require_role)
from app.db import get_db
from app.models.db import ChangeRequest, Device, DeploymentRecord
from app.services import audit_service, change_request_service, deployment_service
from app.rbac import Permission

router = APIRouter(prefix="/api/change-requests", tags=["change-requests"],
                    dependencies=[Depends(get_current_user)])


def _get_owned(db: Session, tenant_id: str, cr_id: str) -> ChangeRequest:
    cr = db.query(ChangeRequest).filter(
        ChangeRequest.id == cr_id, ChangeRequest.tenant_id == tenant_id,
    ).first()
    if not cr:
        raise HTTPException(404, "Change request not found")
    return cr


@router.post("")
async def create_change_request(
    device_id: str = Body(...),
    proposed_config: str = Body(...),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_role("admin", "operator")),
):
    device = db.query(Device).filter(Device.id == device_id, Device.tenant_id == tenant_id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    cr = await change_request_service.create_and_validate(
        db, tenant_id=tenant_id, device=device,
        proposed_config=proposed_config, created_by=user.username, source="manual",
    )
    return change_request_service.to_dict(cr)


@router.get("")
def list_change_requests(
    status: Optional[str] = None,
    device_id: Optional[str] = None,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    q = db.query(ChangeRequest).filter(ChangeRequest.tenant_id == tenant_id)
    if status:
        q = q.filter(ChangeRequest.status == status)
    if device_id:
        q = q.filter(ChangeRequest.device_id == device_id)
    rows = q.order_by(ChangeRequest.created_at.desc()).limit(200).all()
    return {"count": len(rows), "change_requests": [change_request_service.to_dict(c) for c in rows]}


@router.get("/{cr_id}")
def get_change_request(cr_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    return change_request_service.to_dict(_get_owned(db, tenant_id, cr_id))


@router.post("/{cr_id}/approve")
def approve(
    cr_id: str,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_permission(Permission.APPROVE_REMEDIATION)),
):
    cr = _get_owned(db, tenant_id, cr_id)
    prior_status = cr.status
    try:
        cr = change_request_service.approve(db, cr, approved_by=user.username)
    except ValueError as e:
        audit_service.record_from_user(
            db, user, action="change_request.approve", request=request, result="FAILURE",
            object_type="change_request", object_id=cr_id,
            old_value={"status": prior_status}, new_value={"error": str(e)},
        )
        raise HTTPException(409, str(e))
    audit_service.record_from_user(
        db, user, action="change_request.approve", request=request, result="SUCCESS",
        object_type="change_request", object_id=cr_id,
        old_value={"status": prior_status}, new_value={"status": cr.status},
    )
    return change_request_service.to_dict(cr)


@router.post("/{cr_id}/reject")
def reject(
    cr_id: str,
    request: Request,
    reason: str = Body(..., embed=True),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_permission(Permission.APPROVE_REMEDIATION)),
):
    cr = _get_owned(db, tenant_id, cr_id)
    prior_status = cr.status
    try:
        cr = change_request_service.reject(db, cr, rejected_by=user.username, reason=reason)
    except ValueError as e:
        audit_service.record_from_user(
            db, user, action="change_request.reject", request=request, result="FAILURE",
            object_type="change_request", object_id=cr_id,
            old_value={"status": prior_status}, new_value={"error": str(e)},
        )
        raise HTTPException(409, str(e))
    audit_service.record_from_user(
        db, user, action="change_request.reject", request=request, result="SUCCESS",
        object_type="change_request", object_id=cr_id,
        old_value={"status": prior_status}, new_value={"status": cr.status, "reason": reason},
    )
    return change_request_service.to_dict(cr)


@router.post("/{cr_id}/deploy")
async def deploy(
    cr_id: str,
    credential_ref_id: Optional[str] = Body(default=None),
    transport: Optional[str] = Body(default=None),
    framework: str = Body(default="ALL"),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_role("admin", "operator")),
):
    """Deploy an APPROVED change request. Requires prior human approval
    (approve()) -- deployment is never triggered by AI or automatically on
    validation (RULE 4/5)."""
    cr = _get_owned(db, tenant_id, cr_id)
    try:
        dr = await deployment_service.deploy_change_request(
            db, cr, initiated_by=user.username,
            credential_ref_id=credential_ref_id, transport=transport, framework=framework,
        )
    except ValueError as e:
        raise HTTPException(409, str(e))
    return deployment_service.to_dict(dr)


@router.get("/{cr_id}/deployments")
def list_deployments(cr_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    _get_owned(db, tenant_id, cr_id)
    rows = (
        db.query(DeploymentRecord)
        .filter(DeploymentRecord.change_request_id == cr_id, DeploymentRecord.tenant_id == tenant_id)
        .order_by(DeploymentRecord.started_at.desc())
        .all()
    )
    return {"count": len(rows), "deployments": [deployment_service.to_dict(d) for d in rows]}