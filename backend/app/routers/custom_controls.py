"""Tenant-defined CustomControl CRUD + approval workflow.

IMPLEMENTATION_AUDIT.md §C. A CustomControl is created pending_review and
has zero effect on any scan until approve() is called -- see
services/custom_control_service.py for why, and
services/compliance.py::evaluate_baseline_via_opa for where approved rows
get pulled into input.custom_controls on the next evaluation.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.auth.dependencies import CurrentUser, get_current_tenant, get_current_user, require_role
from app.db import get_db
from app.services import custom_control_service

router = APIRouter(prefix="/api/custom-controls", tags=["custom-controls"], dependencies=[Depends(get_current_user)])

MANAGE_CUSTOM_CONTROLS = require_role("admin", "security_analyst")
APPROVE_CUSTOM_CONTROLS = require_role("admin", "security_analyst")


class CustomControlCreate(BaseModel):
    control_id: str = Field(..., description='e.g. "CUSTOM-SSH-001"; unique per tenant')
    title: str
    parameter: str = Field(..., description="dotted path on the flattened baseline, e.g. management.ssh.version")
    operator: str = Field(..., description="eq/ne/gte/lte/in/exists/not_true")
    expected: Any
    severity: str = "MEDIUM"
    remediation: Optional[str] = None


def _control_dict(c) -> Dict[str, Any]:
    return {
        "id": c.id,
        "control_id": c.control_id,
        "title": c.title,
        "parameter": c.parameter,
        "operator": c.operator,
        "expected": c.expected_json,
        "severity": c.severity,
        "remediation": c.remediation,
        "status": c.status,
        "created_by": c.created_by,
        "approved_by": c.approved_by,
        "approved_at": c.approved_at.isoformat() if c.approved_at else None,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "updated_at": c.updated_at.isoformat() if c.updated_at else None,
    }


@router.get("")
def list_custom_controls(
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    rows = custom_control_service.list_controls(db, tenant_id, status=status)
    return {"count": len(rows), "controls": [_control_dict(c) for c in rows]}


@router.post("", dependencies=[Depends(MANAGE_CUSTOM_CONTROLS)])
def create_custom_control(
    payload: CustomControlCreate,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(get_current_user),
):
    try:
        row = custom_control_service.create_control(
            db, tenant_id,
            control_id=payload.control_id, title=payload.title, parameter=payload.parameter,
            operator=payload.operator, expected=payload.expected, severity=payload.severity,
            remediation=payload.remediation, created_by=user.username,
        )
    except custom_control_service.CustomControlValidationError as exc:
        raise HTTPException(400, str(exc))
    return _control_dict(row)


@router.get("/{control_id}")
def get_custom_control(control_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    row = custom_control_service.get_control(db, tenant_id, control_id)
    if not row:
        raise HTTPException(404, "Custom control not found")
    return _control_dict(row)


@router.post("/{control_id}/approve", dependencies=[Depends(APPROVE_CUSTOM_CONTROLS)])
def approve_custom_control(
    control_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(get_current_user),
):
    row = custom_control_service.get_control(db, tenant_id, control_id)
    if not row:
        raise HTTPException(404, "Custom control not found")
    if row.status == "approved":
        raise HTTPException(400, "Already approved")
    row = custom_control_service.approve_control(db, row, user.username)
    return _control_dict(row)


@router.post("/{control_id}/reject", dependencies=[Depends(APPROVE_CUSTOM_CONTROLS)])
def reject_custom_control(
    control_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(get_current_user),
):
    row = custom_control_service.get_control(db, tenant_id, control_id)
    if not row:
        raise HTTPException(404, "Custom control not found")
    row = custom_control_service.reject_control(db, row, user.username)
    return _control_dict(row)


@router.delete("/{control_id}", dependencies=[Depends(MANAGE_CUSTOM_CONTROLS)])
def delete_custom_control(control_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    row = custom_control_service.get_control(db, tenant_id, control_id)
    if not row:
        raise HTTPException(404, "Custom control not found")
    custom_control_service.delete_control(db, row)
    return {"deleted": True, "id": control_id}