"""Section 12: read access to the audit trail.

Restricted to roles that carry Permission.VIEW_AUDIT_LOG (AUDITOR,
TENANT_ADMIN, SUPER_ADMIN) — an auditor must be able to see everything
that happened in their tenant without being able to change anything
(enforced separately: AUDITOR has no mutating permissions in rbac.py).
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.db import AuditLog
from app.schemas import AuditLogOut
from app.auth.rbac import Permission

from app.auth.dependencies import get_current_tenant, get_current_user, require_permission

router = APIRouter(prefix="/api/audit-log", tags=["audit"], dependencies=[Depends(get_current_user)])


@router.get("", response_model=List[AuditLogOut])
def list_audit_log(
    action: Optional[str] = None,
    object_type: Optional[str] = None,
    object_id: Optional[str] = None,
    username: Optional[str] = None,
    result: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    _user=Depends(require_permission(Permission.VIEW_AUDIT_LOG)),
):
    q = db.query(AuditLog).filter(AuditLog.tenant_id == tenant_id)
    if action:
        q = q.filter(AuditLog.action == action)
    if object_type:
        q = q.filter(AuditLog.object_type == object_type)
    if object_id:
        q = q.filter(AuditLog.object_id == object_id)
    if username:
        q = q.filter(AuditLog.username == username)
    if result:
        q = q.filter(AuditLog.result == result.upper())
    if since:
        q = q.filter(AuditLog.created_at >= since)
    if until:
        q = q.filter(AuditLog.created_at <= until)
    return q.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit).all()