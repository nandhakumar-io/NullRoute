"""Section 12: read access to the audit trail.

Restricted to roles that carry Permission.VIEW_AUDIT_LOG (AUDITOR,
TENANT_ADMIN, SUPER_ADMIN) — an auditor must be able to see everything
that happened in their tenant without being able to change anything
(enforced separately: AUDITOR has no mutating permissions in rbac.py).
"""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.db import AuditLog
from app.schemas import AuditLogOut
from app.auth.rbac import Permission
from app.services import audit_service

from app.auth.dependencies import get_current_tenant, get_current_user, require_permission

router = APIRouter(prefix="/api/audit-log", tags=["audit"], dependencies=[Depends(get_current_user)])


def _filtered_query(
    db: Session,
    tenant_id: str,
    action: Optional[str],
    object_type: Optional[str],
    object_id: Optional[str],
    username: Optional[str],
    result: Optional[str],
    since: Optional[datetime],
    until: Optional[datetime],
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
    return q.order_by(AuditLog.created_at.desc())


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
    q = _filtered_query(db, tenant_id, action, object_type, object_id, username, result, since, until)
    return q.offset(offset).limit(limit).all()


_EXPORT_COLUMNS = [
    "id", "created_at", "username", "action", "object_type", "object_id",
    "source_ip", "result", "details",
]


def _row_dict(row: AuditLog) -> dict:
    return {
        "id": row.id,
        "created_at": row.created_at.isoformat() if row.created_at else "",
        "username": row.username or "",
        "action": row.action or "",
        "object_type": row.object_type or "",
        "object_id": row.object_id or "",
        "source_ip": row.source_ip or "",
        "result": row.result or "",
        "details": json.dumps(row.details, default=str) if getattr(row, "details", None) is not None else "",
    }


@router.get("/export")
def export_audit_log(
    format: str = Query("csv", pattern="^(csv|json)$"),
    action: Optional[str] = None,
    object_type: Optional[str] = None,
    object_id: Optional[str] = None,
    username: Optional[str] = None,
    result: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    limit: int = Query(5000, ge=1, le=20000),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user=Depends(require_permission(Permission.VIEW_AUDIT_LOG)),
):
    """Export the (filtered) audit trail as CSV or JSON for compliance
    hand-off / offline review. Honors the exact same filters as the list
    endpoint above so "export what I'm currently looking at" is literal --
    and is itself audit-logged (exporting the audit log is a sensitive,
    reportable action in its own right)."""
    q = _filtered_query(db, tenant_id, action, object_type, object_id, username, result, since, until)
    rows = q.limit(limit).all()

    audit_service.record_from_user(
        db, user, "audit_log.export",
        object_type="audit_log", object_id=None,
        new_value={"format": format, "row_count": len(rows)},
    )

    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")

    if format == "json":
        payload = json.dumps([_row_dict(r) for r in rows], indent=2)
        return StreamingResponse(
            io.BytesIO(payload.encode("utf-8")),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="audit-log-{timestamp}.json"'},
        )

    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=_EXPORT_COLUMNS)
    writer.writeheader()
    for row in rows:
        writer.writerow(_row_dict(row))
    buffer.seek(0)
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="audit-log-{timestamp}.csv"'},
    )