"""Phase 13 -- GET /api/alerts, POST /api/alerts/{id}/acknowledge.

All authenticated tenant members can view alerts for their own tenant.
Acknowledging is a state-mutating action, though, so (per the Section 11
RBAC audit) it's gated to everyone except pure VIEWER -- read-only users
can see alerts but shouldn't be able to change their status.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth.dependencies import CurrentUser, get_current_tenant, get_current_user, require_role
from app.auth.rbac import ALL_ROLE_NAMES
from app.db import get_db
from app.models.db import Alert
from app.services import alert_service

# Every recognized role except the read-only VIEWER (canonical + legacy name).
_NON_VIEWER_ROLES = [r for r in ALL_ROLE_NAMES if r not in ("VIEWER", "viewer")]

router = APIRouter(prefix="/api/alerts", tags=["alerts"], dependencies=[Depends(get_current_user)])


@router.get("")
def list_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    q = db.query(Alert).filter(Alert.tenant_id == tenant_id)
    if status:
        q = q.filter(Alert.status == status)
    if severity:
        q = q.filter(Alert.severity == severity)
    if category:
        q = q.filter(Alert.category == category)
    rows = q.order_by(Alert.created_at.desc()).limit(min(limit, 500)).all()
    return {"count": len(rows), "alerts": [alert_service.to_dict(a) for a in rows]}


@router.post("/{alert_id}/acknowledge")
def acknowledge_alert(
    alert_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_role(*_NON_VIEWER_ROLES)),
):
    alert = db.query(Alert).filter(Alert.id == alert_id, Alert.tenant_id == tenant_id).first()
    if not alert:
        raise HTTPException(404, "Alert not found")
    alert = alert_service.acknowledge_alert(db, alert, acknowledged_by=user.username)
    return alert_service.to_dict(alert)