"""Phase 13 -- GET /api/alerts, POST /api/alerts/{id}/acknowledge.

All authenticated tenant members can view/acknowledge alerts for their own
tenant; there's no restriction to admin-only here since alerts are
informational, not a control-plane action (unlike training approvals or
device collection).
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth.dependencies import CurrentUser, get_current_tenant, get_current_user
from app.db import get_db
from app.models.db import Alert
from app.services import alert_service

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
    user: CurrentUser = Depends(get_current_user),
):
    alert = db.query(Alert).filter(Alert.id == alert_id, Alert.tenant_id == tenant_id).first()
    if not alert:
        raise HTTPException(404, "Alert not found")
    alert = alert_service.acknowledge_alert(db, alert, acknowledged_by=user.username)
    return alert_service.to_dict(alert)