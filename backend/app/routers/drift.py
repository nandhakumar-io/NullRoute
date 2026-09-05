"""Phase 11 -- tenant-wide configuration drift feed (GET /api/drift).

Per-device history lives at GET /api/devices/{id}/drift (routers/devices.py);
this endpoint is the cross-device feed used by the frontend Drift page and
for alerting (Phase 13) on security-impacting drift.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_tenant, get_current_user
from app.db import get_db
from app.models.db import DriftEvent
from app.services import drift_service

router = APIRouter(prefix="/api/drift", tags=["drift"], dependencies=[Depends(get_current_user)])


@router.get("")
def list_drift(
    limit: int = 100,
    security_impacting: Optional[bool] = None,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    q = db.query(DriftEvent).filter(DriftEvent.tenant_id == tenant_id)
    if security_impacting is not None:
        q = q.filter(DriftEvent.security_impacting == security_impacting)
    events = q.order_by(DriftEvent.created_at.desc()).limit(min(limit, 500)).all()
    return {"count": len(events), "events": [drift_service.to_dict(e) for e in events]}