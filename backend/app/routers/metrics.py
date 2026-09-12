"""Phase 15 -- Device metrics history & threshold configuration.

GET  /api/devices/{id}/metrics/history      time-series of persisted
                                             DeviceMetricSnapshot rows
                                             (CPU/memory/interface trend
                                             charts on Device Detail)
GET  /api/devices/{id}/metrics/latest       most recent snapshot only
GET  /api/metrics/thresholds                tenant's alert thresholds
PUT  /api/metrics/thresholds                update tenant's alert thresholds

Thresholds are stored per-tenant (not per-device) for now, matching the
simple global-default model most of this app's other alerting config uses;
device-level overrides can be layered on top later without a breaking
change since the poller always merges tenant thresholds under
metrics_service.DEFAULT_THRESHOLDS.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_tenant, get_current_user
from app.db import get_db
from app.models.db import Device, DeviceMetricSnapshot, TenantSetting
from app.services import metrics_service

router = APIRouter(prefix="/api", tags=["metrics"], dependencies=[Depends(get_current_user)])

THRESHOLDS_SETTING_KEY = "metrics_alert_thresholds"


def _get_device(db: Session, device_id: str, tenant_id: str) -> Device:
    device = db.query(Device).filter(Device.id == device_id, Device.tenant_id == tenant_id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    return device


def _snapshot_out(s: DeviceMetricSnapshot) -> dict:
    return {
        "id": s.id,
        "collected_at": s.collected_at.isoformat() if s.collected_at else None,
        "source": s.source,
        "success": s.success,
        "error": s.error,
        "cpu_average_pct": s.cpu_average_pct,
        "memory_used_pct": s.memory_used_pct,
        "memory_total_bytes": s.memory_total_bytes,
        "memory_used_bytes": s.memory_used_bytes,
        "interface_utilization": s.interface_utilization,
        "environmental": s.environmental,
    }


@router.get("/devices/{device_id}/metrics/history")
def get_metrics_history(
    device_id: str,
    hours: int = Query(24, ge=1, le=24 * 30),
    limit: int = Query(500, ge=1, le=5000),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    _get_device(db, device_id, tenant_id)
    since = datetime.utcnow() - timedelta(hours=hours)
    rows = metrics_service.history(db, device_id, tenant_id, since=since, limit=limit)
    return {"device_id": device_id, "count": len(rows), "snapshots": [_snapshot_out(s) for s in rows]}


@router.get("/devices/{device_id}/metrics/latest")
def get_metrics_latest(
    device_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    _get_device(db, device_id, tenant_id)
    rows = metrics_service.history(db, device_id, tenant_id, limit=1)
    if not rows:
        return {"device_id": device_id, "snapshot": None}
    return {"device_id": device_id, "snapshot": _snapshot_out(rows[0])}


class ThresholdsUpdate(BaseModel):
    cpu_average_pct: Optional[float] = Field(None, ge=0, le=100)
    memory_used_pct: Optional[float] = Field(None, ge=0, le=100)
    interface_utilization_pct: Optional[float] = Field(None, ge=0, le=100)
    interface_error_rate: Optional[float] = Field(None, ge=0)


def _thresholds_row(db: Session, tenant_id: str) -> Optional[TenantSetting]:
    return (
        db.query(TenantSetting)
        .filter(TenantSetting.tenant_id == tenant_id, TenantSetting.key == THRESHOLDS_SETTING_KEY)
        .first()
    )


@router.get("/metrics/thresholds")
def get_thresholds(db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    row = _thresholds_row(db, tenant_id)
    merged = {**metrics_service.DEFAULT_THRESHOLDS, **((row.value or {}) if row else {})}
    return merged


@router.put("/metrics/thresholds")
def update_thresholds(
    payload: ThresholdsUpdate,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    row = _thresholds_row(db, tenant_id)
    new_values = {k: v for k, v in payload.dict().items() if v is not None}
    if row:
        row.value = {**(row.value or {}), **new_values}
    else:
        row = TenantSetting(tenant_id=tenant_id, key=THRESHOLDS_SETTING_KEY, value=new_values)
        db.add(row)
    db.commit()
    return {**metrics_service.DEFAULT_THRESHOLDS, **(row.value or {})}