"""Phase 12 -- scheduled audits.

Creating/updating/deleting a schedule is admin/operator only (same bar as
device configuration collection, since a schedule ultimately triggers
device collection). Any authenticated tenant member can list/view their
own tenant's schedules. Manually triggering a run is exposed via
POST /api/schedules/{id}/run for on-demand execution of a "manual"
schedule (or an early run of a recurring one) -- it still goes through
scheduling_service.execute_schedule(), never a duplicate code path.
"""
from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth.dependencies import CurrentUser, get_current_tenant, get_current_user, require_role
from app.db import get_db
from app.models.db import AuditSchedule
from app.schemas import ScheduleCreate, ScheduleOut, ScheduleUpdate
from app.services import scheduling_service

router = APIRouter(prefix="/api/schedules", tags=["schedules"], dependencies=[Depends(get_current_user)])


def _get_or_404(db: Session, schedule_id: str, tenant_id: str) -> AuditSchedule:
    row = db.query(AuditSchedule).filter(
        AuditSchedule.id == schedule_id, AuditSchedule.tenant_id == tenant_id
    ).first()
    if not row:
        raise HTTPException(404, "Schedule not found")
    return row


@router.get("", response_model=List[ScheduleOut])
def list_schedules(db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    return db.query(AuditSchedule).filter(AuditSchedule.tenant_id == tenant_id).order_by(
        AuditSchedule.created_at.desc()
    ).all()


@router.post("", response_model=ScheduleOut)
def create_schedule(
    payload: ScheduleCreate,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_role("admin", "operator")),
):
    if payload.frequency not in scheduling_service.VALID_FREQUENCIES:
        raise HTTPException(400, f"frequency must be one of {scheduling_service.VALID_FREQUENCIES}")
    schedule = AuditSchedule(
        tenant_id=tenant_id,
        name=payload.name,
        scope=payload.scope,
        frequency=payload.frequency,
        enabled=payload.enabled,
        framework=payload.framework,
        created_by=user.username,
        next_run=scheduling_service.compute_next_run(payload.frequency) if payload.enabled else None,
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)
    return schedule


@router.get("/{schedule_id}", response_model=ScheduleOut)
def get_schedule(
    schedule_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)
):
    return _get_or_404(db, schedule_id, tenant_id)


@router.patch("/{schedule_id}", response_model=ScheduleOut)
def update_schedule(
    schedule_id: str,
    payload: ScheduleUpdate,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_role("admin", "operator")),
):
    schedule = _get_or_404(db, schedule_id, tenant_id)
    data = payload.model_dump(exclude_unset=True)
    if "frequency" in data and data["frequency"] not in scheduling_service.VALID_FREQUENCIES:
        raise HTTPException(400, f"frequency must be one of {scheduling_service.VALID_FREQUENCIES}")
    for field, value in data.items():
        setattr(schedule, field, value)
    # Re-derive next_run whenever frequency/enabled changes so a disabled
    # schedule can't silently keep a stale next_run that would fire the
    # instant it's re-enabled.
    if "frequency" in data or "enabled" in data:
        schedule.next_run = scheduling_service.compute_next_run(schedule.frequency) if schedule.enabled else None
    db.commit()
    db.refresh(schedule)
    return schedule


@router.delete("/{schedule_id}")
def delete_schedule(
    schedule_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_role("admin", "operator")),
):
    schedule = _get_or_404(db, schedule_id, tenant_id)
    db.delete(schedule)
    db.commit()
    return {"deleted": True, "id": schedule_id}


@router.post("/{schedule_id}/run")
async def run_schedule_now(
    schedule_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_role("admin", "operator")),
):
    """On-demand execution. Still routed through the same worker-facing
    execute_schedule() function -- this endpoint just triggers it
    synchronously for the (typically small, manual-scope) case of a user
    clicking "Run now"."""
    schedule = _get_or_404(db, schedule_id, tenant_id)
    return await scheduling_service.execute_schedule(db, schedule)