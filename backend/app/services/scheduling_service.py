"""Phase 12 -- scheduled audits.

`execute_schedule()` is the only place a schedule actually runs a scan, and
it is called ONLY from the background worker
(app/workers/scheduler_worker.py) or from tests -- never from an inbound
FastAPI request, per the problem statement's rule against running long
device scans inside a request handler.

Execution reuses the exact same collection + run_pipeline path as the
manual `/api/devices/{id}/scan` endpoint (RULE 11: no second compliance
implementation). A device that fails collection does not abort the whole
schedule run; each device's outcome is recorded independently and the
schedule's `last_run_detail` summarizes successes/failures.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.models.db import AuditSchedule, Device, Scan

logger = logging.getLogger("scheduling_service")

VALID_FREQUENCIES = ("manual", "hourly", "daily", "weekly")

_FREQUENCY_DELTA = {
    "hourly": timedelta(hours=1),
    "daily": timedelta(days=1),
    "weekly": timedelta(weeks=1),
}


def validate_time_of_day(time_of_day: str) -> None:
    """Raises ValueError via HTTPException-friendly message if not 'HH:MM' 24h."""
    try:
        hour, minute = (int(p) for p in time_of_day.split(":", 1))
        assert 0 <= hour <= 23 and 0 <= minute <= 59
    except (ValueError, AssertionError):
        raise ValueError(f"Invalid time_of_day: {time_of_day!r}, expected 'HH:MM' (24h, UTC)")


def compute_next_run(
    frequency: str, from_time: Optional[datetime] = None, time_of_day: Optional[str] = None,
) -> Optional[datetime]:
    """Manual schedules have no automatic next_run -- they only execute when
    explicitly triggered via POST /api/schedules/{id}/run. Everything else
    is `from_time` (default: now) plus the frequency's fixed interval --
    unless `time_of_day` ("HH:MM", 24h, UTC) is given for daily/weekly, in
    which case the run is anchored to that clock time instead of drifting
    to whatever time of day the schedule happened to be created/last run
    at: the next occurrence of that HH:MM (today if it hasn't passed yet,
    otherwise the next day/week), so "daily at 02:00" actually means
    02:00 every day rather than "24h after whenever I clicked Create"."""
    if frequency not in VALID_FREQUENCIES:
        raise ValueError(f"Unknown frequency: {frequency!r}")
    if frequency == "manual":
        return None
    base = from_time or datetime.utcnow()
    if frequency == "hourly" or not time_of_day:
        return base + _FREQUENCY_DELTA[frequency]
    validate_time_of_day(time_of_day)
    hour, minute = (int(p) for p in time_of_day.split(":", 1))
    candidate = base.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if candidate <= base:
        candidate += _FREQUENCY_DELTA[frequency]
    return candidate


def to_dict(s: AuditSchedule) -> Dict[str, Any]:
    return {
        "id": s.id,
        "tenant_id": s.tenant_id,
        "name": s.name,
        "scope": s.scope,
        "frequency": s.frequency,
        "time_of_day": s.time_of_day,
        "enabled": s.enabled,
        "framework": s.framework,
        "created_by": s.created_by,
        "last_run": s.last_run,
        "next_run": s.next_run,
        "last_run_status": s.last_run_status,
        "last_run_detail": s.last_run_detail,
        "created_at": s.created_at,
        "updated_at": s.updated_at,
    }


def resolve_scope_device_ids(db: Session, schedule: AuditSchedule) -> List[str]:
    """Resolve `scope` against the CURRENT inventory at run time (not at
    creation time), so devices added later are automatically covered by an
    "all" scope."""
    scope = schedule.scope or {}
    if scope.get("all"):
        rows = db.query(Device.id).filter(Device.tenant_id == schedule.tenant_id).all()
        return [r[0] for r in rows]
    device_ids = scope.get("device_ids") or []
    # Still tenant-scoped even if the stored scope somehow contained a
    # foreign device id -- never trust scope blindly across tenants.
    rows = db.query(Device.id).filter(
        Device.tenant_id == schedule.tenant_id, Device.id.in_(device_ids)
    ).all()
    return [r[0] for r in rows]


def due_schedules(db: Session, now: Optional[datetime] = None) -> List[AuditSchedule]:
    now = now or datetime.utcnow()
    return (
        db.query(AuditSchedule)
        .filter(AuditSchedule.enabled.is_(True))
        .filter(AuditSchedule.next_run.isnot(None))
        .filter(AuditSchedule.next_run <= now)
        .all()
    )


async def execute_schedule(db: Session, schedule: AuditSchedule) -> Dict[str, Any]:
    """Run collection+scan for every device in scope. Uses the same
    collector registry / run_pipeline path as manual device scans."""
    # Imported lazily to avoid a routers<->services import cycle.
    from app.routers.devices import CollectRequest, _resolve_credentials
    from app.services.collectors.registry import get_collector
    from app.services.pipeline import run_pipeline

    import anyio

    device_ids = resolve_scope_device_ids(db, schedule)
    results: List[Dict[str, Any]] = []

    for device_id in device_ids:
        device = db.query(Device).filter(
            Device.id == device_id, Device.tenant_id == schedule.tenant_id
        ).first()
        if not device:
            results.append({"device_id": device_id, "success": False, "error": "device not found"})
            continue
        try:
            ref_row, credentials = _resolve_credentials(db, device, schedule.tenant_id, None)
            collector = get_collector(device.vendor, transport=None)
            device.collection_status = "IN_PROGRESS"
            db.commit()
            collection = await anyio.to_thread.run_sync(collector.collect_config, device, credentials)
            device.collection_status = "SUCCESS" if collection.success else "FAILED"
            device.last_collected_at = collection.collected_at
            device.last_collection_error = collection.error
            device.last_collection_transport = collection.transport
            db.commit()

            if not collection.success or not collection.raw_config:
                try:
                    from app.services import alert_service
                    await alert_service.alert_collection_failure(
                        db, schedule.tenant_id, device.id, collection.error or "no configuration returned",
                    )
                except Exception:  # noqa: BLE001 - alerting must never fail the schedule run
                    pass
                results.append({
                    "device_id": device_id, "success": False,
                    "error": collection.error or "no configuration returned",
                })
                continue

            scan = Scan(
                tenant_id=schedule.tenant_id, device_id=device.id,
                framework=schedule.framework, status="uploaded",
            )
            db.add(scan)
            db.commit()
            db.refresh(scan)
            await run_pipeline(db, scan, collection.raw_config, framework=schedule.framework)
            db.refresh(scan)
            results.append({"device_id": device_id, "success": True, "scan_id": scan.id,
                             "final_decision": scan.final_decision})
        except Exception as e:  # noqa: BLE001 - one device's failure must not sink the schedule
            logger.exception("Scheduled scan failed for device %s (schedule %s)", device_id, schedule.id)
            results.append({"device_id": device_id, "success": False, "error": str(e)})

    now = datetime.utcnow()
    failures = [r for r in results if not r["success"]]
    schedule.last_run = now
    schedule.last_run_status = "FAILED" if failures and len(failures) == len(results) and results else (
        "PARTIAL" if failures else "SUCCESS"
    )
    if not results:
        schedule.last_run_status = "SUCCESS"  # empty scope is not a failure
    schedule.last_run_detail = (
        f"{len(results) - len(failures)}/{len(results)} device(s) scanned successfully"
        if results else "No devices in scope"
    )
    schedule.next_run = compute_next_run(schedule.frequency, from_time=now, time_of_day=schedule.time_of_day)
    db.commit()

    return {"schedule_id": schedule.id, "status": schedule.last_run_status,
            "detail": schedule.last_run_detail, "results": results}