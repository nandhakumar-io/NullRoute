"""Phase 16 -- configurable event-driven pipeline triggers.

Lets a tenant declare "when <event_type> happens (optionally matching a
structured <filter>), do <action_type>" entirely through data (the
EventTrigger model), with no code changes required. `dispatch()` is called
from app.events.publish() itself so triggers fire the same way whether or
not a live NATS broker is present -- the same offline-safe pattern the rest
of this app uses for its pipeline.

Every dispatch is journaled to EventTriggerLog with an explicit `outcome`
(fired | skipped_filter | skipped_cooldown | failed) so "why did this fire
at 3am" is always answerable from the audit trail, never guessed at.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from sqlalchemy.orm import Session

from app.models.db import (AuditSchedule, Device, EventTrigger,
                            EventTriggerLog, NetworkScanJob, Scan)

logger = logging.getLogger("event_trigger_service")

_OPS = {
    "eq": lambda a, b: a == b,
    "ne": lambda a, b: a != b,
    "gt": lambda a, b: a is not None and a > b,
    "gte": lambda a, b: a is not None and a >= b,
    "lt": lambda a, b: a is not None and a < b,
    "lte": lambda a, b: a is not None and a <= b,
    "in": lambda a, b: a in (b or []),
    "not_in": lambda a, b: a not in (b or []),
    "contains": lambda a, b: b in a if a is not None else False,
}


def _get_dotted(payload: Dict[str, Any], field: str) -> Any:
    """Resolve a dotted path like 'findings.0.result' against a dict, with
    numeric segments indexing into lists. Missing path -> None."""
    current: Any = payload
    for part in field.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, (list, tuple)):
            try:
                current = current[int(part)]
            except (ValueError, IndexError, TypeError):
                return None
        else:
            return None
    return current


def _matches_clause(payload: Dict[str, Any], clause: Dict[str, Any]) -> bool:
    field = clause.get("field")
    op = clause.get("op", "eq")
    if not field or op not in _OPS:
        # A malformed clause must never silently block every trigger in the
        # system -- fail open (treat as "matches") rather than fail closed.
        return True
    actual = _get_dotted(payload, field)
    try:
        return bool(_OPS[op](actual, clause.get("value")))
    except Exception:
        return True


def matches_filter(payload: Dict[str, Any], filter_: Optional[Union[Dict[str, Any], List[Dict[str, Any]]]]) -> bool:
    """None matches everything. A single clause dict, or a list of clauses
    (AND-ed together), are the only supported shapes."""
    if filter_ is None:
        return True
    if isinstance(filter_, dict):
        return _matches_clause(payload, filter_)
    if isinstance(filter_, list):
        return all(_matches_clause(payload, c) for c in filter_)
    return True


def _resolve_tenant_id(db: Session, payload: Dict[str, Any]) -> Optional[str]:
    """Every event payload should carry enough to resolve a tenant, but
    callers vary (some pass tenant_id directly, others only a scan_id or
    device_id) -- resolve through whichever is present, in order of
    directness, rather than requiring every publish() call site to be
    rewritten."""
    tenant_id = payload.get("tenant_id")
    if tenant_id:
        return tenant_id

    scan_id = payload.get("scan_id")
    if scan_id:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            return scan.tenant_id

    device_id = payload.get("device_id")
    if device_id:
        device = db.query(Device).filter(Device.id == device_id).first()
        if device:
            return device.tenant_id

    return None


def trigger_logs(db: Session, trigger_id: str, tenant_id: str) -> List[EventTriggerLog]:
    return db.query(EventTriggerLog).filter(
        EventTriggerLog.trigger_id == trigger_id, EventTriggerLog.tenant_id == tenant_id
    ).order_by(EventTriggerLog.created_at.desc()).all()


def _log(db: Session, trigger: EventTrigger, event_type: str, payload: Dict[str, Any],
         outcome: str, action_result: Optional[Dict[str, Any]] = None, error: Optional[str] = None) -> EventTriggerLog:
    log = EventTriggerLog(
        trigger_id=trigger.id, tenant_id=trigger.tenant_id, event_type=event_type,
        event_payload=payload, outcome=outcome, action_result=action_result, error=error,
    )
    db.add(log)
    db.commit()
    return log


async def _run_action(db: Session, trigger: EventTrigger, payload: Dict[str, Any]) -> Dict[str, Any]:
    config = trigger.action_config or {}

    if trigger.action_type == "create_alert":
        from app.services import alert_service

        title_template = config.get("title_template") or trigger.name
        try:
            title = title_template.format(**payload)
        except Exception:
            title = title_template
        alert = await alert_service.create_alert(
            db, tenant_id=trigger.tenant_id,
            category=config.get("category", "event_trigger"),
            severity=config.get("severity", "MEDIUM"),
            title=title,
            detail=config.get("detail") or f"Fired by trigger '{trigger.name}' on event {trigger.event_type}",
            scan_id=payload.get("scan_id"), device_id=payload.get("device_id"),
            extra={"trigger_id": trigger.id, "event_payload": payload},
        )
        return {"alert_id": alert.id}

    if trigger.action_type == "run_scan":
        # Event-driven scanning: e.g. a device just committed a config
        # change (syslog/webhook) or drift was detected -- kick off a
        # PENDING NetworkScanJob rather than scanning inline (same
        # no-long-work-in-a-request/dispatch rule as everywhere else in
        # this app). The scheduler-independent network_scan_worker picks
        # it up on its normal poll loop.
        from app.services.network_scan_service import init_stages

        device_ids = list(config.get("device_ids") or [])
        # If the trigger didn't pin specific devices, scan whichever
        # device the firing event itself was about (e.g. the device that
        # just sent the config-commit syslog message).
        if not device_ids and payload.get("device_id"):
            device_ids = [payload["device_id"]]

        if not device_ids:
            raise ValueError("run_scan action requires action_config.device_ids or an event with device_id")

        known = {
            d.id for d in db.query(Device.id).filter(
                Device.tenant_id == trigger.tenant_id, Device.id.in_(device_ids)
            ).all()
        }
        device_ids = [d for d in device_ids if d in known]
        if not device_ids:
            raise ValueError("None of the target device_ids belong to this tenant")

        job = NetworkScanJob(
            tenant_id=trigger.tenant_id,
            name=config.get("name") or f"Event-driven scan ({trigger.name})",
            run_discovery=False,
            requested_device_ids=device_ids,
            framework=config.get("framework", "cis"),
            include_batfish=bool(config.get("include_batfish", False)),
            status="PENDING",
            stages=init_stages(),
            created_by=f"event_trigger:{trigger.id}",
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        return {"network_scan_job_id": job.id, "device_ids": device_ids}

    if trigger.action_type == "run_schedule":
        from app.services import scheduling_service

        schedule_id = config.get("schedule_id")
        schedule = db.query(AuditSchedule).filter(
            AuditSchedule.id == schedule_id, AuditSchedule.tenant_id == trigger.tenant_id
        ).first()
        if not schedule:
            raise ValueError(f"Schedule {schedule_id!r} not found")
        result = await scheduling_service.execute_schedule(db, schedule)
        return {"schedule_result": result}

    raise ValueError(f"Unknown action_type: {trigger.action_type!r}")


async def dispatch(event_type: str, payload: Dict[str, Any]) -> None:
    """Evaluate every enabled trigger for `event_type` against `payload` and
    fire the ones that match and are outside their cooldown window. Never
    raises -- a broken trigger config degrades to a failed log entry, not a
    crashed publisher."""
    from app.db import SessionLocal

    db = SessionLocal()
    tenant_id = _resolve_tenant_id(db, payload)
    if not tenant_id:
        logger.debug("event_trigger dispatch: no resolvable tenant for event %s, skipping", event_type)
        return

    triggers = db.query(EventTrigger).filter(
        EventTrigger.tenant_id == tenant_id,
        EventTrigger.event_type == event_type,
        EventTrigger.enabled.is_(True),
    ).all()

    for trigger in triggers:
        if not matches_filter(payload, trigger.filter):
            _log(db, trigger, event_type, payload, outcome="skipped_filter")
            continue

        if trigger.cooldown_seconds and trigger.last_triggered_at:
            elapsed = (datetime.utcnow() - trigger.last_triggered_at).total_seconds()
            if elapsed < trigger.cooldown_seconds:
                _log(db, trigger, event_type, payload, outcome="skipped_cooldown")
                continue

        try:
            action_result = await _run_action(db, trigger, payload)
        except Exception as e:
            logger.exception("event_trigger '%s' (%s) action failed", trigger.name, trigger.id)
            _log(db, trigger, event_type, payload, outcome="failed", error=str(e))
            continue

        trigger.trigger_count = (trigger.trigger_count or 0) + 1
        trigger.last_triggered_at = datetime.utcnow()
        db.commit()
        _log(db, trigger, event_type, payload, outcome="fired", action_result=action_result)
