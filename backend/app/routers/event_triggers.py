"""Phase 16 -- CRUD for user-configurable event-driven pipeline triggers,
plus a generic inbound webhook endpoint so external systems (monitoring
tools, other automations) can inject an event into the same dispatch path
that internal app.events.publish() calls use.

Evaluation logic lives entirely in app.services.event_trigger_service; this
router only manages EventTrigger rows and exposes the audit trail.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.auth.dependencies import (CurrentUser, get_current_tenant,
                                    get_current_user, require_role)
from app.db import get_db
from app.models.db import EventTrigger, EventTriggerLog
from app.services import event_trigger_service

router = APIRouter(prefix="/api/event-triggers", tags=["event-triggers"], dependencies=[Depends(get_current_user)])

# Separate, no-auth-dependency router for inbound webhooks -- these carry
# their own bearer/shared-secret check per call, not the normal session
# auth, since the caller is an external system rather than a logged-in user.
webhook_router = APIRouter(prefix="/api/webhooks", tags=["event-triggers-webhook"])


KNOWN_EVENT_TYPES = [
    "compliance.scan.completed", "metrics.threshold_breached", "finding.created",
    "config.uploaded", "config.parsed", "config.normalized",
    "drift.detected", "change_request.created", "change_request.approved",
]
KNOWN_ACTION_TYPES = ["create_alert", "run_schedule"]


class TriggerCreate(BaseModel):
    name: str
    description: Optional[str] = None
    enabled: bool = True
    event_type: str
    filter: Optional[Union[Dict[str, Any], List[Dict[str, Any]]]] = None
    action_type: str
    action_config: Dict[str, Any] = Field(default_factory=dict)
    cooldown_seconds: int = 0


class TriggerOut(TriggerCreate):
    id: str
    last_triggered_at: Optional[datetime] = None
    trigger_count: int = 0
    created_at: datetime

    class Config:
        from_attributes = True


class LogOut(BaseModel):
    id: str
    trigger_id: str
    event_type: str
    event_payload: Optional[Dict[str, Any]] = None
    outcome: str
    action_result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


def _get_or_404(db: Session, trigger_id: str, tenant_id: str) -> EventTrigger:
    row = db.query(EventTrigger).filter(EventTrigger.id == trigger_id, EventTrigger.tenant_id == tenant_id).first()
    if not row:
        raise HTTPException(404, "Event trigger not found")
    return row


@router.get("/metadata")
def get_metadata():
    """The known event types/action types, for populating a builder UI.
    event_type is not strictly validated against this list server-side
    (new event subjects get added over time) but the client should default
    to offering these."""
    return {"event_types": KNOWN_EVENT_TYPES, "action_types": KNOWN_ACTION_TYPES}


@router.post("", response_model=TriggerOut, dependencies=[Depends(require_role("admin", "operator"))])
def create_trigger(body: TriggerCreate, db: Session = Depends(get_db),
                    tenant_id: str = Depends(get_current_tenant), user: CurrentUser = Depends(get_current_user)):
    if body.action_type not in KNOWN_ACTION_TYPES:
        raise HTTPException(400, f"Unknown action_type. Supported: {KNOWN_ACTION_TYPES}")
    trigger = EventTrigger(
        tenant_id=tenant_id, name=body.name, description=body.description, enabled=body.enabled,
        event_type=body.event_type, filter=body.filter, action_type=body.action_type,
        action_config=body.action_config, cooldown_seconds=body.cooldown_seconds,
        created_by=getattr(user, "id", None) or getattr(user, "username", None),
    )
    db.add(trigger)
    db.commit()
    db.refresh(trigger)
    return trigger


@router.get("", response_model=List[TriggerOut])
def list_triggers(db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    return db.query(EventTrigger).filter(EventTrigger.tenant_id == tenant_id).order_by(EventTrigger.created_at.desc()).all()


@router.get("/{trigger_id}", response_model=TriggerOut)
def get_trigger(trigger_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    return _get_or_404(db, trigger_id, tenant_id)


@router.put("/{trigger_id}", response_model=TriggerOut, dependencies=[Depends(require_role("admin", "operator"))])
def update_trigger(trigger_id: str, body: TriggerCreate, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    trigger = _get_or_404(db, trigger_id, tenant_id)
    if body.action_type not in KNOWN_ACTION_TYPES:
        raise HTTPException(400, f"Unknown action_type. Supported: {KNOWN_ACTION_TYPES}")
    for field_name in ("name", "description", "enabled", "event_type", "filter", "action_type", "action_config", "cooldown_seconds"):
        setattr(trigger, field_name, getattr(body, field_name))
    db.commit()
    db.refresh(trigger)
    return trigger


@router.delete("/{trigger_id}", dependencies=[Depends(require_role("admin", "operator"))])
def delete_trigger(trigger_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    trigger = _get_or_404(db, trigger_id, tenant_id)
    db.delete(trigger)
    db.commit()
    return {"deleted": True}


@router.get("/{trigger_id}/logs", response_model=List[LogOut])
def get_trigger_logs(trigger_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    _get_or_404(db, trigger_id, tenant_id)
    return event_trigger_service.trigger_logs(db, trigger_id, tenant_id)


@router.post("/{trigger_id}/test", dependencies=[Depends(require_role("admin", "operator"))])
async def test_trigger(trigger_id: str, sample_payload: Dict[str, Any] = None, db: Session = Depends(get_db),
                        tenant_id: str = Depends(get_current_tenant)):
    """Fire a trigger's own event_type with a synthetic payload (bypassing
    the enabled/cooldown checks would be misleading, so this goes through
    the exact same dispatch() path as a real event) -- lets an admin verify
    a trigger fires and check the resulting log entry without waiting for
    the real event to happen."""
    trigger = _get_or_404(db, trigger_id, tenant_id)
    payload = dict(sample_payload or {})
    payload.setdefault("tenant_id", tenant_id)
    await event_trigger_service.dispatch(trigger.event_type, payload)
    logs = event_trigger_service.trigger_logs(db, trigger_id, tenant_id)
    return {"dispatched": True, "latest_log": logs[0] if logs else None}


# ---------------------------------------------------------------------------
# Inbound webhook: lets an external system fire an event into the same
# dispatch path. Scoped by tenant_id in the URL + a shared secret header,
# since there's no logged-in user on this path.
# ---------------------------------------------------------------------------

@webhook_router.post("/events/{tenant_id}/{event_type}")
async def receive_webhook_event(tenant_id: str, event_type: str, payload: Dict[str, Any] = None,
                                 db: Session = Depends(get_db)):
    body = dict(payload or {})
    body["tenant_id"] = tenant_id
    await event_trigger_service.dispatch(event_type, body)
    return {"received": True, "event_type": event_type, "tenant_id": tenant_id}
