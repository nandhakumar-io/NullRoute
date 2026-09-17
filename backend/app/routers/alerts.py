"""Phase 13 -- GET /api/alerts, POST /api/alerts/{id}/acknowledge.

All authenticated tenant members can view alerts for their own tenant.
Acknowledging is a state-mutating action, though, so (per the Section 11
RBAC audit) it's gated to everyone except pure VIEWER -- read-only users
can see alerts but shouldn't be able to change their status.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.auth.dependencies import CurrentUser, get_current_tenant, get_current_user, require_role
from app.auth.rbac import ALL_ROLE_NAMES
from app.db import get_db
from app.models.alerting import AlertChannel, AlertRule, PushSubscription
from app.models.db import Alert
from app.services import alert_channel_service, alert_service, audit_service

# Every recognized role except the read-only VIEWER (canonical + legacy name).
_NON_VIEWER_ROLES = [r for r in ALL_ROLE_NAMES if r not in ("VIEWER", "viewer")]
MANAGE_ALERTING = require_role(*[r for r in ALL_ROLE_NAMES if r not in ("VIEWER", "viewer", "AUDITOR", "auditor")])

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


# ---------------------------------------------------------------------------
# Simulated alerts -- onboarding / channel-verification aid
# ---------------------------------------------------------------------------
#
# The Alerts feed is empty on a fresh install until real drift or a real
# critical finding occurs, which gives an operator no way to confirm their
# webhook / ntfy / email / browser-push wiring actually works until the
# first genuine incident -- exactly the wrong moment to discover it doesn't.
#
# This endpoint creates a REAL Alert row through the REAL
# alert_service.create_alert() path, so it exercises the same rule
# matching and channel dispatch a genuine alert would. It is not a UI-only
# stub; the returned `dispatch_results` is the actual per-channel outcome.
#
# INTEGRITY (important): a simulated alert must never be mistakable for a
# real security event in the feed, in a report, or in an exported evidence
# package. Every row created here is therefore marked three ways --
# `extra.simulated = True`, `extra.simulated_by`, and a "[SIMULATED]" title
# prefix -- and the action is written to the audit log with the acting
# user. Anything that counts or reports on alerts can filter on
# `extra.simulated`.

SIMULATABLE_CATEGORIES: Dict[str, Dict[str, str]] = {
    "CONFIGURATION_DRIFT": {
        "severity": "HIGH",
        "title": "Configuration drift detected on device",
        "detail": (
            "Running configuration no longer matches the approved golden baseline. "
            "3 line(s) added, 1 removed. Simulated event — no device was contacted."
        ),
    },
    "CRITICAL_FINDING": {
        "severity": "CRITICAL",
        "title": "Critical compliance finding raised by scan",
        "detail": (
            "A control mapped to CIS/NIST failed with CRITICAL severity. "
            "Simulated event — no scan was run."
        ),
    },
    "VULNERABILITY_BREACH": {
        "severity": "CRITICAL",
        "title": "Known-exploited vulnerability matched on device platform",
        "detail": (
            "Detected platform/version matches a CVE on the CISA KEV list. "
            "Simulated event — no vulnerability feed was queried."
        ),
    },
}


class SimulateRequest(BaseModel):
    category: str = Field(..., description="One of SIMULATABLE_CATEGORIES")
    severity: Optional[str] = Field(
        None, description="Override severity; defaults to the category's natural severity."
    )
    device_id: Optional[str] = Field(None, description="Optional device to attribute the alert to.")


@router.get("/simulate/categories")
def list_simulatable_categories():
    """Drives the Alerts empty-state button group, so the UI never hardcodes
    a category the backend doesn't actually know how to simulate."""
    return {
        "categories": [
            {"category": c, "severity": meta["severity"], "title": meta["title"]}
            for c, meta in SIMULATABLE_CATEGORIES.items()
        ]
    }


@router.post("/simulate")
async def simulate_alert(
    payload: SimulateRequest,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(MANAGE_ALERTING),
):
    meta = SIMULATABLE_CATEGORIES.get(payload.category)
    if not meta:
        raise HTTPException(
            400,
            f"Unsupported simulation category '{payload.category}'. "
            f"Supported: {', '.join(SIMULATABLE_CATEGORIES)}",
        )

    severity = payload.severity or meta["severity"]
    if severity not in alert_service.VALID_SEVERITIES:
        raise HTTPException(
            400, f"Invalid severity '{severity}'. Valid: {', '.join(alert_service.VALID_SEVERITIES)}"
        )

    alert = await alert_service.create_alert(
        db,
        tenant_id=tenant_id,
        category=payload.category,
        severity=severity,
        title=f"[SIMULATED] {meta['title']}",
        detail=meta["detail"],
        device_id=payload.device_id,
        extra={
            "simulated": True,
            "simulated_by": user.username,
            "simulated_at": datetime.utcnow().isoformat(),
        },
    )

    audit_service.record_from_user(
        db, user, action="alert.simulate", request=request, result="SUCCESS",
        object_type="alert", object_id=alert.id,
        new_value={"category": payload.category, "severity": severity, "simulated": True},
    )

    return {
        "alert": alert_service.to_dict(alert),
        # The real per-channel dispatch outcome -- this is what makes the
        # button a genuine wiring test rather than a cosmetic one.
        "dispatch_results": alert.dispatch_results or {},
    }


# ---------------------------------------------------------------------------
# Alert channels (email / ntfy / webhook / push) -- configurable per tenant
# ---------------------------------------------------------------------------

def _channel_or_404(db: Session, channel_id: str, tenant_id: str) -> AlertChannel:
    ch = db.query(AlertChannel).filter(AlertChannel.id == channel_id, AlertChannel.tenant_id == tenant_id).first()
    if not ch:
        raise HTTPException(404, "Alert channel not found")
    return ch


class ChannelCreate(BaseModel):
    name: str
    channel_type: str  # email | ntfy | webhook | push
    enabled: bool = True
    config: Dict[str, Any] = Field(default_factory=dict)
    secret: Optional[Dict[str, Any]] = None


class ChannelUpdate(BaseModel):
    name: Optional[str] = None
    enabled: Optional[bool] = None
    config: Optional[Dict[str, Any]] = None
    secret: Optional[Dict[str, Any]] = None


def _channel_out(c: AlertChannel) -> Dict[str, Any]:
    return {
        "id": c.id,
        "name": c.name,
        "channel_type": c.channel_type,
        "enabled": c.enabled,
        "config": c.config or {},
        "has_credentials": bool(c.credential_ref),
        "last_test_status": c.last_test_status,
        "last_test_at": c.last_test_at.isoformat() if c.last_test_at else None,
        "last_test_message": c.last_test_message,
        "created_by": c.created_by,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "updated_at": c.updated_at.isoformat() if c.updated_at else None,
    }


@router.get("/channels")
def list_channels(db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    rows = db.query(AlertChannel).filter(AlertChannel.tenant_id == tenant_id).order_by(AlertChannel.created_at.desc()).all()
    return {"count": len(rows), "channels": [_channel_out(c) for c in rows]}


@router.post("/channels")
def create_channel(
    payload: ChannelCreate,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(MANAGE_ALERTING),
):
    if payload.channel_type not in ("email", "ntfy", "webhook", "push"):
        raise HTTPException(400, "channel_type must be one of email, ntfy, webhook, push")

    credential_ref = None
    if payload.secret:
        try:
            credential_ref = alert_channel_service.store_channel_secret(tenant_id, payload.secret)
        except alert_channel_service.ChannelError as e:
            raise HTTPException(502, str(e))

    ch = AlertChannel(
        tenant_id=tenant_id, name=payload.name, channel_type=payload.channel_type,
        enabled=payload.enabled, config=payload.config, credential_ref=credential_ref,
        last_test_status="NEVER_TESTED", created_by=user.subject if user else "api",
    )
    db.add(ch)
    db.commit()
    db.refresh(ch)
    audit_service.record_from_user(
        db, request=request, user=user, action="CREATE_ALERT_CHANNEL",
        object_type="alert_channel", object_id=ch.id,
        new_value={"name": ch.name, "type": ch.channel_type}, result="SUCCESS",
    )
    return _channel_out(ch)


@router.patch("/channels/{channel_id}")
def update_channel(
    channel_id: str,
    payload: ChannelUpdate,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(MANAGE_ALERTING),
):
    ch = _channel_or_404(db, channel_id, tenant_id)
    data = payload.model_dump(exclude_unset=True, exclude={"secret"})
    for k, v in data.items():
        setattr(ch, k, v)

    if payload.secret is not None:
        try:
            if ch.credential_ref:
                alert_channel_service.rotate_channel_secret(tenant_id, ch.credential_ref, payload.secret)
            else:
                ch.credential_ref = alert_channel_service.store_channel_secret(tenant_id, payload.secret)
        except alert_channel_service.ChannelError as e:
            raise HTTPException(502, str(e))

    ch.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(ch)
    audit_service.record_from_user(
        db, request=request, user=user, action="UPDATE_ALERT_CHANNEL",
        object_type="alert_channel", object_id=ch.id, result="SUCCESS",
    )
    return _channel_out(ch)


@router.delete("/channels/{channel_id}", status_code=204)
def delete_channel(
    channel_id: str,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(MANAGE_ALERTING),
):
    ch = _channel_or_404(db, channel_id, tenant_id)
    if ch.credential_ref:
        alert_channel_service.delete_channel_secret(tenant_id, ch.credential_ref)
    db.delete(ch)
    db.commit()
    audit_service.record_from_user(
        db, request=request, user=user, action="DELETE_ALERT_CHANNEL",
        object_type="alert_channel", object_id=channel_id, result="SUCCESS",
    )
    return None


@router.post("/channels/{channel_id}/test")
async def test_channel(
    channel_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(MANAGE_ALERTING),
):
    ch = _channel_or_404(db, channel_id, tenant_id)
    try:
        message = await alert_channel_service.test_channel(db, ch)
        ch.last_test_status = "SUCCESS"
        ch.last_test_message = message
        success = True
    except alert_channel_service.ChannelError as e:
        ch.last_test_status = "FAILED"
        ch.last_test_message = str(e)[:2000]
        message = str(e)
        success = False
    ch.last_test_at = datetime.utcnow()
    db.commit()
    return {"success": success, "message": message}


# ---------------------------------------------------------------------------
# Alert rules (routing: category/severity match -> channel fan-out)
# ---------------------------------------------------------------------------

def _rule_or_404(db: Session, rule_id: str, tenant_id: str) -> AlertRule:
    rule = db.query(AlertRule).filter(AlertRule.id == rule_id, AlertRule.tenant_id == tenant_id).first()
    if not rule:
        raise HTTPException(404, "Alert rule not found")
    return rule


class RuleCreate(BaseModel):
    name: str
    enabled: bool = True
    match_categories: Optional[List[str]] = None
    match_severities: Optional[List[str]] = None
    channel_ids: List[str] = Field(default_factory=list)


class RuleUpdate(BaseModel):
    name: Optional[str] = None
    enabled: Optional[bool] = None
    match_categories: Optional[List[str]] = None
    match_severities: Optional[List[str]] = None
    channel_ids: Optional[List[str]] = None


def _rule_out(r: AlertRule) -> Dict[str, Any]:
    return {
        "id": r.id,
        "name": r.name,
        "enabled": r.enabled,
        "match_categories": r.match_categories or [],
        "match_severities": r.match_severities or [],
        "channel_ids": r.channel_ids or [],
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "updated_at": r.updated_at.isoformat() if r.updated_at else None,
    }


ALERT_CATEGORIES = [
    "CRITICAL_FINDING", "HIGH_RISK", "OPA_FAILURE", "BATFISH_VIOLATION",
    "AI_UNKNOWN_CONFIGURATION", "AI_LOW_CONFIDENCE", "DEVICE_COLLECTION_FAILURE",
    "CONFIGURATION_DRIFT", "FABRIC_ANCHOR_FAILURE", "EVIDENCE_INTEGRITY_FAILURE",
    # Raised by services/vulnerability_service when a device's detected
    # platform/version matches a known-exploited CVE. Registered here so
    # AlertRule routing can target it like any other category.
    "VULNERABILITY_BREACH",
]


@router.get("/categories")
def list_alert_categories():
    return {"categories": ALERT_CATEGORIES, "severities": list(alert_service.VALID_SEVERITIES)}


@router.get("/rules")
def list_rules(db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    rows = db.query(AlertRule).filter(AlertRule.tenant_id == tenant_id).order_by(AlertRule.created_at.desc()).all()
    return {"count": len(rows), "rules": [_rule_out(r) for r in rows]}


@router.post("/rules")
def create_rule(
    payload: RuleCreate,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(MANAGE_ALERTING),
):
    rule = AlertRule(
        tenant_id=tenant_id, name=payload.name, enabled=payload.enabled,
        match_categories=payload.match_categories or [], match_severities=payload.match_severities or [],
        channel_ids=payload.channel_ids, created_by=user.subject if user else "api",
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    audit_service.record_from_user(
        db, request=request, user=user, action="CREATE_ALERT_RULE",
        object_type="alert_rule", object_id=rule.id, new_value={"name": rule.name}, result="SUCCESS",
    )
    return _rule_out(rule)


@router.patch("/rules/{rule_id}")
def update_rule(
    rule_id: str,
    payload: RuleUpdate,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(MANAGE_ALERTING),
):
    rule = _rule_or_404(db, rule_id, tenant_id)
    for k, v in payload.model_dump(exclude_unset=True).items():
        setattr(rule, k, v)
    rule.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(rule)
    audit_service.record_from_user(
        db, request=request, user=user, action="UPDATE_ALERT_RULE",
        object_type="alert_rule", object_id=rule.id, result="SUCCESS",
    )
    return _rule_out(rule)


@router.delete("/rules/{rule_id}", status_code=204)
def delete_rule(
    rule_id: str,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(MANAGE_ALERTING),
):
    rule = _rule_or_404(db, rule_id, tenant_id)
    db.delete(rule)
    db.commit()
    audit_service.record_from_user(
        db, request=request, user=user, action="DELETE_ALERT_RULE",
        object_type="alert_rule", object_id=rule_id, result="SUCCESS",
    )
    return None


# ---------------------------------------------------------------------------
# Web Push subscriptions
# ---------------------------------------------------------------------------

class PushSubscribeRequest(BaseModel):
    endpoint: str
    keys: Dict[str, str]  # {"p256dh": ..., "auth": ...}
    user_agent: Optional[str] = None


@router.get("/push/vapid-public-key")
def get_vapid_public_key():
    key = alert_channel_service.get_vapid_public_key()
    if not key:
        raise HTTPException(503, "Web Push is not configured on this server")
    return {"public_key": key}


@router.post("/push/subscribe")
def subscribe_push(
    payload: PushSubscribeRequest,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(get_current_user),
):
    existing = db.query(PushSubscription).filter(PushSubscription.endpoint == payload.endpoint).first()
    if existing:
        existing.tenant_id = tenant_id
        existing.p256dh = payload.keys.get("p256dh", "")
        existing.auth = payload.keys.get("auth", "")
        existing.user_agent = payload.user_agent
        existing.last_error = None
        db.commit()
        return {"status": "updated", "id": existing.id}

    sub = PushSubscription(
        tenant_id=tenant_id,
        user_subject=user.subject if user else None,
        endpoint=payload.endpoint,
        p256dh=payload.keys.get("p256dh", ""),
        auth=payload.keys.get("auth", ""),
        user_agent=payload.user_agent,
    )
    db.add(sub)
    db.commit()
    db.refresh(sub)
    return {"status": "subscribed", "id": sub.id}


@router.post("/push/unsubscribe")
def unsubscribe_push(
    payload: Dict[str, str],
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    endpoint = payload.get("endpoint")
    if not endpoint:
        raise HTTPException(400, "endpoint is required")
    db.query(PushSubscription).filter(
        PushSubscription.endpoint == endpoint, PushSubscription.tenant_id == tenant_id
    ).delete()
    db.commit()
    return {"status": "unsubscribed"}


@router.get("/push/subscriptions")
def list_push_subscriptions(db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    rows = db.query(PushSubscription).filter(PushSubscription.tenant_id == tenant_id).all()
    return {
        "count": len(rows),
        "subscriptions": [
            {
                "id": s.id,
                "user_agent": s.user_agent,
                "created_at": s.created_at.isoformat() if s.created_at else None,
                "last_used_at": s.last_used_at.isoformat() if s.last_used_at else None,
                "last_error": s.last_error,
            }
            for s in rows
        ],
    }