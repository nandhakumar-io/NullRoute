"""Per-tenant configurable alert routing: channels + rules + web push.

This sits alongside (not instead of) the legacy env-var dispatch in
alert_service.py. `route_and_dispatch()` is called from
alert_service.create_alert() right after the legacy dispatch, so both the
deployment-wide fallback destinations and any operator-configured
per-tenant channels receive the alert. Every function here is
best-effort: a channel failing to accept a notification never raises out
of this module.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.models.alerting import AlertChannel, AlertRule, PushSubscription
from app.services import openbao_service

logger = logging.getLogger("alert_channel_service")


class ChannelError(RuntimeError):
    """Raised on any channel connectivity/config failure. Callers record
    this on the channel/test result rather than letting it propagate."""


# ---------------------------------------------------------------------------
# Credential helpers (mirrors backup_destination_service.py)
# ---------------------------------------------------------------------------

def store_channel_secret(tenant_id: str, secret: Dict[str, Any]) -> str:
    ref = openbao_service.generate_credential_ref()
    try:
        openbao_service.store_device_credentials(tenant_id, ref, "alert_channel", secret)
    except openbao_service.OpenBaoError as e:
        raise ChannelError(f"Failed to store channel credentials: {e}") from e
    return ref


def rotate_channel_secret(tenant_id: str, credential_ref: str, secret: Dict[str, Any]) -> None:
    try:
        openbao_service.rotate_device_credentials(tenant_id, credential_ref, "alert_channel", secret)
    except openbao_service.OpenBaoError as e:
        raise ChannelError(f"Failed to rotate channel credentials: {e}") from e


def delete_channel_secret(tenant_id: str, credential_ref: str) -> None:
    try:
        openbao_service.delete_device_credentials(tenant_id, credential_ref)
    except openbao_service.OpenBaoError:
        logger.warning("Could not delete OpenBao secret for alert channel ref %s", credential_ref)


def _get_secret(tenant_id: str, credential_ref: Optional[str]) -> Dict[str, Any]:
    if not credential_ref:
        return {}
    try:
        return openbao_service.get_device_credentials(tenant_id, credential_ref).secret
    except openbao_service.OpenBaoError as e:
        raise ChannelError(f"Failed to read channel credentials: {e}") from e


# ---------------------------------------------------------------------------
# Per-channel-type senders
# ---------------------------------------------------------------------------

async def _send_email(config: Dict[str, Any], secret: Dict[str, Any], subject: str, body: str) -> str:
    import smtplib
    from email.mime.text import MIMEText

    host = config.get("smtp_host")
    if not host:
        raise ChannelError("Email channel is missing 'smtp_host'")
    port = int(config.get("smtp_port") or 587)
    to_addresses = config.get("to_addresses") or []
    if not to_addresses:
        raise ChannelError("Email channel is missing 'to_addresses'")
    from_address = config.get("from_address") or "alerts@netsec-auditor.local"

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = from_address
    msg["To"] = ", ".join(to_addresses)

    try:
        with smtplib.SMTP(host, port, timeout=8) as smtp:
            if config.get("use_tls", True):
                try:
                    smtp.starttls()
                except smtplib.SMTPException:
                    pass  # server may not support/require STARTTLS (e.g. local relay)
            username = secret.get("username") or from_address
            password = secret.get("password")
            if password:
                smtp.login(username, password)
            smtp.send_message(msg)
    except Exception as e:  # noqa: BLE001
        raise ChannelError(f"SMTP send failed: {e}") from e
    return f"Sent to {len(to_addresses)} recipient(s)"


async def _send_ntfy(config: Dict[str, Any], secret: Dict[str, Any], title: str, body: str, priority: str) -> str:
    import httpx

    server = (config.get("server_url") or "https://ntfy.sh").rstrip("/")
    topic = config.get("topic")
    if not topic:
        raise ChannelError("ntfy channel is missing 'topic'")
    url = f"{server}/{topic}"

    priority_map = {"CRITICAL": "urgent", "HIGH": "high", "MEDIUM": "default", "LOW": "low"}
    headers = {
        "Title": title[:200],
        "Priority": priority_map.get(priority.upper(), config.get("priority") or "default"),
    }
    tags = config.get("tags")
    if tags:
        headers["Tags"] = ",".join(tags)
    token = secret.get("access_token")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(url, content=body.encode("utf-8"), headers=headers)
        if resp.status_code >= 400:
            raise ChannelError(f"ntfy returned HTTP {resp.status_code}")
    except ChannelError:
        raise
    except Exception as e:  # noqa: BLE001
        raise ChannelError(f"ntfy POST failed: {e}") from e
    return f"Published to {url}"


async def _send_webhook(config: Dict[str, Any], secret: Dict[str, Any], payload: Dict[str, Any]) -> str:
    import httpx

    url = config.get("url")
    if not url:
        raise ChannelError("Webhook channel is missing 'url'")
    headers = dict(config.get("headers") or {})
    secret_header = secret.get("header_value")
    secret_header_name = config.get("secret_header_name")
    if secret_header and secret_header_name:
        headers[secret_header_name] = secret_header

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(url, json=payload, headers=headers)
        if resp.status_code >= 400:
            raise ChannelError(f"Webhook returned HTTP {resp.status_code}")
    except ChannelError:
        raise
    except Exception as e:  # noqa: BLE001
        raise ChannelError(f"Webhook POST failed: {e}") from e
    return f"Delivered (HTTP {resp.status_code})"


def _vapid_config():
    import os

    private_key = os.getenv("VAPID_PRIVATE_KEY")
    public_key = os.getenv("VAPID_PUBLIC_KEY")
    claim_email = os.getenv("VAPID_CLAIM_EMAIL", "admin@netsec-auditor.local")
    if not private_key or not public_key:
        raise ChannelError(
            "Web Push is not configured on this server (VAPID_PRIVATE_KEY / VAPID_PUBLIC_KEY unset)"
        )
    return private_key, public_key, claim_email


def get_vapid_public_key() -> Optional[str]:
    import os

    return os.getenv("VAPID_PUBLIC_KEY")


async def _send_push_to_subscription(sub: PushSubscription, title: str, body: str, url: Optional[str] = None) -> None:
    try:
        from pywebpush import WebPushException, webpush
    except ImportError as e:
        raise ChannelError("pywebpush is not installed") from e

    private_key, _public_key, claim_email = _vapid_config()
    payload = json.dumps({"title": title, "body": body, "url": url or "/alerts"})

    try:
        webpush(
            subscription_info={
                "endpoint": sub.endpoint,
                "keys": {"p256dh": sub.p256dh, "auth": sub.auth},
            },
            data=payload,
            vapid_private_key=private_key,
            vapid_claims={"sub": f"mailto:{claim_email}"},
        )
    except WebPushException as e:  # noqa: BLE001
        raise ChannelError(f"Web Push delivery failed: {e}") from e


async def _send_push(db: Session, tenant_id: str, title: str, body: str) -> str:
    subs = db.query(PushSubscription).filter(PushSubscription.tenant_id == tenant_id).all()
    if not subs:
        raise ChannelError("No browsers/devices are subscribed to push notifications yet")

    delivered, failed = 0, 0
    for sub in subs:
        try:
            await _send_push_to_subscription(sub, title, body)
            sub.last_used_at = datetime.utcnow()
            sub.last_error = None
            delivered += 1
        except ChannelError as e:
            sub.last_error = str(e)[:500]
            failed += 1
            # A permanently gone subscription (browser unsubscribed, uninstalled,
            # etc.) returns 404/410 from the push service -- pywebpush surfaces
            # this in the exception text; clean those rows up rather than
            # retrying them forever.
            if "410" in str(e) or "404" in str(e):
                db.delete(sub)
    db.commit()

    if delivered == 0:
        raise ChannelError(f"Push delivery failed for all {failed} subscription(s)")
    return f"Delivered to {delivered}/{len(subs)} subscribed device(s)"


# ---------------------------------------------------------------------------
# Public API: test + route/dispatch
# ---------------------------------------------------------------------------

async def test_channel(db: Session, channel: AlertChannel) -> str:
    secret = _get_secret(channel.tenant_id, channel.credential_ref)
    config = channel.config or {}

    if channel.channel_type == "email":
        return await _send_email(
            config, secret,
            subject="[NetSecAuditor] Test alert channel",
            body="This is a test notification confirming your alert email channel is configured correctly.",
        )
    if channel.channel_type == "ntfy":
        return await _send_ntfy(
            config, secret, title="NetSecAuditor test alert",
            body="This is a test notification confirming your ntfy channel is configured correctly.",
            priority="LOW",
        )
    if channel.channel_type == "webhook":
        return await _send_webhook(config, secret, payload={"test": True, "message": "NetSecAuditor test alert"})
    if channel.channel_type == "push":
        return await _send_push(db, channel.tenant_id, "NetSecAuditor test alert",
                                 "This is a test push notification.")
    raise ChannelError(f"Unsupported channel_type '{channel.channel_type}'")


def _rule_matches(rule: AlertRule, category: str, severity: str) -> bool:
    if not rule.enabled:
        return False
    cats = rule.match_categories or []
    sevs = rule.match_severities or []
    if cats and category not in cats:
        return False
    if sevs and severity not in sevs:
        return False
    return True


async def route_and_dispatch(db: Session, alert) -> Dict[str, Any]:
    """Evaluate every enabled AlertRule for this tenant and dispatch to
    every matched, enabled AlertChannel. Returns a per-channel result map
    merged into Alert.dispatch_results alongside the legacy env-dispatch
    results. Never raises.
    """
    results: Dict[str, Any] = {}
    try:
        rules = (
            db.query(AlertRule)
            .filter(AlertRule.tenant_id == alert.tenant_id, AlertRule.enabled == True)  # noqa: E712
            .all()
        )
    except Exception:  # noqa: BLE001 - table may not exist yet on an un-migrated DB
        return results

    matched_channel_ids = set()
    for rule in rules:
        if _rule_matches(rule, alert.category, alert.severity):
            matched_channel_ids.update(rule.channel_ids or [])

    if not matched_channel_ids:
        return results

    channels = (
        db.query(AlertChannel)
        .filter(AlertChannel.id.in_(matched_channel_ids), AlertChannel.enabled == True)  # noqa: E712
        .all()
    )

    title = f"[{alert.severity}] {alert.title}"
    body = alert.detail or alert.title

    for channel in channels:
        key = f"channel:{channel.name}"
        try:
            if channel.channel_type == "email":
                secret = _get_secret(channel.tenant_id, channel.credential_ref)
                msg = await _send_email(channel.config or {}, secret, title, body)
            elif channel.channel_type == "ntfy":
                secret = _get_secret(channel.tenant_id, channel.credential_ref)
                msg = await _send_ntfy(channel.config or {}, secret, title, body, alert.severity)
            elif channel.channel_type == "webhook":
                secret = _get_secret(channel.tenant_id, channel.credential_ref)
                msg = await _send_webhook(channel.config or {}, secret, payload={
                    "id": alert.id, "category": alert.category, "severity": alert.severity,
                    "title": alert.title, "detail": alert.detail, "scan_id": alert.scan_id,
                    "device_id": alert.device_id,
                })
            elif channel.channel_type == "push":
                msg = await _send_push(db, channel.tenant_id, title, body)
            else:
                msg = f"failed: unsupported channel_type '{channel.channel_type}'"
                results[key] = msg
                continue
            results[key] = f"ok: {msg}"
        except ChannelError as e:
            results[key] = f"failed: {e}"
            logger.warning("Alert channel %s (%s) dispatch failed: %s", channel.name, channel.channel_type, e)
        except Exception as e:  # noqa: BLE001
            results[key] = f"failed: {e}"
            logger.exception("Alert channel %s (%s) dispatch raised unexpectedly", channel.name, channel.channel_type)

    return results