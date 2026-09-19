"""Event-driven scanning trigger: turn an inbound syslog line from a network
device into a normalized `device.*` event on the same dispatch path as every
other event in the app (app.events.publish -> event_trigger_service.dispatch).

This intentionally does NOT run a scan itself -- it only resolves which
Device the message is about and classifies what kind of thing happened, then
publishes an event. Whether that turns into a scan is entirely a matter of
whichever EventTrigger rows a tenant has configured with action_type
"run_scan" (or "create_alert", or nothing at all) -- config-as-data, not
hard-coded pipeline behavior, matching the rest of Phase 16.

Supported today: config-change/config-commit patterns from the vendors this
project already ships sample configs for (Cisco IOS/IOS-XE, Juniper Junos,
Arista EOS, FortiOS, PAN-OS). Anything that doesn't match a known pattern is
still published as a generic `device.syslog_received` event (with
`classified=False`) so a tenant can still build their own filter/trigger
against raw message content -- unmatched traffic is never silently dropped.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.models.db import Device

logger = logging.getLogger("syslog_ingest_service")

# A standard RFC3164-ish syslog line looks like:
#   <PRI>Mon DD HH:MM:SS HOSTNAME %FACILITY-SEVERITY-MNEMONIC: message text
# Real device output varies a lot (RFC5424, vendor timestamp formats, no
# PRI, etc.) -- rather than trying to be a general syslog parser, this pulls
# out just the two things every trigger needs: a device identifier to
# resolve, and the free-text message body to classify/match against.
_PRI_RE = re.compile(r"^<\d+>")
_HOSTNAME_RE = re.compile(
    r"^(?:<\d+>)?(?:\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+)?(?P<host>[\w.-]+)\s+(?P<rest>.*)$"
)

# (event_type, compiled pattern) -- checked in order, first match wins.
# Patterns are deliberately loose substrings/regexes of real vendor mnemonics
# rather than full grammar parsers, since the only thing a trigger needs is
# "was this a config change" style classification.
_CONFIG_CHANGE_PATTERNS: List[tuple[str, re.Pattern]] = [
    # Cisco IOS/IOS-XE: %SYS-5-CONFIG_I: Configured from console by admin
    ("config_changed", re.compile(r"%SYS-\d-CONFIG_I", re.IGNORECASE)),
    # Cisco: %PARSER-5-CFGLOG_LOGGEDCMD (per-command config logging)
    ("config_changed", re.compile(r"%PARSER-\d-CFGLOGGEDCMD", re.IGNORECASE)),
    # Juniper Junos: commit complete / "UI_COMMIT: User 'admin' ... commit"
    ("config_changed", re.compile(r"UI_COMMIT|commit complete", re.IGNORECASE)),
    # Arista EOS: %SYS-5-CONFIG_I / ConfigAgent commit
    ("config_changed", re.compile(r"ConfigAgent.*[Cc]ommit", re.IGNORECASE)),
    # FortiOS: log type "event" subtype "system" with "config-change" action
    ("config_changed", re.compile(r"config[-_]change", re.IGNORECASE)),
    # PAN-OS: commit-succeeded / config-changed job messages
    ("config_changed", re.compile(r"commit-succeeded|CONFIG_CHANGED", re.IGNORECASE)),
    # Generic reboot/reload -- not a config change, but still worth a
    # distinct, filterable event type since a reload can reset drift state.
    ("device_reloaded", re.compile(r"%SYS-\d-RELOAD|System restarted", re.IGNORECASE)),
]


@dataclass
class ParsedSyslog:
    raw: str
    host_token: Optional[str]
    message: str
    event_type: str
    classified: bool


def parse_syslog_line(line: str) -> ParsedSyslog:
    line = line.strip()
    m = _HOSTNAME_RE.match(line)
    host_token = m.group("host") if m else None
    message = m.group("rest") if m else _PRI_RE.sub("", line)

    for event_type, pattern in _CONFIG_CHANGE_PATTERNS:
        if pattern.search(line):
            return ParsedSyslog(raw=line, host_token=host_token, message=message,
                                 event_type=f"device.{event_type}", classified=True)

    return ParsedSyslog(raw=line, host_token=host_token, message=message,
                         event_type="device.syslog_received", classified=False)


def resolve_device(db: Session, tenant_id: str, host_token: Optional[str],
                    source_ip: Optional[str] = None) -> Optional[Device]:
    """Match the syslog sender to a known Device by hostname or management
    IP. Best-effort: a syslog message from an unknown/unmanaged sender still
    gets published (see below) but with device_id=None, so tenant-scoped
    dispatch still works off tenant_id alone and nothing throws."""
    q = db.query(Device).filter(Device.tenant_id == tenant_id)
    if host_token:
        device = q.filter(
            (Device.hostname == host_token) | (Device.name == host_token)
        ).first()
        if device:
            return device
    if source_ip:
        device = q.filter(Device.management_address == source_ip).first()
        if device:
            return device
    return None


async def ingest_syslog_message(db: Session, tenant_id: str, raw_message: str,
                                 source_ip: Optional[str] = None) -> Dict[str, Any]:
    """Parse one syslog line, resolve it to a Device if possible, and publish
    the resulting event through the normal app.events.publish() path so it
    reaches every EventTrigger the tenant has configured for that event_type
    -- most usefully one with action_type="run_scan" for real event-driven
    (as opposed to only time-scheduled) scanning."""
    from app import events  # local import: avoid a hard import cycle at module load

    parsed = parse_syslog_line(raw_message)
    device = resolve_device(db, tenant_id, parsed.host_token, source_ip)

    payload: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "message": parsed.message,
        "raw": parsed.raw,
        "source_ip": source_ip,
        "host_token": parsed.host_token,
        "classified": parsed.classified,
    }
    if device:
        payload["device_id"] = device.id
        payload["hostname"] = device.hostname

    await events.publish(parsed.event_type, payload)

    return {
        "event_type": parsed.event_type,
        "classified": parsed.classified,
        "device_id": device.id if device else None,
        "device_matched": device is not None,
    }
