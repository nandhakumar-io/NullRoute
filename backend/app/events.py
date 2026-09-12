"""
Thin NATS JetStream wrapper.

Subjects (per architecture):
  config.uploaded, config.parsed, config.normalized, ai.mapping.required,
  ai.mapping.completed, compliance.scan.started, compliance.scan.completed,
  finding.created, report.generated

If NATS is unreachable (offline/local dev, this sandbox) publishing is a
no-op logged locally so the synchronous pipeline (services/pipeline.py) still
completes the demo end-to-end; in the docker-compose deployment NATS is a
required service and other consumers (metrics, notifications, audit) react
to these events.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger("events")

NATS_URL = os.getenv("NATS_URL", "nats://nats:4222")

_nc = None
_nats_failed = False

# Guards against a mis-configured trigger action (e.g. one that itself
# publishes an event of the same type it fires on) causing publish() ->
# dispatch() -> publish() -> ... infinite recursion. Each nested publish()
# call increments this; once the ceiling is hit, dispatch is simply skipped
# for that call rather than raising, so the publish itself always succeeds.
MAX_TRIGGER_DISPATCH_DEPTH = 5
_dispatch_depth = 0

async def _get_conn():
    global _nc, _nats_failed
    if _nats_failed:
        return None
    if _nc is not None:
        return _nc
    try:
        import nats
        _nc = await nats.connect(NATS_URL, connect_timeout=2)
        return _nc
    except Exception as e:
        logger.warning("NATS unavailable (%s) — events will be logged only.", e)
        _nats_failed = True
        return None


async def publish(subject: str, payload: Dict[str, Any]) -> None:
    conn = await _get_conn()
    data = json.dumps(payload, default=str).encode("utf-8")
    if conn is None:
        logger.info("[event:offline] %s -> %s", subject, payload)
    else:
        try:
            await conn.publish(subject, data)
        except Exception as e:
            logger.warning("Failed to publish %s: %s", subject, e)

    global _dispatch_depth
    if _dispatch_depth > MAX_TRIGGER_DISPATCH_DEPTH:
        logger.warning("event_trigger dispatch depth exceeded for %s -- skipping to avoid recursion", subject)
        return
    _dispatch_depth += 1
    try:
        from app.services import event_trigger_service
        await event_trigger_service.dispatch(subject, payload)
    except Exception as e:
        logger.warning("event_trigger dispatch failed for %s: %s", subject, e)
    finally:
        _dispatch_depth -= 1
