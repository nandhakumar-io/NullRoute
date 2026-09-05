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


async def _get_conn():
    global _nc
    if _nc is not None:
        return _nc
    try:
        import nats
        _nc = await nats.connect(NATS_URL, connect_timeout=2)
        return _nc
    except Exception as e:
        logger.warning("NATS unavailable (%s) — events will be logged only.", e)
        return None


async def publish(subject: str, payload: Dict[str, Any]) -> None:
    conn = await _get_conn()
    data = json.dumps(payload, default=str).encode("utf-8")
    if conn is None:
        logger.info("[event:offline] %s -> %s", subject, payload)
        return
    try:
        js = conn.jetstream()
        await js.publish(subject, data)
    except Exception as e:
        logger.warning("Failed to publish %s: %s", subject, e)
