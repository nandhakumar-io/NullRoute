"""Phase 15 -- background worker that periodically polls every enabled
device's health metrics (CPU, memory, per-interface counters) and persists
them as DeviceMetricSnapshot rows via app.services.metrics_service.

Mirrors app/workers/scheduler_worker.py's shape deliberately: its own
long-lived process (see the `metrics-poller` service in docker-compose.yml),
completely separate from the uvicorn API process and from the audit
scheduler, so a slow/unreachable device never blocks either of those. Polls
run through the SAME gateway job path (app.gateway.publisher.submit_job,
operation=GET_HEALTH_METRICS) as the on-demand Device Detail panel -- no
second SNMP/gNMI calling convention.

Threshold breaches detected on a fresh snapshot are published as a
best-effort NATS "metrics.threshold_breached" event (see app/events.py) so
the alerting pipeline / event-driven trigger config (Phase 16) can react --
e.g. auto-kick a scan or notify -- without this worker knowing anything
about who's downstream.

Run standalone with:  python -m app.workers.metrics_poller_worker
"""
from __future__ import annotations

import asyncio
import logging
import os
import signal
from typing import Optional

from sqlalchemy.orm import Session

from app import events
from app.db import SessionLocal, init_db
from app.gateway.publisher import submit_job
from app.models.db import Device
from app.services import metrics_service

logger = logging.getLogger("metrics_poller_worker")

POLL_INTERVAL_SECONDS = float(os.getenv("METRICS_POLL_INTERVAL_SECONDS", "300"))
WORKER_ENABLED = os.getenv("METRICS_POLLER_ENABLED", "true").lower() == "true"
# Only devices whose preferred/configured transport can serve
# GET_HEALTH_METRICS today are polled; others are skipped quietly (not an
# error) until additional transports implement get_health_metrics.
METRICS_CAPABLE_PROTOCOLS = {"snmp"}

_shutdown_event: Optional[asyncio.Event] = None


def _pollable_devices(db: Session) -> list[Device]:
    devices = db.query(Device).filter(Device.enabled.is_(True)).all()
    out = []
    for d in devices:
        protocol = (d.protocol or "").lower()
        if protocol and protocol not in METRICS_CAPABLE_PROTOCOLS:
            # Device explicitly configured for a transport that doesn't
            # (yet) support health metrics -- skip rather than force SNMP.
            continue
        out.append(d)
    return out


async def _poll_one(db: Session, device: Device) -> None:
    try:
        result = await submit_job(
            db,
            tenant_id=device.tenant_id,
            requester_id="metrics-poller",
            device_id=device.id,
            operation="GET_HEALTH_METRICS",
            protocol="snmp",
        )
        success = bool(result.get("success"))
        data = (result.get("data") or {}) if success else {}
        snapshot = metrics_service.record_snapshot(
            db, device, data, source="snmp",
            success=success, error=None if success else result.get("error"),
        )
        if success:
            findings = metrics_service.evaluate_thresholds(snapshot)
            if findings:
                logger.warning("Threshold breach(es) for device %s: %s", device.id, findings)
                try:
                    await events.publish("metrics.threshold_breached", {
                        "tenant_id": device.tenant_id,
                        "device_id": device.id,
                        "snapshot_id": snapshot.id,
                        "findings": findings,
                    })
                except Exception:  # noqa: BLE001 - publishing is best-effort
                    logger.debug("metrics.threshold_breached publish failed", exc_info=True)
    except Exception:  # noqa: BLE001 - one device must never sink the poll loop
        logger.exception("Metrics poll failed for device %s", device.id)
        db.rollback()


async def run_once() -> int:
    """Poll every eligible device once. Returns the count polled so tests
    and logging can observe progress without depending on wall clock."""
    db = SessionLocal()
    try:
        devices = _pollable_devices(db)
        for device in devices:
            await _poll_one(db, device)
        return len(devices)
    finally:
        db.close()


async def _loop() -> None:
    global _shutdown_event
    _shutdown_event = asyncio.Event()
    logger.info(
        "metrics_poller_worker started (poll interval=%ss, enabled=%s)",
        POLL_INTERVAL_SECONDS, WORKER_ENABLED,
    )
    if not WORKER_ENABLED:
        logger.warning("METRICS_POLLER_ENABLED=false -- worker is idle, exiting.")
        return

    while not _shutdown_event.is_set():
        try:
            polled = await run_once()
            if polled:
                logger.info("Poll tick collected metrics for %d device(s)", polled)
        except Exception:  # noqa: BLE001 - a bad DB tick must not crash the process
            logger.exception("metrics_poller_worker poll tick failed")

        try:
            await asyncio.wait_for(_shutdown_event.wait(), timeout=POLL_INTERVAL_SECONDS)
        except asyncio.TimeoutError:
            pass  # normal case: just means it's time for the next poll


def _install_signal_handlers(loop: asyncio.AbstractEventLoop) -> None:
    def _request_shutdown() -> None:
        logger.info("metrics_poller_worker received shutdown signal")
        if _shutdown_event is not None:
            _shutdown_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _request_shutdown)
        except NotImplementedError:
            pass


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    init_db()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    _install_signal_handlers(loop)
    try:
        loop.run_until_complete(_loop())
    finally:
        loop.close()


if __name__ == "__main__":
    main()