"""Background worker that actually executes Network Scan jobs.

Mirrors app/workers/scheduler_worker.py exactly: its own long-lived
process (see the `network-scan-worker` service in docker-compose.yml),
separate from the `backend` uvicorn process, so device collection and
compliance evaluation for a whole CIDR can never block API request
handling for other tenants. Poll loop picks up PENDING
app.models.db.NetworkScanJob rows and hands them to
services/network_scan_service.execute_scan_job() -- the only place a job
actually runs, per the same rule.

Run standalone with:  python -m app.workers.network_scan_worker
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
from app.models.db import NetworkScanJob
from app.services.network_scan_service import execute_scan_job

logger = logging.getLogger("network_scan_worker")

POLL_INTERVAL_SECONDS = float(os.getenv("NETWORK_SCAN_POLL_INTERVAL_SECONDS", "5"))
WORKER_ENABLED = os.getenv("NETWORK_SCAN_WORKER_ENABLED", "true").lower() == "true"

_shutdown_event: Optional[asyncio.Event] = None


async def _run_one(db: Session, job: NetworkScanJob) -> None:
    try:
        await execute_scan_job(db, job)
        logger.info("Network scan job %s finished with status=%s", job.id, job.status)
        try:
            await events.publish("network_scan.completed", {
                "job_id": job.id, "tenant_id": job.tenant_id, "status": job.status,
            })
        except Exception:  # noqa: BLE001 - publishing is best-effort
            logger.debug("network_scan.completed publish failed", exc_info=True)
    except Exception:  # noqa: BLE001 - one job must never sink the worker loop
        logger.exception("Network scan job %s failed", job.id)
        db.rollback()
        job.status = "FAILED"
        job.error = "Unhandled worker error -- see backend logs"
        db.commit()


async def run_once() -> int:
    """Run a single poll tick: execute every currently-PENDING job.

    Returns the number of jobs picked up, so tests can assert progress
    without depending on wall-clock timing.
    """
    db = SessionLocal()
    try:
        pending = (
            db.query(NetworkScanJob)
            .filter(NetworkScanJob.status == "PENDING")
            .order_by(NetworkScanJob.created_at.asc())
            .all()
        )
        for job in pending:
            await _run_one(db, job)
        return len(pending)
    finally:
        db.close()


async def _loop() -> None:
    global _shutdown_event
    _shutdown_event = asyncio.Event()
    logger.info(
        "network_scan_worker started (poll interval=%ss, enabled=%s)",
        POLL_INTERVAL_SECONDS, WORKER_ENABLED,
    )
    if not WORKER_ENABLED:
        logger.warning("NETWORK_SCAN_WORKER_ENABLED=false -- worker is idle, exiting.")
        return

    while not _shutdown_event.is_set():
        try:
            picked_up = await run_once()
            if picked_up:
                logger.info("Poll tick executed %d network scan job(s)", picked_up)
        except Exception:  # noqa: BLE001 - a bad DB tick must not crash the process
            logger.exception("network_scan_worker poll tick failed")

        try:
            await asyncio.wait_for(_shutdown_event.wait(), timeout=POLL_INTERVAL_SECONDS)
        except asyncio.TimeoutError:
            pass  # normal case: just means it's time for the next poll


def _install_signal_handlers(loop: asyncio.AbstractEventLoop) -> None:
    def _request_shutdown() -> None:
        logger.info("network_scan_worker received shutdown signal")
        if _shutdown_event is not None:
            _shutdown_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _request_shutdown)
        except NotImplementedError:
            pass  # e.g. Windows


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
