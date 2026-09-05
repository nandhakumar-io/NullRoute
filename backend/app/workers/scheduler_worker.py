"""Phase 12 -- background worker that actually executes scheduled audits.

Per the problem statement ("Do not run long device scans directly inside
FastAPI request handlers") and the docstrings already in
services/scheduling_service.py and models/db.AuditSchedule, this module is
the ONLY place `execute_schedule()` is invoked outside of the explicit
"run now" endpoint (POST /api/schedules/{id}/run) and tests. It runs as its
own long-lived process (see the `scheduler` service in docker-compose.yml),
completely separate from the `backend` uvicorn process, so a slow/hung
device collection can never block API request handling.

Design:
  - Poll loop: every SCHEDULER_POLL_INTERVAL_SECONDS, open a fresh DB
    session, ask scheduling_service.due_schedules() for anything whose
    next_run has passed and is enabled, and execute each one in turn via
    the SAME scheduling_service.execute_schedule() used by the manual
    "run now" endpoint (RULE 11 -- no second compliance implementation).
  - One schedule's failure is caught and logged; it never stops the loop
    or blocks other due schedules from running in the same tick.
  - A NATS "schedule.executed" event is published (best effort) after each
    run so other consumers (metrics/notifications) can react, matching the
    "Use NATS/background workers for execution" instruction. Publishing
    failure never fails the run itself.
  - Graceful shutdown on SIGTERM/SIGINT (docker-compose `stop`).

Run standalone with:  python -m app.workers.scheduler_worker
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
from app.models.db import AuditSchedule
from app.services import scheduling_service

logger = logging.getLogger("scheduler_worker")

POLL_INTERVAL_SECONDS = float(os.getenv("SCHEDULER_POLL_INTERVAL_SECONDS", "30"))
WORKER_ENABLED = os.getenv("SCHEDULER_WORKER_ENABLED", "true").lower() == "true"

_shutdown_event: Optional[asyncio.Event] = None


async def _run_one(db: Session, schedule: AuditSchedule) -> None:
    try:
        result = await scheduling_service.execute_schedule(db, schedule)
        logger.info(
            "Executed schedule %s (%s): status=%s detail=%s",
            schedule.id, schedule.name, result.get("status"), result.get("detail"),
        )
        try:
            await events.publish("schedule.executed", {
                "schedule_id": schedule.id,
                "tenant_id": schedule.tenant_id,
                "status": result.get("status"),
                "detail": result.get("detail"),
            })
        except Exception:  # noqa: BLE001 - publishing is best-effort
            logger.debug("schedule.executed publish failed", exc_info=True)
    except Exception:  # noqa: BLE001 - one schedule must never sink the worker loop
        logger.exception("Schedule %s (%s) failed to execute", schedule.id, schedule.name)
        db.rollback()


async def run_once() -> int:
    """Run a single poll tick: execute every currently-due schedule.

    Returns the number of schedules that were picked up, so tests and the
    loop's own logging can assert/observe progress without depending on
    wall-clock timing.
    """
    db = SessionLocal()
    try:
        due = scheduling_service.due_schedules(db)
        for schedule in due:
            await _run_one(db, schedule)
        return len(due)
    finally:
        db.close()


async def _loop() -> None:
    global _shutdown_event
    _shutdown_event = asyncio.Event()
    logger.info(
        "scheduler_worker started (poll interval=%ss, enabled=%s)",
        POLL_INTERVAL_SECONDS, WORKER_ENABLED,
    )
    if not WORKER_ENABLED:
        logger.warning("SCHEDULER_WORKER_ENABLED=false -- worker is idle, exiting.")
        return

    while not _shutdown_event.is_set():
        try:
            picked_up = await run_once()
            if picked_up:
                logger.info("Poll tick executed %d due schedule(s)", picked_up)
        except Exception:  # noqa: BLE001 - a bad DB tick must not crash the process
            logger.exception("scheduler_worker poll tick failed")

        try:
            await asyncio.wait_for(_shutdown_event.wait(), timeout=POLL_INTERVAL_SECONDS)
        except asyncio.TimeoutError:
            pass  # normal case: just means it's time for the next poll


def _install_signal_handlers(loop: asyncio.AbstractEventLoop) -> None:
    def _request_shutdown() -> None:
        logger.info("scheduler_worker received shutdown signal")
        if _shutdown_event is not None:
            _shutdown_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _request_shutdown)
        except NotImplementedError:
            # add_signal_handler isn't available on some platforms (e.g. Windows)
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
