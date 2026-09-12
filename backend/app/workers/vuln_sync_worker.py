"""Background worker -- periodically syncs the vulnerability feeds
(NVD/CISA KEV/vendor PSIRTs) and then re-correlates every device against
the refreshed CVE catalog.

Same pattern as scheduler_worker.py: its own long-lived process (add a
`vuln_sync` service in docker-compose.yml alongside `scheduler` if/when
this repo wires worker containers -- none of the existing workers are
wired into docker-compose today either, see workers/scheduler_worker.py,
workers/training_worker.py, workers/network_scan_worker.py,
workers/evidence_verification_worker.py, so this one is left consistent
with that rather than introducing new infra on its own).

  - Poll loop: every VULN_SYNC_INTERVAL_HOURS (default 24h), open a fresh
    DB session, call vuln_sync_service.sync_all() then
    vuln_correlation_service.correlate_all_devices(db).
  - One tick's failure is caught and logged; it never stops the loop.
  - Graceful shutdown on SIGTERM/SIGINT.

Run standalone with:  python -m app.workers.vuln_sync_worker
"""
from __future__ import annotations

import asyncio
import logging
import os
import signal
from typing import Optional

from app.db import SessionLocal, init_db
from app.services import vuln_correlation_service, vuln_sync_service

logger = logging.getLogger("vuln_sync_worker")

POLL_INTERVAL_SECONDS = float(os.getenv("VULN_SYNC_INTERVAL_HOURS", "24")) * 3600.0
WORKER_ENABLED = os.getenv("VULN_SYNC_WORKER_ENABLED", "true").lower() == "true"

_shutdown_event: Optional[asyncio.Event] = None


async def run_once() -> dict:
    """Run a single sync + correlate tick. Returns a summary dict so tests
    and the loop's own logging can observe progress without depending on
    wall-clock timing.
    """
    db = SessionLocal()
    try:
        sync_result = await vuln_sync_service.sync_all(db)
        correlate_result = vuln_correlation_service.correlate_all_devices(db)
        return {"sync": sync_result, "correlate": correlate_result}
    except Exception:  # noqa: BLE001 - one bad tick must never sink the worker loop
        logger.exception("vuln_sync_worker tick failed")
        db.rollback()
        return {"status": "error"}
    finally:
        db.close()


async def _loop() -> None:
    global _shutdown_event
    _shutdown_event = asyncio.Event()
    logger.info(
        "vuln_sync_worker started (poll interval=%.0fs, enabled=%s)",
        POLL_INTERVAL_SECONDS, WORKER_ENABLED,
    )
    if not WORKER_ENABLED:
        logger.warning("VULN_SYNC_WORKER_ENABLED=false -- worker is idle, exiting.")
        return

    while not _shutdown_event.is_set():
        try:
            result = await run_once()
            logger.info("vuln_sync_worker tick complete: %s", result)
        except Exception:  # noqa: BLE001 - defensive, run_once already catches internally
            logger.exception("vuln_sync_worker poll tick failed")

        try:
            await asyncio.wait_for(_shutdown_event.wait(), timeout=POLL_INTERVAL_SECONDS)
        except asyncio.TimeoutError:
            pass  # normal case: just means it's time for the next poll


def _install_signal_handlers(loop: asyncio.AbstractEventLoop) -> None:
    def _request_shutdown() -> None:
        logger.info("vuln_sync_worker received shutdown signal")
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