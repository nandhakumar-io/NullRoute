"""
Training Worker (Loop 2 — Offline Model Fine-Tuning)

Polls the `training_jobs` table for QUEUED rows and executes
`training_service.run_training_job()` synchronously in a thread pool so
the fine-tuning work doesn't block the async event loop.

Designed for resilience:
- Catches all per-job exceptions so one failing job never kills the worker.
- Handles SIGTERM / SIGINT gracefully (current job finishes, then exits).
- Uses a configurable poll interval (TRAINING_WORKER_POLL_INTERVAL_SECONDS).
- Holds a `RUNNING` claim by setting job.status before training starts;
  if the worker dies mid-job, the job is marked FAILED after
  TRAINING_JOB_STALE_MINUTES and can be retried via the API
  (POST /api/ai/training/jobs/{id}/retry).
- Claims each job with an atomic QUEUED -> RUNNING UPDATE
  (training_service.claim_job), so the NATS wake-up callback, the poll loop
  and any second worker container can never run the same job twice.
"""
from __future__ import annotations

import asyncio
import logging
import os
import signal
import time
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger("training_worker")

POLL_INTERVAL = int(os.getenv("TRAINING_WORKER_POLL_INTERVAL_SECONDS", "30"))
MAX_CONCURRENT_JOBS = int(os.getenv("TRAINING_WORKER_MAX_CONCURRENT_JOBS", "1"))

_shutdown = False
_sigint_count = 0
_wakeup_event: asyncio.Event | None = None
# One poll at a time inside this process: the NATS callback and the timer loop
# both call _poll_once(); the DB-level claim is the real guard, this just
# avoids two of them contending for the same SQLAlchemy session/thread pool.
_poll_lock: asyncio.Lock | None = None


def _handle_signal(signum, _frame):
    global _shutdown, _sigint_count
    _sigint_count += 1
    if _sigint_count >= 2:
        # Second signal: force-exit immediately so the user is never blocked.
        logger.warning("Training worker force-killed (received signal %s twice)", signum)
        os._exit(1)
    logger.info(
        "Training worker received signal %s — shutting down cleanly after current job. "
        "Press Ctrl+C again to force-quit.",
        signum,
    )
    _shutdown = True
    # Wake up the sleep loop immediately so the process exits without waiting
    # for the full POLL_INTERVAL to elapse.
    if _wakeup_event is not None:
        try:
            _wakeup_event.set()
        except RuntimeError:
            pass  # event loop may already be closed


signal.signal(signal.SIGTERM, _handle_signal)
signal.signal(signal.SIGINT, _handle_signal)


async def _run_job_in_thread(db, job_id: str) -> None:
    """Run the synchronous training job in a thread pool so the async event
    loop remains responsive for heartbeat / health-check endpoints."""
    from app.services import training_service
    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="training") as pool:
        await loop.run_in_executor(pool, training_service.run_training_job, db, job_id)


async def _poll_once() -> None:
    """Claim and execute one batch of QUEUED training jobs."""
    global _poll_lock
    if _poll_lock is None:
        _poll_lock = asyncio.Lock()
    async with _poll_lock:
        await _poll_once_locked()


async def _poll_once_locked() -> None:
    from app.db import SessionLocal
    from app.models.db import TrainingJob
    from app.services import training_service

    db = SessionLocal()
    try:
        try:
            recovered = training_service.recover_stale_jobs(db)
            if recovered:
                logger.warning("Training worker: marked %d stale RUNNING job(s) FAILED", recovered)
        except Exception:  # noqa: BLE001
            logger.exception("Training worker: stale-job recovery failed")
            db.rollback()

        queued = (
            db.query(TrainingJob)
            .filter(TrainingJob.status == "QUEUED")
            .order_by(TrainingJob.created_at, TrainingJob.id)
            .limit(MAX_CONCURRENT_JOBS)
            .all()
        )
        if not queued:
            return

        for job in queued:
            if _shutdown:
                logger.info("Shutdown requested — skipping job %s", job.id)
                break
            logger.info("Training worker: attempting to claim job %s", job.id)
            try:
                # run_training_job() claims atomically and is a no-op if
                # another runner got there first.
                await _run_job_in_thread(db, job.id)
                db.refresh(job)
                logger.info(
                    "Training worker: job %s finished with status=%s metrics=%s",
                    job.id, job.status, job.metrics,
                )
            except Exception as exc:  # noqa: BLE001
                logger.exception("Training worker: job %s raised an unexpected error: %s", job.id, exc)
                db.rollback()
    finally:
        db.close()


async def main() -> None:
    global _wakeup_event
    _wakeup_event = asyncio.Event()
    logger.info(
        "Training worker started — poll_interval=%ds, max_concurrent=%d",
        POLL_INTERVAL, MAX_CONCURRENT_JOBS,
    )

    # Optional: subscribe to NATS training.job.queued to wake up immediately
    # without waiting for the next poll interval.
    # Uses the internal events._get_conn() since there is no public accessor.
    try:
        from app import events as _events

        async def _on_job_queued(msg) -> None:
            try:
                import json as _json
                data = _json.loads(msg.data.decode())
                logger.info(
                    "NATS: training.job.queued received for job %s", data.get("job_id")
                )
                await _poll_once()
            except Exception:  # noqa: BLE001
                pass

        _nc = await _events._get_conn()
        if _nc is not None:
            await _nc.subscribe("training.job.queued", cb=_on_job_queued)
            logger.info("Subscribed to NATS training.job.queued")
        else:
            logger.info("NATS unavailable — training worker running in poll-only mode")
    except Exception:  # noqa: BLE001
        logger.warning("Could not subscribe to NATS training.job.queued — polling only")


    while not _shutdown:
        try:
            await _poll_once()
        except Exception:  # noqa: BLE001
            logger.exception("Training worker: unexpected error in _poll_once, continuing")
        if not _shutdown:
            # Sleep but wake up immediately if a shutdown signal arrives.
            _wakeup_event.clear()
            try:
                await asyncio.wait_for(
                    asyncio.shield(asyncio.ensure_future(_wakeup_event.wait())),
                    timeout=POLL_INTERVAL,
                )
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass  # normal: either poll interval elapsed or task cancelled

    logger.info("Training worker exiting cleanly")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    asyncio.run(main())
