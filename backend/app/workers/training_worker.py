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
  if the worker dies mid-job, the job stays RUNNING and can be manually
  retried via the API (POST /api/training/jobs/{id}/retry).
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


def _handle_signal(signum, _frame):
    global _shutdown
    logger.info("Training worker received signal %s — finishing current job then exiting", signum)
    _shutdown = True


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
    from app.db import SessionLocal
    from app.models.db import TrainingJob

    db = SessionLocal()
    try:
        queued = (
            db.query(TrainingJob)
            .filter(TrainingJob.status == "QUEUED")
            .order_by(TrainingJob.id)
            .limit(MAX_CONCURRENT_JOBS)
            .all()
        )
        if not queued:
            return

        for job in queued:
            if _shutdown:
                logger.info("Shutdown requested — skipping job %s", job.id)
                break
            logger.info("Training worker: claiming job %s", job.id)
            try:
                await _run_job_in_thread(db, job.id)
                db.refresh(job)
                logger.info(
                    "Training worker: job %s finished with status=%s metrics=%s",
                    job.id, job.status, job.metrics,
                )
            except Exception as exc:  # noqa: BLE001
                logger.exception("Training worker: job %s raised an unexpected error: %s", job.id, exc)
    finally:
        db.close()


async def main() -> None:
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
            await asyncio.sleep(POLL_INTERVAL)

    logger.info("Training worker exiting cleanly")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    asyncio.run(main())
