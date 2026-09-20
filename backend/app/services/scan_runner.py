"""Background execution and lifecycle control for scan pipelines.

Why this module exists
----------------------
Scan pipelines run as in-process asyncio tasks (services/pipeline.py). Three
problems came from managing those tasks ad hoc inside routers/scans.py:

1. A stop was only ever a *request* (control_state=STOP_REQUESTED). Something
   still had to move it to STOPPED, and that something was the live task. If
   there was no live task -- the API process had reloaded (``uvicorn
   --reload``), the task had already ended, or the scan was queued -- nothing
   ever finalized it: the scan sat in "Stopping..." forever, kept reappearing
   in the running-pipelines list (so the count went down and then back up),
   and clicking Stop again returned 409.

   ``stop_scans`` fixes that by treating the DB as the source of truth: after
   cancelling any live task it *always* finalizes the scan to STOPPED itself,
   so "force stop" is immediate and idempotent whether or not a task existed.

2. Bulk uploads spawned one unbounded task per file. A 50-file upload fired
   50 concurrent pipelines at one Ollama GPU / Batfish / DB pool.
   ``start_scan_task`` runs every pipeline behind a semaphore
   (SCAN_PIPELINE_CONCURRENCY, default 3); queued scans wait cheaply and are
   just as stoppable/deletable as running ones (cancelling a task that is
   still waiting on the semaphore is instant).

3. Anything the process lost (crash, hot reload, deploy) left scans "running"
   forever. ``reconcile_stale`` (startup + lazily from the running list)
   moves those to a resumable STOPPED/PAUSED state.

Multi-process note: RUNNING_SCAN_TASKS is per process. The deployment runs a
single uvicorn worker. If you ever run several, a force-stop still finalizes
the DB row immediately (so the UI is correct at once) and the owning worker's
pipeline exits at its next stage checkpoint, which treats STOPPED as a stop.
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta
from typing import Awaitable, Callable, Dict, Iterable, List, Optional

from sqlalchemy.orm import Session

from app import events
from app.db import SessionLocal
from app.models.db import Scan
from app.services import minio_service
from app.services.pipeline import continue_resume, run_pipeline

log = logging.getLogger("scan_runner")

# Statuses a pipeline never leaves once reached; everything else is queued,
# running, paused or stop-requested.
TERMINAL_SCAN_STATUSES = {"completed", "review", "blocked", "failed", "stopped"}

# A finished scan keeps control_state="RUNNING" (historical convention that
# the UI relies on), so "is a pipeline live?" must look at status as well.
_LIVE_CONTROL_STATES = {"RUNNING", "PAUSE_REQUESTED", "STOP_REQUESTED", None}

RUNNING_SCAN_TASKS: Dict[str, "asyncio.Task[None]"] = {}
_SLOTS: Dict[int, asyncio.Semaphore] = {}
_shutting_down = False

SHUTDOWN_NOTE = "Interrupted by a server restart. Resume to continue from the last checkpoint."


def _int_env(name: str, default: int, minimum: int = 1) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except ValueError:
        return default


def max_concurrency() -> int:
    return _int_env("SCAN_PIPELINE_CONCURRENCY", 3)


def stop_grace_seconds() -> float:
    return float(_int_env("SCAN_STOP_GRACE_SECONDS", 3))


def _slots() -> asyncio.Semaphore:
    # Semaphores bind to a loop on first use; keep exactly one per running
    # loop (tests and reloads create new loops).
    key = id(asyncio.get_running_loop())
    sem = _SLOTS.get(key)
    if sem is None:
        _SLOTS.clear()
        sem = _SLOTS[key] = asyncio.Semaphore(max_concurrency())
    return sem


# --------------------------------------------------------------------------
# Classification helpers
# --------------------------------------------------------------------------

def scan_phase(scan: Scan) -> str:
    """One of: 'stopped' | 'finished' | 'paused' | 'live'."""
    if scan.control_state == "STOPPED" or scan.status == "stopped":
        return "stopped"
    if scan.status in TERMINAL_SCAN_STATUSES:
        return "finished"
    if scan.control_state == "PAUSED":
        return "paused"
    return "live"


def has_live_task(scan_id: str) -> bool:
    task = RUNNING_SCAN_TASKS.get(scan_id)
    return bool(task and not task.done())


# --------------------------------------------------------------------------
# Task lifecycle
# --------------------------------------------------------------------------

Work = Callable[[Session, Scan], Awaitable[object]]


def _forget(scan_id: str, task: "asyncio.Task[None]") -> None:
    if RUNNING_SCAN_TASKS.get(scan_id) is task:
        RUNNING_SCAN_TASKS.pop(scan_id, None)


def _spawn(scan_id: str, work: Work) -> "asyncio.Task[None]":
    existing = RUNNING_SCAN_TASKS.get(scan_id)
    if existing is not None and not existing.done():
        return existing  # never run the same scan twice at once
    task = asyncio.create_task(_execute(scan_id, work), name=f"scan-{scan_id[:8]}")
    RUNNING_SCAN_TASKS[scan_id] = task
    task.add_done_callback(lambda t, sid=scan_id: _forget(sid, t))
    return task


def start_scan_task(scan_id: str, raw_text: str, framework: str) -> "asyncio.Task[None]":
    """Run a freshly-created scan's full pipeline in the background."""
    async def work(db: Session, scan: Scan):
        return await run_pipeline(db, scan, raw_text, framework=framework)
    return _spawn(scan_id, work)


def start_resume_task(scan_id: str) -> "asyncio.Task[None]":
    """Continue a scan flagged by pipeline.mark_resuming() in the background."""
    async def work(db: Session, scan: Scan):
        return await continue_resume(db, scan)
    return _spawn(scan_id, work)


async def _execute(scan_id: str, work: Work) -> None:
    try:
        async with _slots():  # a queued scan waits here, and is cancellable here
            db = SessionLocal()
            try:
                scan = db.get(Scan, scan_id)
                if scan is None:  # deleted while queued
                    return
                if scan.control_state in ("STOP_REQUESTED", "STOPPED"):
                    finalize_stopped(db, scan_id)  # stopped while queued
                    return
                if scan.status == "queued":
                    scan.status = "uploaded"
                    db.commit()
                await work(db, scan)
            except Exception as exc:  # noqa: BLE001 - CancelledError is not an Exception
                log.exception("scan pipeline %s crashed", scan_id)
                _record_failure(db, scan_id, exc)
            finally:
                db.close()
    except asyncio.CancelledError:
        # Cancelled by a force-stop / force-delete / shutdown, either while
        # queued or mid-stage. The DB session above is already closed (its
        # uncommitted work rolled back); persist STOPPED from a fresh one.
        _finalize_in_new_session(scan_id, SHUTDOWN_NOTE if _shutting_down else None)
        raise


def _record_failure(db: Session, scan_id: str, exc: BaseException) -> None:
    try:
        db.rollback()
        scan = db.get(Scan, scan_id)
        if scan is not None and scan.status not in ("failed", "stopped"):
            scan.status = "failed"
            scan.error = str(exc)[:2000]
            db.commit()
    except Exception:  # noqa: BLE001
        log.exception("could not record failure for scan %s", scan_id)


def _finalize_in_new_session(scan_id: str, note: Optional[str]) -> None:
    db = SessionLocal()
    try:
        finalize_stopped(db, scan_id, note=note)
    except Exception:  # noqa: BLE001
        log.exception("could not persist STOPPED for scan %s", scan_id)
    finally:
        db.close()


# --------------------------------------------------------------------------
# Raw-config archiving for queued scans
# --------------------------------------------------------------------------

_BACKGROUND: "set[asyncio.Task]" = set()


def archive_raw_configs_in_background(items: List[tuple]) -> None:
    """Fire-and-forget: store each queued scan's raw config in the object
    store *now* instead of when its pipeline finally gets a slot.

    A bulk upload can leave dozens of scans queued behind the concurrency
    limit, holding their config text only in memory. If one is stopped (or
    the server restarts) before it starts, the in-memory copy is gone and it
    could never be resumed. Archiving up front makes queued scans just as
    resumable as running ones. Best-effort: MinIO trouble never affects the
    scan, and the request that queued them doesn't wait for it.

    ``items``: (scan_id, tenant_id, device_id, raw_bytes)
    """
    if not items:
        return

    async def _run() -> None:
        gate = asyncio.Semaphore(4)

        async def one(scan_id: str, tenant_id: str, device_id: str, raw: bytes) -> None:
            async with gate:
                key = minio_service.object_key(tenant_id, device_id, scan_id, "raw_config.txt")
                stored = await asyncio.to_thread(minio_service.put_object, key, raw, content_type="text/plain")
                if stored is None:
                    return
                db = SessionLocal()
                try:
                    scan = db.get(Scan, scan_id)
                    if scan is not None and not scan.raw_config_path:
                        scan.raw_config_path = key
                        db.commit()
                finally:
                    db.close()

        await asyncio.gather(*(one(*i) for i in items), return_exceptions=True)

    task = asyncio.create_task(_run(), name="scan-archive-raw")
    _BACKGROUND.add(task)
    task.add_done_callback(_BACKGROUND.discard)


# --------------------------------------------------------------------------
# Stop
# --------------------------------------------------------------------------

def finalize_stopped(db: Session, scan_id: str, note: Optional[str] = None) -> str:
    """Idempotently persist STOPPED. Returns 'stopped', 'finished' (the
    pipeline completed before the stop landed -- left as it is) or 'gone'."""
    db.rollback()
    scan = db.get(Scan, scan_id)
    if scan is None:
        return "gone"
    if scan.status in TERMINAL_SCAN_STATUSES and scan.status != "stopped":
        if scan.control_state != "RUNNING":
            scan.control_state = "RUNNING"  # clear a stop request that lost the race
            db.commit()
        return "finished"
    if scan.status == "stopped" and scan.control_state == "STOPPED":
        return "stopped"
    scan.status = "stopped"
    scan.control_state = "STOPPED"
    scan.stopped_at = datetime.utcnow()
    if note:
        scan.error = note
    db.commit()
    return "stopped"


async def stop_scans(
    db: Session, scans: Iterable[Scan], *, immediate: bool = True, note: Optional[str] = None,
) -> Dict[str, str]:
    """Stop many scans at once and return ``{scan_id: outcome}`` where outcome is
    'stopped' | 'already_stopped' | 'finished' | 'stopping' (cooperative stop
    still winding down at its next checkpoint).

    immediate=True (force stop): cancel each live task now, wait one short
    grace period for all of them together, then finalize every scan to
    STOPPED in the DB regardless -- so when this returns, nothing is left in
    STOP_REQUESTED.

    immediate=False: a live task is asked to stop at its next checkpoint;
    scans with no live task (paused, queued in another process, orphaned)
    are finalized right away since no checkpoint will ever run for them.
    """
    scans = list(scans)
    outcomes: Dict[str, str] = {}
    targets: List[Scan] = []
    for scan in scans:
        phase = scan_phase(scan)
        if phase == "stopped":
            outcomes[scan.id] = "already_stopped"
        elif phase == "finished":
            outcomes[scan.id] = "finished"
        else:
            targets.append(scan)
    if not targets:
        return outcomes

    for scan in targets:
        if scan.control_state != "PAUSED":
            scan.control_state = "STOP_REQUESTED"
    db.commit()

    live = {s.id: RUNNING_SCAN_TASKS[s.id] for s in targets if has_live_task(s.id)}
    if immediate and live:
        for task in live.values():
            task.cancel()
        # asyncio.wait (not wait_for/await): never re-cancels, never raises.
        await asyncio.wait(list(live.values()), timeout=stop_grace_seconds())

    for scan in targets:
        if immediate or scan.id not in live:
            result = finalize_stopped(db, scan.id, note=note)
            outcomes[scan.id] = {"stopped": "stopped", "finished": "finished"}.get(result, "stopped")
            if result == "stopped":
                await _publish_stopped(scan.id)
        else:
            outcomes[scan.id] = "stopping"
    return outcomes


async def _publish_stopped(scan_id: str) -> None:
    """Announce the stop on the event bus without ever making the stop wait
    for it: a down NATS makes the first publish() spend a long time on
    connect/reconnect attempts, and a force-stop must be immediate."""
    async def _send() -> None:
        try:
            await asyncio.wait_for(events.publish("pipeline.stopped", {"scan_id": scan_id, "forced": True}), 3)
        except Exception:  # noqa: BLE001 - event bus is best-effort
            pass

    task = asyncio.create_task(_send(), name="scan-stopped-event")
    _BACKGROUND.add(task)
    task.add_done_callback(_BACKGROUND.discard)


# --------------------------------------------------------------------------
# Reconciliation + shutdown
# --------------------------------------------------------------------------

def reconcile_stale(db: Session, *, startup: bool = False, grace_seconds: int = 20) -> int:
    """Repair scans whose pipeline no longer exists in this process.

    startup=True: this process just started, so every non-terminal scan with
    no live task lost its pipeline (crash / reload / deploy). Live ones become
    STOPPED (resumable); pending pause/stop requests are honoured.

    startup=False (called lazily from the running-scans list): only repair
    *_REQUESTED scans older than ``grace_seconds`` -- a healthy pipeline
    honours those within one stage checkpoint, so anything older is stuck.
    """
    now = datetime.utcnow()
    fixed = 0
    rows = db.query(Scan).filter(~Scan.status.in_(TERMINAL_SCAN_STATUSES)).all()
    for scan in rows:
        if has_live_task(scan.id) or scan.control_state == "PAUSED":
            continue
        age = now - (scan.updated_at or scan.created_at or now)
        stale = startup or age > timedelta(seconds=grace_seconds)
        state = scan.control_state
        if state == "STOP_REQUESTED" and stale:
            scan.status, scan.control_state, scan.stopped_at = "stopped", "STOPPED", now
        elif state == "PAUSE_REQUESTED" and stale:
            scan.status, scan.control_state, scan.paused_at = "paused", "PAUSED", now
        elif startup and state in _LIVE_CONTROL_STATES:
            scan.status, scan.control_state, scan.stopped_at = "stopped", "STOPPED", now
            scan.error = SHUTDOWN_NOTE
        else:
            continue
        fixed += 1
    if fixed:
        db.commit()
        log.warning("reconciled %d orphaned scan(s)%s", fixed, " at startup" if startup else "")
    return fixed


async def shutdown(timeout: float = 5.0) -> None:
    """Cancel in-flight pipelines on app shutdown; each persists a resumable
    STOPPED state (see _execute) instead of being left 'running' forever."""
    global _shutting_down
    _shutting_down = True
    tasks = [t for t in RUNNING_SCAN_TASKS.values() if not t.done()]
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.wait(tasks, timeout=timeout)
    _shutting_down = False
