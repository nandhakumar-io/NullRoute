"""Periodic evidence-integrity verification worker.

The Evidence Ledger UI already exposes an on-demand `POST
/api/evidence/{id}/verify` (recompute off-chain hash; additionally compare
against the on-chain hash when Fabric is enabled and the record was
anchored -- app/routers/evidence.py). That is sufficient to *detect*
tampering, but only if a human happens to click it -- silent tampering
(a direct database edit, or a compromised org unilaterally forging a
write despite the dual-org endorsement policy) could otherwise sit
undiscovered indefinitely.

This worker closes that gap by re-running the exact same verification
logic on a schedule, across every EvidenceRecord, and raising an alert
(alert_service.alert_evidence_integrity_failure) the moment a mismatch is
found -- matching the "no second compliance/verification implementation"
discipline the rest of this codebase follows (RULE 11): it calls
evidence_service.verify_evidence()/fabric_service.verify_evidence(), the
same functions the router uses, rather than reimplementing hash
comparison here.

Design (mirrors app/workers/scheduler_worker.py):
  - Its own long-lived process (see the `evidence-verifier` service in
    docker-compose.yml), separate from the `backend` uvicorn process and
    from `scheduler_worker`, so a slow Fabric round-trip never blocks API
    requests or schedule execution.
  - Each poll tick processes up to EVIDENCE_VERIFICATION_BATCH_SIZE
    records, oldest-checked-first (NULLs -- i.e. never checked -- first),
    so a large ledger is swept incrementally across ticks rather than
    trying to verify everything at once.
  - One record's failure (a raised exception, not an integrity mismatch)
    is caught, logged, and recorded as VERIFICATION_ERROR; it never stops
    the batch or the loop.
  - Graceful shutdown on SIGTERM/SIGINT (docker-compose `stop`).

Run standalone with: python -m app.workers.evidence_verification_worker
"""
from __future__ import annotations

import asyncio
import logging
import os
import signal
from typing import List, Optional

from sqlalchemy.orm import Session

from app.db import SessionLocal, init_db
from app.models.db import EvidenceRecord
from app.services import alert_service, evidence_service, fabric_service

logger = logging.getLogger("evidence_verification_worker")

POLL_INTERVAL_SECONDS = float(os.getenv("EVIDENCE_VERIFICATION_POLL_INTERVAL_SECONDS", "3600"))
BATCH_SIZE = int(os.getenv("EVIDENCE_VERIFICATION_BATCH_SIZE", "200"))
WORKER_ENABLED = os.getenv("EVIDENCE_VERIFICATION_WORKER_ENABLED", "true").lower() == "true"

_shutdown_event: Optional[asyncio.Event] = None


def _due_records(db: Session, limit: int) -> List[EvidenceRecord]:
    """Oldest-checked-first, never-checked records first (NULLs sort first
    ascending in Postgres/SQLite for this column) -- so a ledger larger
    than one batch still gets full coverage over successive ticks rather
    than the same head-of-table records being re-checked every time."""
    return (
        db.query(EvidenceRecord)
        .order_by(EvidenceRecord.last_verified_at.asc().nullsfirst())
        .limit(limit)
        .all()
    )


async def _verify_one(db: Session, record: EvidenceRecord) -> None:
    from datetime import datetime

    try:
        result = evidence_service.verify_evidence(record.evidence_hash, record.evidence_json)
        status = result.get("status", "INTEGRITY_VERIFIED" if result.get("match") else "INTEGRITY_FAILURE")

        if fabric_service.FABRIC_ENABLED and record.fabric_status == "ANCHORED":
            try:
                fabric_result = await fabric_service.verify_evidence(record.evidence_id, result["calculated_hash"])
                if not fabric_result.get("match"):
                    status = "INTEGRITY_FAILURE"
            except fabric_service.FabricUnavailableError:
                # Fabric being briefly unreachable is not itself an
                # integrity failure -- don't alert or flip status on it,
                # just leave the off-chain result as the tick's verdict
                # and let the next tick retry the on-chain half.
                logger.debug("Fabric unavailable while verifying evidence %s; off-chain result stands", record.evidence_id)

        record.last_verified_at = datetime.utcnow()
        record.last_verification_status = status
        db.commit()

        if status == "INTEGRITY_FAILURE":
            logger.warning("Evidence integrity check FAILED for %s (scan=%s tenant=%s)", record.evidence_id, record.scan_id, record.tenant_id)
            await alert_service.alert_evidence_integrity_failure(
                db, tenant_id=record.tenant_id, scan_id=record.scan_id,
                evidence_id=record.evidence_id,
                detail="Scheduled verification sweep found the stored evidence no longer matches its recorded hash.",
            )
    except Exception:  # noqa: BLE001 - one record's failure must never sink the batch
        logger.exception("Evidence verification errored for %s", record.evidence_id)
        db.rollback()
        try:
            record.last_verification_status = "VERIFICATION_ERROR"
            db.commit()
        except Exception:  # noqa: BLE001 - even the error write-back is best-effort
            db.rollback()


async def run_once() -> int:
    """Run a single poll tick: verify up to BATCH_SIZE due records.

    Returns the number of records processed, so tests and the loop's own
    logging can observe progress without depending on wall-clock timing.
    """
    db = SessionLocal()
    try:
        due = _due_records(db, BATCH_SIZE)
        for record in due:
            await _verify_one(db, record)
        return len(due)
    finally:
        db.close()


async def _loop() -> None:
    global _shutdown_event
    _shutdown_event = asyncio.Event()
    logger.info(
        "evidence_verification_worker started (poll interval=%ss, batch size=%s, enabled=%s)",
        POLL_INTERVAL_SECONDS, BATCH_SIZE, WORKER_ENABLED,
    )
    if not WORKER_ENABLED:
        logger.warning("EVIDENCE_VERIFICATION_WORKER_ENABLED=false -- worker is idle, exiting.")
        return

    while not _shutdown_event.is_set():
        try:
            processed = await run_once()
            if processed:
                logger.info("Poll tick verified %d evidence record(s)", processed)
        except Exception:  # noqa: BLE001 - a bad DB tick must not crash the process
            logger.exception("evidence_verification_worker poll tick failed")

        try:
            await asyncio.wait_for(_shutdown_event.wait(), timeout=POLL_INTERVAL_SECONDS)
        except asyncio.TimeoutError:
            pass  # normal case: just means it's time for the next poll


def _install_signal_handlers(loop: asyncio.AbstractEventLoop) -> None:
    def _request_shutdown() -> None:
        logger.info("evidence_verification_worker received shutdown signal")
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