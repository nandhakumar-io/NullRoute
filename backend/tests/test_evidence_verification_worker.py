"""app/workers/evidence_verification_worker.py -- the scheduled sweep that
re-verifies every EvidenceRecord on a timer instead of waiting for someone
to click "Verify" in the Evidence Ledger UI.

Covers: a clean record is marked INTEGRITY_VERIFIED with a timestamp; a
tampered record is marked INTEGRITY_FAILURE AND raises a CRITICAL
EVIDENCE_INTEGRITY_FAILURE alert; one record raising an exception is
recorded as VERIFICATION_ERROR without aborting the rest of the batch;
and the oldest-checked-first ordering (NULLs first) actually holds.
"""
from __future__ import annotations

import pytest

from app.auth import dependencies as deps_mod
from app.auth import jwt as jwt_mod


@pytest.fixture(autouse=True)
def _demo_auth(monkeypatch):
    monkeypatch.setattr(jwt_mod, "AUTH_ENABLED", False)
    monkeypatch.setattr(deps_mod, "AUTH_ENABLED", False)
    yield


@pytest.fixture
def db_session(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test.db")
    monkeypatch.setenv("AI_ENABLED", "false")
    monkeypatch.setattr("app.services.fabric_service.FABRIC_ENABLED", False)
    from app.db import SessionLocal, init_db

    init_db()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _make_evidence(db, *, tenant_name, evidence_id, evidence_json, evidence_hash, fabric_status="NOT_ANCHORED"):
    from app.models.db import EvidenceRecord, Scan, Tenant

    tenant = Tenant(name=tenant_name)
    db.add(tenant)
    db.commit()
    db.refresh(tenant)

    scan = Scan(tenant_id=tenant.id, device_id="dev-x", status="completed")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    record = EvidenceRecord(
        evidence_id=evidence_id, scan_id=scan.id, device_id="dev-x", tenant_id=tenant.id,
        evidence_json=evidence_json, evidence_hash=evidence_hash, final_decision="PASS",
        fabric_status=fabric_status,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def test_clean_record_marked_verified_with_timestamp(db_session):
    from app.services import evidence_service
    from app.workers import evidence_verification_worker as worker

    evidence_json = {"final_decision": "PASS"}
    evidence_hash = evidence_service.hash_evidence(evidence_service.canonicalize_evidence(evidence_json))
    record = _make_evidence(db_session, tenant_name="T1", evidence_id="ev-clean", evidence_json=evidence_json, evidence_hash=evidence_hash)

    assert record.last_verified_at is None
    processed = _run(worker, db_session)
    assert processed == 1

    db_session.refresh(record)
    assert record.last_verification_status == "INTEGRITY_VERIFIED"
    assert record.last_verified_at is not None


def test_tampered_record_marked_failure_and_raises_alert(db_session):
    from app.models.db import Alert
    from app.workers import evidence_verification_worker as worker

    # evidence_hash deliberately does not match evidence_json -- exactly
    # what evidence_service.verify_evidence() is designed to catch.
    record = _make_evidence(
        db_session, tenant_name="T2", evidence_id="ev-tampered",
        evidence_json={"final_decision": "BLOCK"}, evidence_hash="0" * 64,
    )

    processed = _run(worker, db_session)
    assert processed == 1

    db_session.refresh(record)
    assert record.last_verification_status == "INTEGRITY_FAILURE"

    alerts = db_session.query(Alert).filter(Alert.tenant_id == record.tenant_id).all()
    assert len(alerts) == 1
    assert alerts[0].category == "EVIDENCE_INTEGRITY_FAILURE"
    assert alerts[0].severity == "CRITICAL"
    assert alerts[0].extra["evidence_id"] == "ev-tampered"


def test_one_record_raising_does_not_abort_batch(db_session, monkeypatch):
    from app.services import evidence_service
    from app.workers import evidence_verification_worker as worker

    evidence_json = {"final_decision": "PASS"}
    evidence_hash = evidence_service.hash_evidence(evidence_service.canonicalize_evidence(evidence_json))
    bad = _make_evidence(db_session, tenant_name="T3a", evidence_id="ev-bad", evidence_json=evidence_json, evidence_hash=evidence_hash)
    good = _make_evidence(db_session, tenant_name="T3b", evidence_id="ev-good", evidence_json=evidence_json, evidence_hash=evidence_hash)

    real_verify = evidence_service.verify_evidence

    def _flaky_verify(stored_hash, evidence):
        if stored_hash == bad.evidence_hash and evidence is bad.evidence_json:
            raise RuntimeError("simulated verification blowup")
        return real_verify(stored_hash, evidence)

    monkeypatch.setattr(evidence_service, "verify_evidence", _flaky_verify)

    processed = _run(worker, db_session)
    assert processed == 2

    db_session.refresh(bad)
    db_session.refresh(good)
    assert bad.last_verification_status == "VERIFICATION_ERROR"
    assert good.last_verification_status == "INTEGRITY_VERIFIED"


def test_due_records_orders_never_checked_first(db_session):
    from datetime import datetime, timedelta

    from app.workers import evidence_verification_worker as worker

    old = _make_evidence(db_session, tenant_name="T4a", evidence_id="ev-old", evidence_json={}, evidence_hash="x")
    old.last_verified_at = datetime.utcnow() - timedelta(days=1)
    db_session.commit()

    never_checked = _make_evidence(db_session, tenant_name="T4b", evidence_id="ev-never", evidence_json={}, evidence_hash="x")

    due = worker._due_records(db_session, limit=10)
    ids = [r.evidence_id for r in due]
    # never-checked (NULL last_verified_at) sorts before the older-but-
    # already-checked record, so nothing is starved of its first check
    # while a large ledger is repeatedly re-verifying already-known-good
    # records.
    assert ids.index("ev-never") < ids.index("ev-old")


def _run(worker, db):
    """Runs one verification pass over `db`'s session by monkeypatching the
    worker module's SessionLocal to hand back this test's already-open
    session, so assertions and the worker share the same sqlite-file state
    without needing a second connection.
    """
    import asyncio

    class _NoCloseSession:
        def __init__(self, real):
            self._real = real

        def __getattr__(self, name):
            return getattr(self._real, name)

        def close(self):
            pass  # keep the fixture's session open for post-assertions

    original_session_local = worker.SessionLocal
    worker.SessionLocal = lambda: _NoCloseSession(db)
    try:
        return asyncio.run(worker.run_once())
    finally:
        worker.SessionLocal = original_session_local