"""Phase 12 -- background scheduler worker.

Covers the gap the docstrings in services/scheduling_service.py and
models/db.AuditSchedule pointed at but that didn't exist yet:
app/workers/scheduler_worker.py, the process that actually calls
execute_schedule() outside of the manual "run now" endpoint.

These tests stub scheduling_service.execute_schedule() itself (it's
already covered by the schedules router/pipeline tests) so we can assert
the worker's own responsibilities in isolation:
  - only picks up schedules that are enabled AND due
  - never lets one schedule's failure stop the others in the same tick
  - a disabled or not-yet-due schedule is left untouched
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.models.db import AuditSchedule, Tenant
from app.services import scheduling_service
from app.workers import scheduler_worker


@pytest.fixture
def db_session(tmp_path):
    """Independent SQLite engine per test, matching the pattern used by
    test_alert_service.py -- not the app.db module-level singleton, which
    is bound at import time."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.models.db import Base

    engine = create_engine(f"sqlite:///{tmp_path}/svc.db", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()
    yield db
    db.close()


def _tenant(db):
    t = Tenant(name="T1")
    db.add(t)
    db.commit()
    db.refresh(t)
    return t


def _schedule(db, tenant_id, *, name, next_run, enabled=True, frequency="daily"):
    s = AuditSchedule(
        tenant_id=tenant_id, name=name, scope={"all": True}, frequency=frequency,
        enabled=enabled, framework="ALL", next_run=next_run,
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    return s


@pytest.mark.asyncio
async def test_run_once_executes_only_due_enabled_schedules(db_session, monkeypatch):
    tenant = _tenant(db_session)
    now = datetime.utcnow()

    due = _schedule(db_session, tenant.id, name="due-now", next_run=now - timedelta(minutes=5))
    not_due = _schedule(db_session, tenant.id, name="future", next_run=now + timedelta(hours=1))
    disabled = _schedule(
        db_session, tenant.id, name="disabled-but-due",
        next_run=now - timedelta(minutes=5), enabled=False,
    )

    executed_ids = []

    async def _fake_execute(db, schedule):
        executed_ids.append(schedule.id)
        return {"schedule_id": schedule.id, "status": "SUCCESS", "detail": "ok", "results": []}

    monkeypatch.setattr(scheduling_service, "execute_schedule", _fake_execute)
    monkeypatch.setattr(scheduler_worker, "SessionLocal", lambda: db_session)

    async def _fake_publish(subject, payload):
        return None

    monkeypatch.setattr(scheduler_worker.events, "publish", _fake_publish)

    # db_session is closed by the test fixture, not by run_once, since we
    # injected it via SessionLocal — guard against the worker's own
    # `db.close()` from severing the fixture's connection mid-test.
    monkeypatch.setattr(db_session, "close", lambda: None)

    picked_up = await scheduler_worker.run_once()

    assert picked_up == 1
    assert executed_ids == [due.id]
    assert not_due.id not in executed_ids
    assert disabled.id not in executed_ids


@pytest.mark.asyncio
async def test_one_schedule_failure_does_not_block_others(db_session, monkeypatch):
    tenant = _tenant(db_session)
    now = datetime.utcnow()

    bad = _schedule(db_session, tenant.id, name="will-fail", next_run=now - timedelta(minutes=1))
    good = _schedule(db_session, tenant.id, name="will-succeed", next_run=now - timedelta(minutes=1))

    executed_ids = []

    async def _fake_execute(db, schedule):
        if schedule.id == bad.id:
            raise RuntimeError("collection blew up")
        executed_ids.append(schedule.id)
        return {"schedule_id": schedule.id, "status": "SUCCESS", "detail": "ok", "results": []}

    monkeypatch.setattr(scheduling_service, "execute_schedule", _fake_execute)
    monkeypatch.setattr(scheduler_worker, "SessionLocal", lambda: db_session)

    async def _fake_publish(subject, payload):
        return None

    monkeypatch.setattr(scheduler_worker.events, "publish", _fake_publish)
    monkeypatch.setattr(db_session, "close", lambda: None)

    picked_up = await scheduler_worker.run_once()

    assert picked_up == 2  # both were due and attempted
    assert executed_ids == [good.id]  # bad one raised but didn't stop the loop


@pytest.mark.asyncio
async def test_run_once_is_noop_when_nothing_due(db_session, monkeypatch):
    tenant = _tenant(db_session)
    _schedule(db_session, tenant.id, name="future", next_run=datetime.utcnow() + timedelta(days=1))

    called = False

    async def _fake_execute(db, schedule):
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr(scheduling_service, "execute_schedule", _fake_execute)
    monkeypatch.setattr(scheduler_worker, "SessionLocal", lambda: db_session)
    monkeypatch.setattr(db_session, "close", lambda: None)

    picked_up = await scheduler_worker.run_once()

    assert picked_up == 0
    assert called is False
