"""Enterprise Network Scan UI pass -- background worker.

Mirrors test_scheduler_worker.py's approach: stub
network_scan_service.execute_scan_job (already exercised in
test_network_scan_service.py) and assert the worker's own
responsibilities in isolation -- only PENDING jobs are picked up, and one
job's failure never blocks another in the same poll tick.
"""
from __future__ import annotations

import pytest

from app.models.db import NetworkScanJob, Tenant
from app.services import network_scan_service
from app.workers import network_scan_worker


@pytest.fixture
def db_session(tmp_path):
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


def _job(db, tenant_id, *, status="PENDING"):
    job = NetworkScanJob(
        tenant_id=tenant_id, run_discovery=False, requested_device_ids=[],
        framework="ALL", status=status, stages=network_scan_service.init_stages(),
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


@pytest.mark.asyncio
async def test_run_once_executes_only_pending_jobs(db_session, monkeypatch):
    tenant = _tenant(db_session)
    pending = _job(db_session, tenant.id, status="PENDING")
    running = _job(db_session, tenant.id, status="RUNNING")
    completed = _job(db_session, tenant.id, status="COMPLETED")

    executed_ids = []

    async def _fake_execute(db, job):
        executed_ids.append(job.id)
        job.status = "COMPLETED"

    monkeypatch.setattr(network_scan_service, "execute_scan_job", _fake_execute)
    monkeypatch.setattr(network_scan_worker, "execute_scan_job", _fake_execute)
    monkeypatch.setattr(network_scan_worker, "SessionLocal", lambda: db_session)

    async def _fake_publish(subject, payload):
        return None

    monkeypatch.setattr(network_scan_worker.events, "publish", _fake_publish)
    monkeypatch.setattr(db_session, "close", lambda: None)

    picked_up = await network_scan_worker.run_once()

    assert picked_up == 1
    assert executed_ids == [pending.id]
    assert running.id not in executed_ids
    assert completed.id not in executed_ids


@pytest.mark.asyncio
async def test_one_job_failure_does_not_block_others(db_session, monkeypatch):
    tenant = _tenant(db_session)
    bad = _job(db_session, tenant.id, status="PENDING")
    good = _job(db_session, tenant.id, status="PENDING")

    executed_ids = []

    async def _fake_execute(db, job):
        if job.id == bad.id:
            raise RuntimeError("nmap blew up")
        executed_ids.append(job.id)
        job.status = "COMPLETED"

    monkeypatch.setattr(network_scan_worker, "execute_scan_job", _fake_execute)
    monkeypatch.setattr(network_scan_worker, "SessionLocal", lambda: db_session)

    async def _fake_publish(subject, payload):
        return None

    monkeypatch.setattr(network_scan_worker.events, "publish", _fake_publish)
    monkeypatch.setattr(db_session, "close", lambda: None)

    picked_up = await network_scan_worker.run_once()

    assert picked_up == 2
    assert executed_ids == [good.id]
    db_session.refresh(bad)
    assert bad.status == "FAILED"


@pytest.mark.asyncio
async def test_run_once_is_noop_when_nothing_pending(db_session, monkeypatch):
    tenant = _tenant(db_session)
    _job(db_session, tenant.id, status="COMPLETED")

    called = False

    async def _fake_execute(db, job):
        nonlocal called
        called = True

    monkeypatch.setattr(network_scan_worker, "execute_scan_job", _fake_execute)
    monkeypatch.setattr(network_scan_worker, "SessionLocal", lambda: db_session)
    monkeypatch.setattr(db_session, "close", lambda: None)

    picked_up = await network_scan_worker.run_once()

    assert picked_up == 0
    assert not called
