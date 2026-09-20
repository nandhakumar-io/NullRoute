"""Unit tests for services/rollback_service.py (Phase 15b, section 12 of the
Part 3 integration brief): DEPLOY -> VERIFY -> FAIL -> ROLLBACK -> VERIFY
ROLLBACK -> EVIDENCE.

Exercises the service directly against an in-memory sqlite session with the
collector/deployer/object-storage/credential/pipeline seams mocked, mirroring
the unit-test style used elsewhere for deployment_service (rather than the
full HTTP router e2e style used in test_change_request_gnmi_deploy_e2e.py)
so these stay fast and independent of auth/OPA/Batfish setup.
"""
from __future__ import annotations

import hashlib

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models.db import Base, ChangeRequest, Device, DeploymentRecord, RollbackRecord
from app.services import rollback_service
from app.services.collectors.base import CollectionResult
from app.services.deployment.base import DeploymentResult
from app.services.openbao_service import DeviceCredentials


CURRENT_CONFIG = "hostname r1\nno ip http server\n"
CURRENT_HASH = hashlib.sha256(CURRENT_CONFIG.encode()).hexdigest()


@pytest.fixture
def db(tmp_path):
    """Independent SQLite engine per test (matches test_alert_service.py's
    db_session fixture) -- never the app.db module-level singleton, which
    is bound at import time."""
    engine = create_engine(f"sqlite:///{tmp_path}/rollback.db", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


@pytest.fixture
def scenario(db):
    device = Device(tenant_id="t1", hostname="r1", vendor="cisco", management_address="10.0.0.1")
    db.add(device)
    db.commit()
    db.refresh(device)

    cr = ChangeRequest(
        tenant_id="t1", device_id=device.id, created_by="alice",
        current_config_object_key="tenants/t1/devices/x/change-requests/y/current.cfg",
        current_config_hash=CURRENT_HASH,
        proposed_config_hash="deadbeef",
        status="APPROVED",
    )
    db.add(cr)
    db.commit()
    db.refresh(cr)

    dr = DeploymentRecord(
        tenant_id="t1", change_request_id=cr.id, device_id=device.id,
        initiated_by="alice", transport="ssh",
        expected_pre_hash=CURRENT_HASH, observed_pre_hash=CURRENT_HASH,
        status="DRIFTED", post_config_hash="cafebabe", post_verification_passed=False,
    )
    db.add(dr)
    db.commit()
    db.refresh(dr)
    return device, cr, dr


def _patch_common(monkeypatch, db):
    monkeypatch.setattr(rollback_service, "_resolve_credentials",
                         lambda db_, device, tenant_id, credential_ref_id=None:
                         DeviceCredentials(credential_type="ssh_password", secret={"username": "a", "password": "b"}))
    monkeypatch.setattr(rollback_service.minio_service, "get_object", lambda key: CURRENT_CONFIG.encode())

    async def _fake_run_pipeline(db_, scan, raw_text, framework="ALL"):
        scan.status = "completed"
        return scan
    monkeypatch.setattr(rollback_service, "run_pipeline", _fake_run_pipeline)


DRIFTED_RUNNING = "hostname r1\nip http server\nip ssh version 2\n"


def _stateful_collector(first_raw, later_raw, later_hash):
    calls = {"n": 0}

    def collect(device_, creds):
        calls["n"] += 1
        if calls["n"] == 1:
            return CollectionResult(success=True, raw_config=first_raw, config_hash="pre")
        return CollectionResult(success=True, raw_config=later_raw, config_hash=later_hash)
    return type("C", (), {"collect_config": staticmethod(collect)})()


@pytest.mark.asyncio
async def test_rollback_succeeds_and_verifies(db, scenario, monkeypatch):
    device, cr, dr = scenario
    _patch_common(monkeypatch, db)
    pushed = []

    def push(device_, creds, lines):
        pushed.append(list(lines))
        return DeploymentResult(success=True, transport="ssh")
    monkeypatch.setattr(rollback_service, "get_deployer",
                        lambda transport: type("D", (), {"push_config": staticmethod(push)})())
    coll = _stateful_collector(DRIFTED_RUNNING, CURRENT_CONFIG, CURRENT_HASH)
    monkeypatch.setattr(rollback_service, "get_collector", lambda vendor, transport=None: coll)

    rb = await rollback_service.rollback_deployment(db, dr, initiated_by="bob")

    assert rb.status == "VERIFIED"
    assert rb.post_rollback_verified is True
    assert rb.post_rollback_hash == CURRENT_HASH
    assert rb.post_rollback_scan_id is not None
    # Only the difference is reverted -- never the whole archived config.
    assert pushed == [["no ip http server", "no ip ssh version 2"]]
    db.refresh(dr)
    assert dr.rolled_back is True


@pytest.mark.asyncio
async def test_rollback_push_failure_is_critical(db, scenario, monkeypatch):
    device, cr, dr = scenario
    _patch_common(monkeypatch, db)
    monkeypatch.setattr(rollback_service, "get_deployer",
                         lambda transport: type("D", (), {"push_config": staticmethod(
                             lambda device_, creds, lines: DeploymentResult(
                                 success=False, transport="ssh", error="auth failed"))})())
    coll = _stateful_collector(DRIFTED_RUNNING, DRIFTED_RUNNING, "x")
    monkeypatch.setattr(rollback_service, "get_collector", lambda vendor, transport=None: coll)

    rb = await rollback_service.rollback_deployment(db, dr, initiated_by="bob")

    assert rb.status == "CRITICAL_MANUAL_INTERVENTION_REQUIRED"
    assert "auth failed" in rb.error
    db.refresh(dr)
    assert dr.rolled_back is False


@pytest.mark.asyncio
async def test_rollback_verification_mismatch_is_critical_not_success(db, scenario, monkeypatch):
    """Push succeeds, but the device's actual post-rollback config doesn't
    match the target hash -- section 12: never report rollback success
    without verification."""
    device, cr, dr = scenario
    _patch_common(monkeypatch, db)
    monkeypatch.setattr(rollback_service, "get_deployer",
                         lambda transport: type("D", (), {"push_config": staticmethod(
                             lambda device_, creds, lines: DeploymentResult(success=True, transport="ssh"))})())
    monkeypatch.setattr(rollback_service, "get_collector",
                         lambda vendor, transport=None: type("C", (), {"collect_config": staticmethod(
                             lambda device_, creds: CollectionResult(
                                 success=True, raw_config="hostname r1\nsomething-else\n",
                                 config_hash="not-the-target-hash"))})())

    rb = await rollback_service.rollback_deployment(db, dr, initiated_by="bob")

    assert rb.status == "CRITICAL_MANUAL_INTERVENTION_REQUIRED"
    assert rb.post_rollback_verified is False
    db.refresh(dr)
    assert dr.rolled_back is False


@pytest.mark.asyncio
async def test_rollback_rejects_ineligible_status(db, scenario, monkeypatch):
    device, cr, dr = scenario
    dr.status = "FAILED"  # push never happened -- nothing to roll back
    db.commit()
    _patch_common(monkeypatch, db)

    with pytest.raises(ValueError, match="not eligible for rollback"):
        await rollback_service.rollback_deployment(db, dr, initiated_by="bob")


@pytest.mark.asyncio
async def test_rollback_missing_archived_config_is_critical(db, scenario, monkeypatch):
    device, cr, dr = scenario
    cr.current_config_object_key = None
    cr.current_config_hash = None
    db.commit()
    _patch_common(monkeypatch, db)

    rb = await rollback_service.rollback_deployment(db, dr, initiated_by="bob")

    assert rb.status == "CRITICAL_MANUAL_INTERVENTION_REQUIRED"
    assert "No archived pre-change configuration" in rb.error
