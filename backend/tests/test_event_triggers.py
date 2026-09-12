"""Phase 16 -- configurable event-driven pipeline triggers.

Covers app/services/event_trigger_service.py in isolation (own SQLite
engine, matching test_scheduler_worker.py's pattern) plus the dispatch
hook wired into app.events.publish().
"""
from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest

from app.models.db import (AuditSchedule, Base, Device, EventTrigger,
                            EventTriggerLog, Scan, Tenant)
from app.services import event_trigger_service


@pytest.fixture
def db_session(tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(f"sqlite:///{tmp_path}/triggers.db", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()
    yield db
    db.close()


@pytest.fixture
def tenant(db_session):
    t = Tenant(name="acme")
    db_session.add(t)
    db_session.commit()
    return t


# --------------------------------------------------------------------- #
# filter matching
# --------------------------------------------------------------------- #

def test_matches_filter_none_always_matches():
    assert event_trigger_service.matches_filter({"a": 1}, None) is True


def test_matches_filter_single_clause():
    payload = {"decision": "FAIL", "score": 42}
    assert event_trigger_service.matches_filter(payload, {"field": "decision", "op": "eq", "value": "FAIL"})
    assert not event_trigger_service.matches_filter(payload, {"field": "decision", "op": "eq", "value": "PASS"})


def test_matches_filter_and_list_of_clauses():
    payload = {"decision": "FAIL", "score": 42}
    clauses = [
        {"field": "decision", "op": "eq", "value": "FAIL"},
        {"field": "score", "op": "gte", "value": 40},
    ]
    assert event_trigger_service.matches_filter(payload, clauses)
    clauses[1]["value"] = 50
    assert not event_trigger_service.matches_filter(payload, clauses)


def test_matches_filter_dotted_field_and_in_op():
    payload = {"findings": [{"result": "FAIL"}]}
    assert event_trigger_service.matches_filter(payload, {"field": "findings.0.result", "op": "in", "value": ["FAIL", "ERROR"]})


def test_matches_filter_malformed_clause_fails_open():
    assert event_trigger_service.matches_filter({"a": 1}, {"op": "eq", "value": 1}) is True  # missing "field"


# --------------------------------------------------------------------- #
# tenant resolution
# --------------------------------------------------------------------- #

def test_resolve_tenant_id_direct(db_session, tenant):
    assert event_trigger_service._resolve_tenant_id(db_session, {"tenant_id": tenant.id}) == tenant.id


def test_resolve_tenant_id_via_scan(db_session, tenant):
    device = Device(tenant_id=tenant.id, hostname="r1", vendor="cisco")
    db_session.add(device)
    db_session.commit()
    scan = Scan(tenant_id=tenant.id, device_id=device.id)
    db_session.add(scan)
    db_session.commit()
    assert event_trigger_service._resolve_tenant_id(db_session, {"scan_id": scan.id}) == tenant.id


def test_resolve_tenant_id_none_when_unresolvable(db_session):
    assert event_trigger_service._resolve_tenant_id(db_session, {}) is None


# --------------------------------------------------------------------- #
# dispatch / end-to-end trigger firing
# --------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_dispatch_fires_create_alert_action(db_session, tenant):
    trigger = EventTrigger(
        tenant_id=tenant.id, name="high cpu", event_type="metrics.threshold_breached",
        filter=None, action_type="create_alert",
        action_config={"category": "capacity", "severity": "HIGH", "title_template": "CPU hot: {device_id}"},
        enabled=True,
    )
    db_session.add(trigger)
    db_session.commit()

    fake_alert = type("A", (), {"id": "alert-1"})()
    with patch("app.db.SessionLocal", return_value=db_session), \
         patch("app.services.alert_service.create_alert", new=AsyncMock(return_value=fake_alert)) as mock_create:
        await event_trigger_service.dispatch("metrics.threshold_breached", {"tenant_id": tenant.id, "device_id": "dev-1"})

    mock_create.assert_awaited_once()
    db_session.refresh(trigger)
    assert trigger.trigger_count == 1
    assert trigger.last_triggered_at is not None
    logs = event_trigger_service.trigger_logs(db_session, trigger.id, tenant.id)
    assert len(logs) == 1
    assert logs[0].outcome == "fired"


@pytest.mark.asyncio
async def test_dispatch_skips_when_filter_does_not_match(db_session, tenant):
    trigger = EventTrigger(
        tenant_id=tenant.id, name="only FAIL", event_type="compliance.scan.completed",
        filter={"field": "decision", "op": "eq", "value": "FAIL"},
        action_type="create_alert", action_config={}, enabled=True,
    )
    db_session.add(trigger)
    db_session.commit()

    with patch("app.db.SessionLocal", return_value=db_session), \
         patch("app.services.alert_service.create_alert", new=AsyncMock()) as mock_create:
        await event_trigger_service.dispatch("compliance.scan.completed", {"tenant_id": tenant.id, "decision": "PASS"})

    mock_create.assert_not_awaited()
    db_session.refresh(trigger)
    assert trigger.trigger_count == 0
    logs = event_trigger_service.trigger_logs(db_session, trigger.id, tenant.id)
    assert logs[0].outcome == "skipped_filter"


@pytest.mark.asyncio
async def test_dispatch_respects_cooldown(db_session, tenant):
    trigger = EventTrigger(
        tenant_id=tenant.id, name="noisy", event_type="finding.created",
        action_type="create_alert", action_config={}, enabled=True,
        cooldown_seconds=3600, last_triggered_at=datetime.utcnow() - timedelta(seconds=10),
    )
    db_session.add(trigger)
    db_session.commit()

    with patch("app.db.SessionLocal", return_value=db_session), \
         patch("app.services.alert_service.create_alert", new=AsyncMock()) as mock_create:
        await event_trigger_service.dispatch("finding.created", {"tenant_id": tenant.id})

    mock_create.assert_not_awaited()
    logs = event_trigger_service.trigger_logs(db_session, trigger.id, tenant.id)
    assert logs[0].outcome == "skipped_cooldown"


@pytest.mark.asyncio
async def test_dispatch_disabled_trigger_never_evaluated(db_session, tenant):
    trigger = EventTrigger(
        tenant_id=tenant.id, name="off", event_type="finding.created",
        action_type="create_alert", action_config={}, enabled=False,
    )
    db_session.add(trigger)
    db_session.commit()

    with patch("app.db.SessionLocal", return_value=db_session), \
         patch("app.services.alert_service.create_alert", new=AsyncMock()) as mock_create:
        await event_trigger_service.dispatch("finding.created", {"tenant_id": tenant.id})

    mock_create.assert_not_awaited()
    assert event_trigger_service.trigger_logs(db_session, trigger.id, tenant.id) == []


@pytest.mark.asyncio
async def test_dispatch_run_schedule_action_reuses_execute_schedule(db_session, tenant):
    schedule = AuditSchedule(tenant_id=tenant.id, name="nightly", scope={"all": True}, frequency="manual")
    db_session.add(schedule)
    db_session.commit()

    trigger = EventTrigger(
        tenant_id=tenant.id, name="rescan on breach", event_type="metrics.threshold_breached",
        action_type="run_schedule", action_config={"schedule_id": schedule.id}, enabled=True,
    )
    db_session.add(trigger)
    db_session.commit()

    fake_result = {"schedule_id": schedule.id, "status": "SUCCESS", "detail": "0/0"}
    with patch("app.db.SessionLocal", return_value=db_session), \
         patch("app.services.scheduling_service.execute_schedule", new=AsyncMock(return_value=fake_result)) as mock_exec:
        await event_trigger_service.dispatch("metrics.threshold_breached", {"tenant_id": tenant.id})

    mock_exec.assert_awaited_once()
    logs = event_trigger_service.trigger_logs(db_session, trigger.id, tenant.id)
    assert logs[0].outcome == "fired"
    assert logs[0].action_result["schedule_result"] == fake_result


@pytest.mark.asyncio
async def test_dispatch_unknown_schedule_id_logs_failure(db_session, tenant):
    trigger = EventTrigger(
        tenant_id=tenant.id, name="bad config", event_type="finding.created",
        action_type="run_schedule", action_config={"schedule_id": "does-not-exist"}, enabled=True,
    )
    db_session.add(trigger)
    db_session.commit()

    with patch("app.db.SessionLocal", return_value=db_session):
        await event_trigger_service.dispatch("finding.created", {"tenant_id": tenant.id})

    logs = event_trigger_service.trigger_logs(db_session, trigger.id, tenant.id)
    assert logs[0].outcome == "failed"
    assert "not found" in logs[0].error


@pytest.mark.asyncio
async def test_dispatch_no_resolvable_tenant_is_a_noop(db_session):
    # No tenant_id/scan_id/device_id anywhere in payload -> dispatch must
    # return quietly rather than raise.
    with patch("app.db.SessionLocal", return_value=db_session):
        await event_trigger_service.dispatch("finding.created", {})  # should not raise


# --------------------------------------------------------------------- #
# events.publish() recursion guard
# --------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_events_publish_dispatch_depth_guard():
    import app.events as events_mod

    calls = {"n": 0}

    async def _recursive_dispatch(event_type, payload):
        calls["n"] += 1
        if calls["n"] < 10:  # would recurse forever without the depth guard
            await events_mod.publish(event_type, payload)

    with patch("app.services.event_trigger_service.dispatch", new=_recursive_dispatch), \
         patch.object(events_mod, "_get_conn", new=AsyncMock(return_value=None)):
        await events_mod.publish("some.event", {})

    assert calls["n"] == events_mod.MAX_TRIGGER_DISPATCH_DEPTH + 1