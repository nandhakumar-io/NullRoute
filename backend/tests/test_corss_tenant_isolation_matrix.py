"""Cross-tenant isolation matrix (spec section 19).

test_evidence_tenant_isolation.py, test_training_knowledge_tenant_isolation.py,
and test_change_requests.py::test_tenant_isolation_for_change_requests already
cover evidence, training mappings, knowledge base, and change requests. This
file closes the remaining gaps from the section-19 list: devices, drift
events, alerts, schedules, and exceptions. Every check follows the same
shape: seed a row for a second ("OtherTenant") tenant directly in the DB,
then confirm the demo-auth SIH-Demo-tenant client (a) never sees it in a
list endpoint and (b) gets 404 -- not the other tenant's data, and not a 500
-- when addressing it directly by id.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.auth import dependencies as deps_mod
from app.auth import jwt as jwt_mod


@pytest.fixture(autouse=True)
def _demo_auth(monkeypatch):
    monkeypatch.setattr(jwt_mod, "AUTH_ENABLED", False)
    monkeypatch.setattr(deps_mod, "AUTH_ENABLED", False)
    yield


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test.db")
    monkeypatch.setenv("AI_ENABLED", "false")
    from app.main import app

    with TestClient(app) as c:
        yield c


def _other_tenant(db):
    from app.models.db import Tenant
    t = Tenant(name="OtherTenant")
    db.add(t)
    db.commit()
    db.refresh(t)
    return t


# --------------------------------------------------------------------- #
# Devices
# --------------------------------------------------------------------- #

def _make_other_tenant_device(client):
    from app.db import SessionLocal
    from app.models.db import Device

    db = SessionLocal()
    try:
        other = _other_tenant(db)
        device = Device(tenant_id=other.id, hostname="other-r1", vendor="cisco")
        db.add(device)
        db.commit()
        db.refresh(device)
        return device.id
    finally:
        db.close()


def test_list_devices_excludes_other_tenant(client):
    device_id = _make_other_tenant_device(client)
    resp = client.get("/api/devices")
    assert resp.status_code == 200
    assert device_id not in [d["id"] for d in resp.json()["items"]]


def test_get_device_404s_for_other_tenant(client):
    device_id = _make_other_tenant_device(client)
    resp = client.get(f"/api/devices/{device_id}")
    assert resp.status_code == 404


def test_device_collection_status_404s_for_other_tenant(client):
    device_id = _make_other_tenant_device(client)
    resp = client.get(f"/api/devices/{device_id}/collection-status")
    assert resp.status_code == 404


def test_device_drift_404s_for_other_tenant(client):
    device_id = _make_other_tenant_device(client)
    resp = client.get(f"/api/devices/{device_id}/drift")
    assert resp.status_code == 404


# --------------------------------------------------------------------- #
# Drift events
# --------------------------------------------------------------------- #

def _make_other_tenant_drift_event(client):
    from app.db import SessionLocal
    from app.models.db import Device, DriftEvent, Scan

    db = SessionLocal()
    try:
        other = _other_tenant(db)
        device = Device(tenant_id=other.id, hostname="other-r2", vendor="arista")
        db.add(device)
        db.commit()
        db.refresh(device)

        scan = Scan(tenant_id=other.id, device_id=device.id, status="completed")
        db.add(scan)
        db.commit()
        db.refresh(scan)

        event = DriftEvent(
            tenant_id=other.id, device_id=device.id, current_scan_id=scan.id,
            current_config_hash="deadbeef", security_impacting=True,
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event.id
    finally:
        db.close()


def test_list_drift_excludes_other_tenant(client):
    event_id = _make_other_tenant_drift_event(client)
    resp = client.get("/api/drift")
    assert resp.status_code == 200
    body = resp.json()
    ids = [e["id"] for e in body] if isinstance(body, list) else [e["id"] for e in body.get("events", body.get("items", []))]
    assert event_id not in ids


# --------------------------------------------------------------------- #
# Alerts
# --------------------------------------------------------------------- #

def _make_other_tenant_alert(client):
    from app.db import SessionLocal
    from app.models.db import Alert

    db = SessionLocal()
    try:
        other = _other_tenant(db)
        alert = Alert(tenant_id=other.id, category="DRIFT", severity="HIGH", title="Other tenant's alert")
        db.add(alert)
        db.commit()
        db.refresh(alert)
        return alert.id
    finally:
        db.close()


def test_list_alerts_excludes_other_tenant(client):
    alert_id = _make_other_tenant_alert(client)
    resp = client.get("/api/alerts")
    assert resp.status_code == 200
    body = resp.json()
    ids = [a["id"] for a in body] if isinstance(body, list) else [a["id"] for a in body.get("alerts", body.get("items", []))]
    assert alert_id not in ids


def test_acknowledge_alert_404s_for_other_tenant(client):
    """Tenant A must not be able to acknowledge (mutate) tenant B's alert
    merely by guessing/enumerating its id."""
    alert_id = _make_other_tenant_alert(client)
    resp = client.post(f"/api/alerts/{alert_id}/acknowledge")
    assert resp.status_code == 404

    # Confirm it genuinely wasn't touched.
    from app.db import SessionLocal
    from app.models.db import Alert
    db = SessionLocal()
    try:
        still_there = db.query(Alert).filter(Alert.id == alert_id).first()
        assert still_there is not None
        assert still_there.acknowledged_at is None or still_there.acknowledged_at is None  # never set by tenant A
    finally:
        db.close()


# --------------------------------------------------------------------- #
# Schedules
# --------------------------------------------------------------------- #

def _make_other_tenant_schedule(client):
    from app.db import SessionLocal
    from app.models.db import AuditSchedule

    db = SessionLocal()
    try:
        other = _other_tenant(db)
        sched = AuditSchedule(tenant_id=other.id, name="other tenant nightly scan", scope={"all": True})
        db.add(sched)
        db.commit()
        db.refresh(sched)
        return sched.id
    finally:
        db.close()


def test_list_schedules_excludes_other_tenant(client):
    schedule_id = _make_other_tenant_schedule(client)
    resp = client.get("/api/schedules")
    assert resp.status_code == 200
    assert schedule_id not in [s["id"] for s in resp.json()]


def test_get_schedule_404s_for_other_tenant(client):
    schedule_id = _make_other_tenant_schedule(client)
    resp = client.get(f"/api/schedules/{schedule_id}")
    assert resp.status_code == 404


def test_patch_schedule_404s_for_other_tenant(client):
    schedule_id = _make_other_tenant_schedule(client)
    resp = client.patch(f"/api/schedules/{schedule_id}", json={"enabled": False})
    assert resp.status_code == 404


def test_delete_schedule_404s_for_other_tenant(client):
    schedule_id = _make_other_tenant_schedule(client)
    resp = client.delete(f"/api/schedules/{schedule_id}")
    assert resp.status_code == 404

    from app.db import SessionLocal
    from app.models.db import AuditSchedule
    db = SessionLocal()
    try:
        assert db.query(AuditSchedule).filter(AuditSchedule.id == schedule_id).first() is not None
    finally:
        db.close()


def test_run_schedule_404s_for_other_tenant(client):
    schedule_id = _make_other_tenant_schedule(client)
    resp = client.post(f"/api/schedules/{schedule_id}/run")
    assert resp.status_code == 404


# --------------------------------------------------------------------- #
# Compliance exceptions
# --------------------------------------------------------------------- #

def _make_other_tenant_exception(client):
    from app.db import SessionLocal
    from app.models.db import ComplianceException, Device

    db = SessionLocal()
    try:
        other = _other_tenant(db)
        device = Device(tenant_id=other.id, hostname="other-r3", vendor="juniper")
        db.add(device)
        db.commit()
        db.refresh(device)

        exc = ComplianceException(
            tenant_id=other.id, device_id=device.id, control_id="AAA-01",
            reason="other tenant's exception", status="PENDING",
            expires_at=datetime.utcnow() + timedelta(days=30),
        )
        db.add(exc)
        db.commit()
        db.refresh(exc)
        return exc.id
    finally:
        db.close()


def test_list_exceptions_excludes_other_tenant(client):
    exc_id = _make_other_tenant_exception(client)
    resp = client.get("/api/exceptions")
    assert resp.status_code == 200
    body = resp.json()
    ids = [e["id"] for e in body] if isinstance(body, list) else [e["id"] for e in body.get("exceptions", body.get("items", []))]
    assert exc_id not in ids


def test_approve_exception_404s_for_other_tenant(client):
    """Tenant A approving/rejecting tenant B's exception would be a serious
    compliance-integrity issue (spec 45: exceptions must never silently
    override another tenant's OPA result)."""
    exc_id = _make_other_tenant_exception(client)
    resp = client.post(f"/api/exceptions/{exc_id}/approve")
    assert resp.status_code == 404

    from app.db import SessionLocal
    from app.models.db import ComplianceException
    db = SessionLocal()
    try:
        still_pending = db.query(ComplianceException).filter(ComplianceException.id == exc_id).first()
        assert still_pending.status == "PENDING"
    finally:
        db.close()


def test_reject_exception_404s_for_other_tenant(client):
    exc_id = _make_other_tenant_exception(client)
    resp = client.post(f"/api/exceptions/{exc_id}/reject", json={"reason": "no"})
    assert resp.status_code == 404