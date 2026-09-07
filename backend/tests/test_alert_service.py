import pytest
from fastapi.testclient import TestClient

from app.auth import dependencies as deps_mod
from app.auth import jwt as jwt_mod
from app.services import alert_service


@pytest.fixture(autouse=True)
def _demo_auth(monkeypatch):
    monkeypatch.setattr(jwt_mod, "AUTH_ENABLED", False)
    monkeypatch.setattr(deps_mod, "AUTH_ENABLED", False)
    yield


@pytest.fixture(autouse=True)
def _no_real_network(monkeypatch):
    """The sandbox's egress firewall hangs (rather than fast-refuses)
    connections to hosts outside the allowlist, so NATS publishing must be
    stubbed in tests -- exercising the *behavior* (dispatch never raises,
    results recorded) without depending on real network reachability."""
    async def _fake_publish(subject, payload):
        return None

    monkeypatch.setattr(alert_service.events, "publish", _fake_publish)
    yield


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test.db")
    monkeypatch.setenv("AI_ENABLED", "false")
    from app.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture
def db_session(tmp_path):
    """Independent SQLite engine per test (not the app.db module-level
    singleton, which is bound at import time) so tests never share state
    via a stale unique constraint."""
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
    from app.models.db import Tenant
    t = Tenant(name="T1")
    db.add(t)
    db.commit()
    db.refresh(t)
    return t


@pytest.mark.asyncio
async def test_create_alert_persists_and_dispatch_is_best_effort(db_session, monkeypatch):
    monkeypatch.delenv("ALERT_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("ALERT_NTFY_URL", raising=False)
    monkeypatch.delenv("ALERT_SMTP_HOST", raising=False)
    monkeypatch.setattr(alert_service, "ALERT_WEBHOOK_URL", None)
    monkeypatch.setattr(alert_service, "ALERT_NTFY_URL", None)
    monkeypatch.setattr(alert_service, "ALERT_SMTP_HOST", None)

    tenant = _tenant(db_session)
    alert = await alert_service.create_alert(
        db_session, tenant.id, "CRITICAL_FINDING", "CRITICAL", "Test alert", detail="detail here",
    )
    assert alert.id
    assert alert.status == "OPEN"
    assert alert.dispatch_results["email"] == "skipped (not configured)"
    assert alert.dispatch_results["nats"] == "published"


@pytest.mark.asyncio
async def test_dispatch_failure_never_raises(db_session, monkeypatch):
    """A broken webhook must not prevent the alert from being created."""
    monkeypatch.setattr(alert_service, "ALERT_WEBHOOK_URL", "http://webhook.test/hook")

    import httpx
    import respx

    tenant = _tenant(db_session)
    with respx.mock:
        respx.post("http://webhook.test/hook").mock(side_effect=httpx.ConnectError("refused"))
        alert = await alert_service.create_alert(
            db_session, tenant.id, "DEVICE_COLLECTION_FAILURE", "HIGH", "Collection failed",
        )
    assert alert.id
    assert "failed" in alert.dispatch_results["webhook"]


@pytest.mark.asyncio
async def test_evaluate_scan_for_alerts_fires_expected_categories(db_session):
    from app.models.db import Device, Scan

    tenant = _tenant(db_session)
    device = Device(tenant_id=tenant.id, hostname="r1", vendor="cisco")
    db_session.add(device)
    db_session.commit()
    db_session.refresh(device)

    scan = Scan(
        tenant_id=tenant.id, device_id=device.id, framework="ALL",
        opa_decision="BLOCK", batfish_status="BATFISH_FAIL",
        risk_score=95, risk_level="CRITICAL", final_decision="BLOCK",
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)

    findings = [{"severity": "CRITICAL", "result": "FAIL", "control_id": "C1", "title": "Weak password policy"}]

    created = await alert_service.evaluate_scan_for_alerts(db_session, scan, findings)
    categories = {a.category for a in created}
    assert "CRITICAL_FINDING" in categories
    assert "HIGH_RISK" in categories
    assert "OPA_FAILURE" in categories
    assert "BATFISH_VIOLATION" in categories


@pytest.mark.asyncio
async def test_evaluate_scan_for_alerts_ai_unknown(db_session):
    from app.models.db import AIAnalysis, Device, Scan

    tenant = _tenant(db_session)
    device = Device(tenant_id=tenant.id, hostname="r2", vendor="juniper")
    db_session.add(device)
    db_session.commit()
    db_session.refresh(device)

    scan = Scan(tenant_id=tenant.id, device_id=device.id, framework="ALL", opa_decision="PASS",
                batfish_status="NOT_INTEGRATED", risk_level="LOW")
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)

    ai_row = AIAnalysis(
        scan_id=scan.id, device_id=device.id, tenant_id=tenant.id, raw_command_hash="abc",
        intent="UNKNOWN", classifier_confidence=0.2, semantic_similarity=0.3,
        decision="UNKNOWN", requires_review=True,
    )
    db_session.add(ai_row)
    db_session.commit()

    created = await alert_service.evaluate_scan_for_alerts(db_session, scan, [])
    categories = {a.category for a in created}
    assert "AI_UNKNOWN_CONFIGURATION" in categories
    assert "HIGH_RISK" not in categories
    assert "OPA_FAILURE" not in categories


def test_alerts_router_list_and_acknowledge(client):
    import asyncio

    from app.db import SessionLocal
    from app.models.db import Tenant

    db = SessionLocal()
    tenant = db.query(Tenant).filter(Tenant.name == "SIH-Demo").first()
    if not tenant:
        tenant = Tenant(name="SIH-Demo")
        db.add(tenant)
        db.commit()
        db.refresh(tenant)

    alert = asyncio.run(
        alert_service.create_alert(db, tenant.id, "DEVICE_COLLECTION_FAILURE", "HIGH", "Collection failed")
    )
    db.close()

    listed = client.get("/api/alerts")
    assert listed.status_code == 200
    body = listed.json()
    assert any(a["id"] == alert.id for a in body["alerts"])

    ack = client.post(f"/api/alerts/{alert.id}/acknowledge")
    assert ack.status_code == 200
    assert ack.json()["status"] == "ACKNOWLEDGED"
    assert ack.json()["acknowledged_by"]

    filtered = client.get("/api/alerts", params={"status": "OPEN"})
    assert alert.id not in [a["id"] for a in filtered.json()["alerts"]]


def test_viewer_can_list_but_not_acknowledge_alerts(client):
    """Section 11 RBAC audit fix: VIEWER is read-only. Listing stays open
    to every authenticated role, but acknowledging (a state mutation) must
    403 for VIEWER while remaining available to every other role."""
    import asyncio

    from app.auth.dependencies import CurrentUser, get_current_user
    from app.db import SessionLocal
    from app.main import app
    from app.models.db import Tenant

    db = SessionLocal()
    tenant = db.query(Tenant).filter(Tenant.name == "SIH-Demo").first()
    if not tenant:
        tenant = Tenant(name="SIH-Demo")
        db.add(tenant)
        db.commit()
        db.refresh(tenant)
    tenant_id = tenant.id
    alert = asyncio.run(
        alert_service.create_alert(db, tenant_id, "HIGH_RISK", "HIGH", "viewer test alert")
    )
    alert_id = alert.id
    db.close()

    def _viewer_user():
        return CurrentUser(subject="v1", username="viewer1", roles=["VIEWER"], tenant_id=tenant_id)

    app.dependency_overrides[get_current_user] = _viewer_user
    try:
        listed = client.get("/api/alerts")
        assert listed.status_code == 200

        ack = client.post(f"/api/alerts/{alert_id}/acknowledge")
        assert ack.status_code == 403
    finally:
        app.dependency_overrides.pop(get_current_user, None)

    # Sanity check the same alert IS acknowledgeable by a non-viewer role.
    def _analyst_user():
        return CurrentUser(subject="a1", username="analyst1", roles=["SECURITY_ANALYST"], tenant_id=tenant_id)

    app.dependency_overrides[get_current_user] = _analyst_user
    try:
        ack = client.post(f"/api/alerts/{alert_id}/acknowledge")
        assert ack.status_code == 200
        assert ack.json()["status"] == "ACKNOWLEDGED"
    finally:
        app.dependency_overrides.pop(get_current_user, None)


def test_alerts_tenant_isolation(client):
    import asyncio

    from app.db import SessionLocal
    from app.models.db import Tenant

    db = SessionLocal()
    other_tenant = Tenant(name="OtherTenant")
    db.add(other_tenant)
    db.commit()
    db.refresh(other_tenant)
    alert = asyncio.run(
        alert_service.create_alert(db, other_tenant.id, "HIGH_RISK", "HIGH", "not mine")
    )
    db.close()

    listed = client.get("/api/alerts")
    assert alert.id not in [a["id"] for a in listed.json()["alerts"]]

    ack = client.post(f"/api/alerts/{alert.id}/acknowledge")
    assert ack.status_code == 404