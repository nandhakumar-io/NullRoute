"""Regression test for a cross-tenant evidence leak: routers/evidence.py
previously queried EvidenceRecord (list/get/history/verify/simulate-tamper/
restore) without filtering by tenant_id at all, so any authenticated user
could read -- and even tamper with -- another tenant's evidence purely by
guessing/enumerating an evidence_id. evidence_service.get_evidence/
get_evidence_history already accepted an optional tenant_id filter; the
router just never passed it. Fixed by threading get_current_tenant()
through every evidence endpoint (RULE 19: tenant A cannot access tenant
B's evidence)."""
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


def _make_other_tenant_evidence(client):
    """Directly inserts an EvidenceRecord for a tenant OTHER than the
    demo-auth SIH-Demo tenant every request in `client` authenticates as."""
    from app.db import SessionLocal
    from app.models.db import EvidenceRecord, Scan, Tenant

    db = SessionLocal()
    try:
        other_tenant = Tenant(name="OtherTenant")
        db.add(other_tenant)
        db.commit()
        db.refresh(other_tenant)

        scan = Scan(tenant_id=other_tenant.id, device_id="dev-x", status="completed")
        db.add(scan)
        db.commit()
        db.refresh(scan)

        record = EvidenceRecord(
            evidence_id="ev-other-tenant-1",
            scan_id=scan.id,
            device_id="dev-x",
            tenant_id=other_tenant.id,
            evidence_json={"final_decision": "PASS"},
            evidence_hash="deadbeef",
            final_decision="PASS",
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record.evidence_id
    finally:
        db.close()


def test_list_evidence_excludes_other_tenant(client):
    evidence_id = _make_other_tenant_evidence(client)
    resp = client.get("/api/evidence")
    assert resp.status_code == 200
    ids = [e["evidence_id"] for e in resp.json()]
    assert evidence_id not in ids


def test_get_evidence_404s_for_other_tenant(client):
    evidence_id = _make_other_tenant_evidence(client)
    resp = client.get(f"/api/evidence/{evidence_id}")
    assert resp.status_code == 404


def test_verify_evidence_404s_for_other_tenant(client):
    evidence_id = _make_other_tenant_evidence(client)
    resp = client.post(f"/api/evidence/{evidence_id}/verify")
    assert resp.status_code == 404


def test_simulate_tamper_404s_for_other_tenant(client):
    evidence_id = _make_other_tenant_evidence(client)
    resp = client.post(f"/api/evidence/{evidence_id}/simulate-tamper")
    assert resp.status_code == 404
