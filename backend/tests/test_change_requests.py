"""Phase 14 -- change requests + remediation.

Covers: creation runs the existing validator (mocked OPA, Batfish degrades
to BATFISH_UNAVAILABLE without a live coordinator -- exercised, not
mocked, since that's its own tested fallback path); approval/rejection
RBAC and status-transition guards; tenant isolation; and the remediation
suggestion endpoint never fabricating configuration.
"""
from __future__ import annotations

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from app.auth import dependencies as deps_mod
from app.auth import jwt as jwt_mod
from app.services import opa_service

OPA_EVAL_URL = f"{opa_service.OPA_URL}/v1/data/compliance/evaluate"


def _opa_body(decision, findings=None):
    findings = findings if findings is not None else []
    return {
        "result": {
            "decision": decision,
            "findings": findings,
            "violations": [f for f in findings if f["result"] == "FAIL"],
            "evaluated_controls": [f["control_id"] for f in findings],
            "policy_version": "1.0.0",
        }
    }


@pytest.fixture(autouse=True)
def _demo_auth(monkeypatch):
    monkeypatch.setattr(jwt_mod, "AUTH_ENABLED", False)
    monkeypatch.setattr(deps_mod, "AUTH_ENABLED", False)
    yield


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test.db")
    monkeypatch.setenv("AI_ENABLED", "false")
    monkeypatch.setattr("app.services.batfish_service.BATFISH_ENABLED", False)
    from app.main import app

    with TestClient(app) as c:
        yield c


def _create_device(client, vendor="cisco"):
    resp = client.post("/api/devices", json={"hostname": "r1", "vendor": vendor})
    assert resp.status_code == 200
    return resp.json()["id"]


def test_create_change_request_runs_existing_validator(client):
    device_id = _create_device(client)

    with respx.mock:
        respx.post(OPA_EVAL_URL).mock(return_value=httpx.Response(200, json=_opa_body("PASS")))
        resp = client.post("/api/change-requests", json={
            "device_id": device_id,
            "proposed_config": "hostname r1\nno ip http server\n",
        })

    assert resp.status_code == 200
    body = resp.json()
    print(body)
    assert body["status"] == "PENDING_APPROVAL"
    assert body["opa_decision"] == "PASS"
    assert body["final_decision"] == "PASS"
    assert body["proposed_config_hash"]
    # Batfish has no live coordinator in the test sandbox -- must degrade
    # explicitly, never silently report PASS (RULE 13).
    assert body["batfish_status"] in ("BATFISH_UNAVAILABLE", "BATFISH_UNSUPPORTED", "NOT_INTEGRATED")


def test_change_request_opa_block_still_requires_approval_not_auto_rejected(client):
    """A BLOCK-worthy proposed config still lands in PENDING_APPROVAL --
    the validator informs the decision, but a human always makes the
    approve/reject call (RULE 5)."""
    device_id = _create_device(client)
    critical_fail = {
        "control_id": "CIS-TELNET-001", "framework": "CIS", "title": "Telnet disabled",
        "severity": "CRITICAL", "parameter": "management.telnet.enabled",
        "expected": False, "actual": True, "result": "FAIL", "reason": "telnet on",
        "remediation": "disable telnet",
    }

    with respx.mock:
        respx.post(OPA_EVAL_URL).mock(return_value=httpx.Response(200, json=_opa_body("BLOCK", [critical_fail])))
        resp = client.post("/api/change-requests", json={
            "device_id": device_id,
            "proposed_config": "hostname r1\ntransport input telnet\n",
        })

    body = resp.json()
    assert body["status"] == "PENDING_APPROVAL"
    assert body["opa_decision"] == "BLOCK"
    assert body["final_decision"] == "BLOCK"


def test_approve_records_approver_and_timestamp(client):
    device_id = _create_device(client)
    with respx.mock:
        respx.post(OPA_EVAL_URL).mock(return_value=httpx.Response(200, json=_opa_body("PASS")))
        cr = client.post("/api/change-requests", json={
            "device_id": device_id, "proposed_config": "hostname r1\n",
        }).json()

    resp = client.post(f"/api/change-requests/{cr['id']}/approve")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "APPROVED"
    assert body["approved_by"]
    assert body["approved_at"]


def test_reject_records_reason(client):
    device_id = _create_device(client)
    with respx.mock:
        respx.post(OPA_EVAL_URL).mock(return_value=httpx.Response(200, json=_opa_body("PASS")))
        cr = client.post("/api/change-requests", json={
            "device_id": device_id, "proposed_config": "hostname r1\n",
        }).json()

    resp = client.post(f"/api/change-requests/{cr['id']}/reject", json={"reason": "not needed right now"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "REJECTED"
    assert body["rejection_reason"] == "not needed right now"


def test_cannot_approve_twice(client):
    device_id = _create_device(client)
    with respx.mock:
        respx.post(OPA_EVAL_URL).mock(return_value=httpx.Response(200, json=_opa_body("PASS")))
        cr = client.post("/api/change-requests", json={
            "device_id": device_id, "proposed_config": "hostname r1\n",
        }).json()

    first = client.post(f"/api/change-requests/{cr['id']}/approve")
    assert first.status_code == 200
    second = client.post(f"/api/change-requests/{cr['id']}/approve")
    assert second.status_code == 409


def test_tenant_isolation_for_change_requests(client, monkeypatch):
    from app.db import SessionLocal
    from app.models.db import ChangeRequest, Device, Tenant

    device_id = _create_device(client)

    db = SessionLocal()
    other_tenant = Tenant(name="OtherCRTenant")
    db.add(other_tenant)
    db.commit()
    db.refresh(other_tenant)
    other_device = Device(tenant_id=other_tenant.id, hostname="foreign", vendor="cisco")
    db.add(other_device)
    db.commit()
    db.refresh(other_device)
    foreign_cr = ChangeRequest(
        tenant_id=other_tenant.id, device_id=other_device.id,
        proposed_config_hash="deadbeef", status="PENDING_APPROVAL",
    )
    db.add(foreign_cr)
    db.commit()
    db.refresh(foreign_cr)
    foreign_cr_id = foreign_cr.id
    db.close()

    resp = client.get(f"/api/change-requests/{foreign_cr_id}")
    assert resp.status_code == 404

    listed = client.get("/api/change-requests")
    assert foreign_cr_id not in [c["id"] for c in listed.json()["change_requests"]]


def test_remediation_suggestions_never_invents_config(client):
    from app.db import SessionLocal
    from app.models.db import Finding, Scan

    device_id = _create_device(client)
    db = SessionLocal()
    from app.models.db import Device
    device = db.query(Device).filter(Device.id == device_id).first()
    scan = Scan(tenant_id=device.tenant_id, device_id=device_id, framework="CIS", status="completed")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    db.add(Finding(
        scan_id=scan.id, framework="CIS", control_id="CIS-TELNET-001", title="Telnet disabled",
        severity="CRITICAL", expected_value="False", actual_value="True", result="FAIL",
        parameter="management.telnet.enabled", remediation="Disable telnet; use SSH only.",
    ))
    db.commit()
    scan_id = scan.id
    db.close()

    resp = client.get(f"/api/scans/{scan_id}/remediation-suggestions")
    assert resp.status_code == 200
    body = resp.json()
    assert body["finding_count"] == 1
    assert body["suggestions"][0]["guidance"] == "Disable telnet; use SSH only."
    assert "not generated configuration" in body["note"]