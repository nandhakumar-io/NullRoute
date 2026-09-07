"""Phase 10 follow-up: CURRENT-vs-PROPOSED Batfish snapshot diff, wired
into the Change Request flow (change_request_service.create_and_validate).

Covers:
  - No prior known config -> snapshot diff is skipped entirely
    (change_impact_status stays NOT_CHECKED, snapshot_diff is None) --
    RULE 13 still holds (nothing is reported as a pass by omission).
  - A prior known config + a diff that finds a behavioral change
    (BATFISH_FAIL) -> snapshot_diff is persisted on the ChangeRequest and
    the final decision is escalated to REVIEW (never silently PASSed,
    never itself a second BLOCK authority -- see change_validation_
    service.correlate()).
  - The snapshot diff raising is caught and recorded as BATFISH_ERROR
    without ever blocking change-request creation (best-effort, matches
    the rest of the Batfish integration's failure discipline).
"""
from __future__ import annotations

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from app.auth import dependencies as deps_mod
from app.auth import jwt as jwt_mod
from app.services import batfish_service, change_request_service, opa_service

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
    # Single-snapshot Batfish analysis stays disabled/degraded as in the
    # existing change-request tests -- this file is only exercising the
    # separate CURRENT-vs-PROPOSED diff path, which is monkeypatched
    # directly per-test rather than requiring a live coordinator.
    monkeypatch.setattr("app.services.batfish_service.BATFISH_ENABLED", False)
    from app.main import app

    with TestClient(app) as c:
        yield c


def _create_device(client, vendor="cisco"):
    resp = client.post("/api/devices", json={"hostname": "r1", "vendor": vendor})
    assert resp.status_code == 200
    return resp.json()["id"]


def test_no_prior_config_skips_snapshot_diff(client):
    """No prior scan for this device -> latest_known_config() returns None
    -> the snapshot-diff branch never runs at all."""
    device_id = _create_device(client)

    with respx.mock:
        respx.post(OPA_EVAL_URL).mock(return_value=httpx.Response(200, json=_opa_body("PASS")))
        resp = client.post("/api/change-requests", json={
            "device_id": device_id,
            "proposed_config": "hostname r1\nno ip http server\n",
        })

    assert resp.status_code == 200
    body = resp.json()
    assert body["snapshot_diff"] is None
    assert body["validation_detail"]["change_impact_status"] == "NOT_CHECKED"
    assert body["final_decision"] == "PASS"


def test_snapshot_diff_behavioral_change_escalates_to_review(client, monkeypatch):
    """A prior known config exists and the CURRENT-vs-PROPOSED diff finds a
    behavioral change (BATFISH_FAIL) -> stored on the CR and the final
    decision is escalated to REVIEW even though OPA alone said PASS."""
    device_id = _create_device(client)

    # The `client` fixture disables single-snapshot Batfish analysis
    # (BATFISH_ENABLED=False) to match the rest of the change-request
    # test suite; the diff path this test targets is gated on the same
    # flag, so it needs to be re-enabled here specifically.
    monkeypatch.setattr(batfish_service, "BATFISH_ENABLED", True)
    # Force a "prior known config" without needing a real scan/MinIO round
    # trip -- this isolates the test to the snapshot-diff wiring itself.
    monkeypatch.setattr(
        change_request_service, "latest_known_config",
        lambda db, device_id: "hostname r1\nvlan 10\n name GUEST\n",
    )

    fake_diff = {
        "status": "BATFISH_FAIL",
        "network_name": "scan-cr-fake",
        "current_snapshot": "current-cr-fake",
        "proposed_snapshot": "proposed-cr-fake",
        "node_delta": {"added": [], "removed": []},
        "route_delta": {"current_count": 4, "proposed_count": 4, "count_delta": 0},
        "differential_reachability": {"status": "BATFISH_PASS", "changed_flow_count": 3, "sample": []},
    }
    monkeypatch.setattr(batfish_service, "compare_network_snapshots", lambda **kwargs: fake_diff)

    with respx.mock:
        respx.post(OPA_EVAL_URL).mock(return_value=httpx.Response(200, json=_opa_body("PASS")))
        resp = client.post("/api/change-requests", json={
            "device_id": device_id,
            "proposed_config": "hostname r1\nvlan 10\n name GUEST\ninterface Vlan10\n ip access-group MGMT-ACL in\n",
        })

    assert resp.status_code == 200
    body = resp.json()
    assert body["opa_decision"] == "PASS"
    # OPA alone would have passed this -- the behavioral diff is what
    # pushes the final decision to REVIEW instead of PASS.
    assert body["final_decision"] == "REVIEW"
    assert "reachability" in body["final_reason"].lower()
    assert body["snapshot_diff"]["status"] == "BATFISH_FAIL"
    assert body["snapshot_diff"]["differential_reachability"]["changed_flow_count"] == 3
    assert body["validation_detail"]["change_impact_status"] == "BATFISH_FAIL"
    # Still requires human approval either way (RULE 5) -- REVIEW never
    # auto-blocks or auto-approves the change request itself.
    assert body["status"] == "PENDING_APPROVAL"


def test_snapshot_diff_exception_recorded_as_error_never_blocks_creation(client, monkeypatch):
    """If compare_network_snapshots raises, the change request must still
    be created (best-effort diff, matches the rest of the Batfish
    integration's failure discipline) with change_impact recorded as
    BATFISH_ERROR rather than silently treated as "no change"."""
    device_id = _create_device(client)
    monkeypatch.setattr(batfish_service, "BATFISH_ENABLED", True)
    monkeypatch.setattr(
        change_request_service, "latest_known_config",
        lambda db, device_id: "hostname r1\n",
    )

    def _boom(**kwargs):
        raise RuntimeError("batfish coordinator exploded")

    monkeypatch.setattr(batfish_service, "compare_network_snapshots", _boom)

    with respx.mock:
        respx.post(OPA_EVAL_URL).mock(return_value=httpx.Response(200, json=_opa_body("PASS")))
        resp = client.post("/api/change-requests", json={
            "device_id": device_id,
            "proposed_config": "hostname r1\nno ip http server\n",
        })

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "PENDING_APPROVAL"
    assert body["validation_detail"]["change_impact_status"] == "BATFISH_ERROR"
    assert body["snapshot_diff"]["status"] == "BATFISH_ERROR"