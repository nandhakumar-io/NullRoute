"""Regression test for the dataset-level HITL approval gate.

Before this fix, dataset_service.create_dataset_version() only ever
snapshotted TrainingExample rows with validation_status == "VALIDATED",
but nothing set that status after hitl_service created them (default
PENDING) -- so a human's correction of an unknown command would go
through review_mapping(), a TrainingExample would be written, and it
would then sit invisible forever: no dataset would ever include it, and
no training job built from that dataset would ever see it. The reviewer
had no endpoint to promote it to VALIDATED at all.

This test exercises the real HTTP path end-to-end: submit an unknown
command -> correct it via POST /api/training/{id}/review -> confirm it
does NOT show up in a freshly compiled dataset (still PENDING) -> list
it via GET /api/training/examples -> validate it via POST
/api/training/examples/{id}/validate -> confirm a new dataset snapshot
now includes it.
"""
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


def _make_pending_mapping(raw_pattern="banner motd unique-marker-for-this-test"):
    from app.db import SessionLocal
    from app.models.db import CommandMapping

    db = SessionLocal()
    try:
        mapping = CommandMapping(
            tenant_id=None,
            vendor="cisco_ios",
            raw_command_pattern=raw_pattern,
            normalized_parameter="unknown",
            example_value=None,
            ai_suggested_meaning="unclear",
            confidence=0.3,
            status="pending",
        )
        db.add(mapping)
        db.commit()
        db.refresh(mapping)
        return mapping.id
    finally:
        db.close()


def test_corrected_example_excluded_until_validated_then_included(client):
    mapping_id = _make_pending_mapping()

    # Human corrects the unknown command.
    resp = client.post(
        f"/api/training/{mapping_id}/review",
        json={
            "action": "correct",
            "normalized_parameter": "management.banner_configured",
            "normalized_facts": {"facts": [{"parameter": "management.banner_configured", "value": "true"}]},
            "correction_reason": "AI could not classify this banner variant",
        },
    )
    assert resp.status_code == 200, resp.text

    # It should show up in the PENDING training-examples queue...
    pending = client.get("/api/training/examples", params={"status": "PENDING"}).json()
    assert len(pending) == 1
    example_id = pending[0]["id"]
    assert pending[0]["human_action"] == "CORRECTED"
    assert pending[0]["validation_status"] == "PENDING"

    # ...but a dataset compiled right now must NOT include it (this is the
    # bug: previously nothing ever flipped it to VALIDATED, so it would be
    # silently excluded forever).
    dv_before = client.post("/api/ai/datasets", params={"version_label": "before-validate"}).json()
    assert dv_before["example_count"] == 0

    # Reviewer validates it via the new second-gate endpoint.
    validate_resp = client.post(f"/api/training/examples/{example_id}/validate")
    assert validate_resp.status_code == 200, validate_resp.text
    assert validate_resp.json()["validation_status"] == "VALIDATED"

    # No longer in the PENDING queue.
    pending_after = client.get("/api/training/examples", params={"status": "PENDING"}).json()
    assert pending_after == []

    # A fresh dataset snapshot now picks it up.
    dv_after = client.post("/api/ai/datasets", params={"version_label": "after-validate"}).json()
    assert dv_after["example_count"] == 1


def test_bulk_validate_and_exclude(client):
    id_a = _make_pending_mapping("no ip http server unique-a")
    id_b = _make_pending_mapping("logging trap informational unique-b")

    for mid in (id_a, id_b):
        r = client.post(f"/api/training/{mid}/review", json={"action": "approve"})
        assert r.status_code == 200, r.text

    pending = client.get("/api/training/examples", params={"status": "PENDING", "human_action": "APPROVED"}).json()
    assert len(pending) == 2
    ex_ids = [e["id"] for e in pending]

    bulk_resp = client.post("/api/training/examples/bulk-validate", json=ex_ids)
    assert bulk_resp.status_code == 200, bulk_resp.text
    assert bulk_resp.json()["validated_count"] == 2

    dv = client.post("/api/ai/datasets", params={"version_label": "bulk-validated"}).json()
    assert dv["example_count"] == 2

    # Exclude one example from a later snapshot: re-run a mapping and
    # explicitly exclude its resulting example.
    id_c = _make_pending_mapping("service tcp-keepalives-in unique-c")
    r = client.post(f"/api/training/{id_c}/review", json={"action": "approve"})
    assert r.status_code == 200
    pending_c = client.get(
        "/api/training/examples", params={"status": "PENDING", "human_action": "APPROVED"}
    ).json()
    assert len(pending_c) == 1
    exclude_resp = client.post(f"/api/training/examples/{pending_c[0]['id']}/exclude")
    assert exclude_resp.status_code == 200
    assert exclude_resp.json()["validation_status"] == "EXCLUDED"

    excluded = client.get("/api/training/examples", params={"status": "EXCLUDED"}).json()
    assert len(excluded) == 1