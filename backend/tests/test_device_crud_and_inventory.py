"""Device CRUD + inventory tests.

NOTE ON PROVENANCE: the file this replaces (tests/test_device_crud_and_inventory.py)
contained a near-verbatim copy of app/routers/devices.py's source code with
no `def test_*` functions in it at all -- pytest collected it but it
exercised nothing. That is likely why the CRUD regressions reported against
this router (duplicate devices on re-add, bulk delete 404ing) shipped
unnoticed. This file replaces it with real tests against the actual HTTP
API, covering the specific bugs that were found and fixed:
  - POST /api/devices/bulk/delete didn't exist (frontend called it, 404)
  - Re-submitting "Add Device" with the same management_address silently
    created a second device row
  - DELETE /api/devices/{id} cascades dependent rows without FK violations
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
    from app.main import app

    with TestClient(app) as c:
        yield c


def test_create_device_basic(client):
    resp = client.post("/api/devices", json={"hostname": "sw1", "management_address": "10.0.0.1", "vendor": "cisco"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["hostname"] == "sw1"
    assert body["management_address"] == "10.0.0.1"
    assert body["enabled"] is True


def test_create_device_duplicate_management_address_rejected(client):
    """Regression test: re-submitting Add Device with the same management
    IP (double-click, retried request, re-importing the same discovered
    host) must not create a second inventory row."""
    first = client.post("/api/devices", json={"hostname": "sw1", "management_address": "10.0.0.5"})
    assert first.status_code == 200

    dup = client.post("/api/devices", json={"hostname": "sw1-again", "management_address": "10.0.0.5"})
    assert dup.status_code == 409

    listed = client.get("/api/devices")
    matches = [d for d in listed.json()["items"] if d["management_address"] == "10.0.0.5"]
    assert len(matches) == 1


def test_create_device_without_management_address_not_blocked_by_dedup(client):
    # Devices with no management_address (e.g. purely config-upload-driven)
    # must not collide with each other via the dedup check.
    r1 = client.post("/api/devices", json={"hostname": "a"})
    r2 = client.post("/api/devices", json={"hostname": "b"})
    assert r1.status_code == 200
    assert r2.status_code == 200


def test_update_device(client):
    created = client.post("/api/devices", json={"hostname": "sw1", "site": "hq"}).json()
    resp = client.patch(f"/api/devices/{created['id']}", json={"site": "branch-1"})
    assert resp.status_code == 200
    assert resp.json()["site"] == "branch-1"


def test_delete_device(client):
    created = client.post("/api/devices", json={"hostname": "sw1"}).json()
    device_id = created["id"]

    resp = client.delete(f"/api/devices/{device_id}")
    assert resp.status_code == 204

    listed = client.get("/api/devices").json()["items"]
    assert all(d["id"] != device_id for d in listed)

    # Deleting again is a clean 404, not a 500 -- the row is really gone.
    assert client.delete(f"/api/devices/{device_id}").status_code == 404


def test_delete_device_after_recreate_with_same_address_does_not_duplicate(client):
    """The combination of the two bugs: delete a device, then re-add one
    with the same management address -- must succeed exactly once, not
    leave the old row behind or create two."""
    created = client.post("/api/devices", json={"hostname": "sw1", "management_address": "10.0.0.9"}).json()
    client.delete(f"/api/devices/{created['id']}")

    recreated = client.post("/api/devices", json={"hostname": "sw1-new", "management_address": "10.0.0.9"})
    assert recreated.status_code == 200

    listed = client.get("/api/devices").json()["items"]
    matches = [d for d in listed if d["management_address"] == "10.0.0.9"]
    assert len(matches) == 1
    assert matches[0]["hostname"] == "sw1-new"


def test_bulk_delete_devices(client):
    """Regression test: POST /api/devices/bulk/delete previously did not
    exist on the backend at all -- the frontend called it and always got a
    404, so bulk delete silently did nothing from the user's perspective."""
    ids = []
    for i in range(3):
        d = client.post("/api/devices", json={"hostname": f"sw{i}", "management_address": f"10.0.1.{i}"}).json()
        ids.append(d["id"])

    resp = client.post("/api/devices/bulk/delete", json={"device_ids": ids})
    assert resp.status_code == 200
    body = resp.json()
    assert body["requested"] == 3
    assert body["affected"] == 3
    assert sorted(body["device_ids"]) == sorted(ids)

    remaining = client.get("/api/devices").json()["items"]
    assert all(d["id"] not in ids for d in remaining)


def test_bulk_delete_skips_unknown_ids_without_erroring(client):
    d = client.post("/api/devices", json={"hostname": "sw1"}).json()
    resp = client.post("/api/devices/bulk/delete", json={"device_ids": [d["id"], "does-not-exist"]})
    assert resp.status_code == 200
    body = resp.json()
    assert body["requested"] == 2
    assert body["affected"] == 1
    assert body["device_ids"] == [d["id"]]


def test_bulk_enable_disable(client):
    d = client.post("/api/devices", json={"hostname": "sw1"}).json()
    assert client.post("/api/devices/bulk/disable", json={"device_ids": [d["id"]]}).status_code == 200
    assert client.get(f"/api/devices/{d['id']}/collection-status").json()["enabled"] is False
    assert client.post("/api/devices/bulk/enable", json={"device_ids": [d["id"]]}).status_code == 200
    assert client.get(f"/api/devices/{d['id']}/collection-status").json()["enabled"] is True