import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from app.auth import dependencies as deps_mod
from app.auth import jwt as jwt_mod
from app.services import openbao_service
from app.services.collectors.base import CollectionResult


@pytest.fixture(autouse=True)
def _demo_auth(monkeypatch):
    monkeypatch.setattr(jwt_mod, "AUTH_ENABLED", False)
    monkeypatch.setattr(deps_mod, "AUTH_ENABLED", False)
    monkeypatch.setattr(openbao_service, "OPENBAO_ENABLED", True)
    monkeypatch.setattr(openbao_service, "OPENBAO_ADDR", "http://openbao.test")
    monkeypatch.setattr(openbao_service, "OPENBAO_TOKEN", "test-token")
    yield


@pytest.fixture(autouse=True)
def _no_real_network(monkeypatch):
    """test_scan_endpoint_feeds_pipeline runs the full pipeline, which
    publishes NATS events (app.events.publish, a raw TCP client -- not
    intercepted by respx). The sandbox's egress firewall hangs rather than
    fast-refuses connections to hosts outside the allowlist, so NATS
    publishing must be stubbed here exactly as in test_alert_service.py."""
    async def _fake_publish(subject, payload):
        return None

    monkeypatch.setattr("app.events.publish", _fake_publish)
    yield


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test.db")
    monkeypatch.setenv("AI_ENABLED", "false")
    monkeypatch.setattr("app.services.batfish_service.BATFISH_ENABLED", False)
    from app.main import app

    with TestClient(app) as c:
        yield c


def _create_device_with_creds(client, vendor="cisco"):
    dev = client.post("/api/devices", json={"hostname": "r1", "vendor": vendor, "management_address": "10.0.0.1"})
    assert dev.status_code == 200
    device_id = dev.json()["id"]

    with respx.mock:
        respx.post(url__regex=r"http://openbao\.test/v1/secret/data/.*").mock(
            return_value=httpx.Response(200, json={"data": {"version": 1}})
        )
        cred = client.post(
            f"/api/devices/{device_id}/credentials",
            json={"credential_type": "ssh_password", "secret": {"username": "admin", "password": "x"}},
        )
    assert cred.status_code == 200
    return device_id


def test_collect_endpoint_success(client, monkeypatch):
    device_id = _create_device_with_creds(client)

    from app.routers import devices as devices_mod

    class _FakeCollector:
        transport = "ssh"

        def collect_config(self, device, credentials):
            return CollectionResult(success=True, vendor="cisco", hostname="r1", raw_config="hostname r1\n", transport="ssh")

    monkeypatch.setattr(devices_mod, "get_collector", lambda vendor, transport=None: _FakeCollector())

    with respx.mock:
        respx.get(url__regex=r"http://openbao\.test/v1/secret/data/.*").mock(
            return_value=httpx.Response(
                200,
                json={"data": {"data": {"credential_type": "ssh_password", "username": "admin", "password": "x"}}},
            )
        )
        resp = client.post(f"/api/devices/{device_id}/collect", json={})

    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    assert "x" not in resp.text  # password never present in response
    assert body["config_hash"]

    status = client.get(f"/api/devices/{device_id}/collection-status")
    assert status.json()["collection_status"] == "SUCCESS"


def test_collect_endpoint_no_credentials(client):
    dev = client.post("/api/devices", json={"hostname": "r2", "vendor": "cisco"})
    device_id = dev.json()["id"]
    resp = client.post(f"/api/devices/{device_id}/collect", json={})
    assert resp.status_code == 400


def test_scan_endpoint_feeds_pipeline(client, monkeypatch):
    device_id = _create_device_with_creds(client)

    from app.routers import devices as devices_mod

    sample_config = (
        "hostname r1\n"
        "service password-encryption\n"
        "no ip http server\n"
        "line vty 0 4\n transport input ssh\n"
    )

    class _FakeCollector:
        transport = "ssh"

        def collect_config(self, device, credentials):
            return CollectionResult(success=True, vendor="cisco", hostname="r1", raw_config=sample_config, transport="ssh")

    monkeypatch.setattr(devices_mod, "get_collector", lambda vendor, transport=None: _FakeCollector())

    import re
    with respx.mock:
        respx.get(url__regex=re.compile(r".*/v1/secret/data/.*")).mock(
            return_value=httpx.Response(
                200,
                json={"data": {"data": {"credential_type": "ssh_password", "username": "admin", "password": "x"}}},
            )
        )
        respx.post(url__regex=re.compile(r".*/v1/data/compliance/evaluate")).mock(
            return_value=httpx.Response(200, json={"result": {"decision": "PASS", "decision_id": "d1", "findings": []}})
        )
        respx.post(url__regex=re.compile(r".*/generate")).mock(
            return_value=httpx.Response(200, json={"response": "{}"})
        )
        resp = client.post(f"/api/devices/{device_id}/scan", json={})

    assert resp.status_code == 200
    body = resp.json()
    assert body["device_id"] == device_id
    assert "findings" in body
