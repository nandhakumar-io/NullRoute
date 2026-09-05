import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from app.auth import dependencies as deps_mod
from app.auth import jwt as jwt_mod
from app.services import openbao_service


@pytest.fixture(autouse=True)
def _demo_auth(monkeypatch):
    monkeypatch.setattr(jwt_mod, "AUTH_ENABLED", False)
    monkeypatch.setattr(deps_mod, "AUTH_ENABLED", False)
    monkeypatch.setattr(openbao_service, "OPENBAO_ENABLED", True)
    monkeypatch.setattr(openbao_service, "OPENBAO_ADDR", "http://openbao.test")
    monkeypatch.setattr(openbao_service, "OPENBAO_TOKEN", "test-token")
    yield


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test.db")
    from app.main import app

    with TestClient(app) as c:
        yield c


@respx.mock
def test_create_credential_ref_never_returns_secret(client):
    dev = client.post("/api/devices", json={"hostname": "r1", "vendor": "cisco"})
    assert dev.status_code == 200
    device_id = dev.json()["id"]

    respx.post(url__regex=r"http://openbao\.test/v1/secret/data/.*").mock(
        return_value=httpx.Response(200, json={"data": {"version": 1}})
    )

    resp = client.post(
        f"/api/devices/{device_id}/credentials",
        json={"credential_type": "ssh_password", "secret": {"username": "admin", "password": "hunter2"}},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "hunter2" not in resp.text
    assert "secret" not in body
    assert "password" not in body
    assert body["credential_type"] == "ssh_password"
    assert body["credential_ref"].startswith("dev-")


def test_invalid_credential_type_rejected(client):
    dev = client.post("/api/devices", json={"hostname": "r2", "vendor": "juniper"})
    device_id = dev.json()["id"]
    resp = client.post(
        f"/api/devices/{device_id}/credentials",
        json={"credential_type": "totally_invalid", "secret": {"password": "x"}},
    )
    assert resp.status_code == 422
