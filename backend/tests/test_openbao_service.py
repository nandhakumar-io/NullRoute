import httpx
import pytest
import respx

from app.services import openbao_service


@pytest.fixture(autouse=True)
def _configure(monkeypatch):
    monkeypatch.setattr(openbao_service, "OPENBAO_ENABLED", True)
    monkeypatch.setattr(openbao_service, "OPENBAO_ADDR", "http://openbao.test")
    monkeypatch.setattr(openbao_service, "OPENBAO_TOKEN", "test-token")
    monkeypatch.setattr(openbao_service, "OPENBAO_MOUNT", "secret")
    monkeypatch.setattr(openbao_service, "OPENBAO_PATH_PREFIX", "netsec-auditor/devices")


@respx.mock
def test_store_and_get_roundtrip():
    ref = "dev-abc123"
    path = f"netsec-auditor/devices/tenant-a/{ref}"

    store_route = respx.post(f"http://openbao.test/v1/secret/data/{path}").mock(
        return_value=httpx.Response(200, json={"data": {"version": 1}})
    )
    openbao_service.store_device_credentials(
        "tenant-a", ref, "ssh_password", {"username": "admin", "password": "s3cr3t"}
    )
    assert store_route.called

    respx.get(f"http://openbao.test/v1/secret/data/{path}").mock(
        return_value=httpx.Response(
            200,
            json={"data": {"data": {"credential_type": "ssh_password", "username": "admin", "password": "s3cr3t"}}},
        )
    )
    creds = openbao_service.get_device_credentials("tenant-a", ref)
    assert creds.credential_type == "ssh_password"
    assert creds.secret == {"username": "admin", "password": "s3cr3t"}


@respx.mock
def test_get_missing_credentials_raises():
    ref = "dev-missing"
    path = f"netsec-auditor/devices/tenant-a/{ref}"
    respx.get(f"http://openbao.test/v1/secret/data/{path}").mock(return_value=httpx.Response(404))
    with pytest.raises(openbao_service.OpenBaoError):
        openbao_service.get_device_credentials("tenant-a", ref)


@respx.mock
def test_rotate_overwrites_secret():
    ref = "dev-rot"
    path = f"netsec-auditor/devices/tenant-a/{ref}"
    route = respx.post(f"http://openbao.test/v1/secret/data/{path}").mock(
        return_value=httpx.Response(200, json={"data": {"version": 2}})
    )
    openbao_service.rotate_device_credentials("tenant-a", ref, "ssh_password", {"password": "new-secret"})
    assert route.called


@respx.mock
def test_delete_credentials():
    ref = "dev-del"
    path = f"netsec-auditor/devices/tenant-a/{ref}"
    route = respx.delete(f"http://openbao.test/v1/secret/metadata/{path}").mock(return_value=httpx.Response(204))
    openbao_service.delete_device_credentials("tenant-a", ref)
    assert route.called


def test_disabled_raises():
    import app.services.openbao_service as mod

    mod.OPENBAO_ENABLED = False
    try:
        with pytest.raises(openbao_service.OpenBaoError):
            openbao_service.get_device_credentials("tenant-a", "ref")
    finally:
        mod.OPENBAO_ENABLED = True


def test_missing_token_raises(monkeypatch):
    monkeypatch.setattr(openbao_service, "OPENBAO_TOKEN", "")
    with pytest.raises(openbao_service.OpenBaoError):
        openbao_service.get_device_credentials("tenant-a", "ref")
