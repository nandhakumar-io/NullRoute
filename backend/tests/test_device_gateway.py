import time

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


@pytest.fixture(autouse=True)
def _no_real_nats(monkeypatch):
    async def _fake_publish(subject, payload):
        return None

    monkeypatch.setattr("app.events.publish", _fake_publish)
    yield


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test.db")
    monkeypatch.setenv("AI_ENABLED", "false")
    monkeypatch.setenv("GATEWAY_MOCK_CONNECTOR", "true")
    monkeypatch.setenv("JOB_SIGNING_SECRET", "test-signing-secret")
    from app.main import app

    with TestClient(app) as c:
        yield c


def _create_device_with_creds(client, vendor="mock"):
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


def _openbao_get_mock():
    return respx.get(url__regex=r"http://openbao\.test/v1/secret/data/.*").mock(
        return_value=httpx.Response(
            200,
            json={"data": {"data": {"credential_type": "ssh_password", "username": "admin", "password": "x"}}},
        )
    )


# ---------------------------------------------------------------------------
# API-level end-to-end: audit request -> signed envelope -> gateway ->
# mocked connector -> normalized result.
# ---------------------------------------------------------------------------

def test_audit_device_end_to_end_success(client):
    device_id = _create_device_with_creds(client)
    with respx.mock:
        _openbao_get_mock()
        resp = client.post(f"/api/devices/{device_id}/audit")
    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    assert body["device_id"] == device_id
    assert "job_id" in body
    assert body["normalized_data"]["vendor"] == "mock"
    # No secret material anywhere in the response.
    assert "password" not in str(body)
    assert "x" != body.get("secret")


def test_gateway_metrics_endpoint_reflects_activity(client):
    device_id = _create_device_with_creds(client)
    with respx.mock:
        _openbao_get_mock()
        client.post(f"/api/devices/{device_id}/audit")
    metrics_resp = client.get("/api/devices/gateway/metrics")
    assert metrics_resp.status_code == 200
    m = metrics_resp.json()
    assert m["jobs_received"] >= 1
    assert m["jobs_completed"] >= 1
    assert "password" not in str(m)


def test_supported_operations_endpoint(client):
    resp = client.get("/api/devices/gateway/operations")
    assert resp.status_code == 200
    ops = resp.json()["read_only_operations"]
    assert set(ops) == {"AUDIT", "FETCH_CONFIG", "GET_FACTS", "GET_VERSION", "GET_INTERFACES", "GET_NEIGHBORS"}


# ---------------------------------------------------------------------------
# Unit-level: envelope signing/verification.
# ---------------------------------------------------------------------------

from app.gateway.envelope import build_envelope, verify_signature, sign  # noqa: E402


def test_valid_signed_envelope_verifies():
    env = build_envelope("t1", "u1", "d1", "AUDIT", "mock", secret="s3cret")
    assert verify_signature(env, secret="s3cret") is True


def test_tampered_field_invalidates_signature():
    env = build_envelope("t1", "u1", "d1", "AUDIT", "mock", secret="s3cret")
    env.device_id = "d2"  # tamper after signing
    assert verify_signature(env, secret="s3cret") is False


def test_wrong_secret_invalidates_signature():
    env = build_envelope("t1", "u1", "d1", "AUDIT", "mock", secret="s3cret")
    assert verify_signature(env, secret="wrong-secret") is False


def test_missing_signature_fails():
    env = build_envelope("t1", "u1", "d1", "AUDIT", "mock", secret="s3cret")
    env.signature = ""
    assert verify_signature(env, secret="s3cret") is False


# ---------------------------------------------------------------------------
# Unit-level: validator security matrix (Part 13 "DEVICE GATEWAY" list).
# ---------------------------------------------------------------------------

from app.db import get_session_local, init_db  # noqa: E402
from app.gateway.errors import GatewayError, GatewayErrorCode  # noqa: E402
from app.gateway.validator import validate_envelope  # noqa: E402
from app.models.db import Device, GatewayJobRecord, Tenant  # noqa: E402

SECRET = "unit-test-secret"


@pytest.fixture
def db_session(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/unit.db")
    init_db()
    session = get_session_local()()
    yield session
    session.close()


@pytest.fixture
def tenant_and_device(db_session):
    tenant = Tenant(name="acme")
    db_session.add(tenant)
    db_session.commit()
    device = Device(tenant_id=tenant.id, hostname="r1", vendor="mock")
    db_session.add(device)
    db_session.commit()
    return tenant, device


def _env(tenant, device, **overrides):
    kwargs = dict(
        tenant_id=tenant.id, requester_id="user-1", device_id=device.id,
        operation="AUDIT", protocol="ssh", secret=SECRET,
    )
    kwargs.update(overrides)
    return build_envelope(**kwargs)


def test_validate_valid_signed_job(db_session, tenant_and_device):
    tenant, device = tenant_and_device
    result = validate_envelope(db_session, _env(tenant, device), secret=SECRET)
    assert result.id == device.id


def test_validate_invalid_signature(db_session, tenant_and_device):
    tenant, device = tenant_and_device
    env = _env(tenant, device)
    env.operation = "FETCH_CONFIG"  # tamper post-sign
    with pytest.raises(GatewayError) as exc:
        validate_envelope(db_session, env, secret=SECRET)
    assert exc.value.code == GatewayErrorCode.INVALID_JOB_SIGNATURE


def test_validate_expired_job(db_session, tenant_and_device):
    tenant, device = tenant_and_device
    env = _env(tenant, device, ttl_seconds=-10)
    with pytest.raises(GatewayError) as exc:
        validate_envelope(db_session, env, secret=SECRET)
    assert exc.value.code == GatewayErrorCode.EXPIRED_JOB


def test_validate_replayed_job(db_session, tenant_and_device):
    tenant, device = tenant_and_device
    env = _env(tenant, device)
    validate_envelope(db_session, env, secret=SECRET)
    db_session.add(GatewayJobRecord(
        job_id=env.job_id, nonce=env.nonce, tenant_id=tenant.id, requester_id="user-1",
        device_id=device.id, operation="AUDIT", protocol="ssh", status="VALIDATED",
    ))
    db_session.commit()
    with pytest.raises(GatewayError) as exc:
        validate_envelope(db_session, env, secret=SECRET)
    assert exc.value.code == GatewayErrorCode.REPLAYED_JOB


def test_validate_tenant_mismatch(db_session, tenant_and_device):
    tenant, device = tenant_and_device
    env = _env(tenant, device, tenant_id="does-not-exist")
    with pytest.raises(GatewayError) as exc:
        validate_envelope(db_session, env, secret=SECRET)
    assert exc.value.code == GatewayErrorCode.TENANT_MISMATCH


def test_validate_unauthorized_device_cross_tenant(db_session, tenant_and_device):
    tenant, device = tenant_and_device
    other_tenant = Tenant(name="other")
    db_session.add(other_tenant)
    db_session.commit()
    env = _env(tenant, device, tenant_id=other_tenant.id)
    with pytest.raises(GatewayError) as exc:
        validate_envelope(db_session, env, secret=SECRET)
    # device belongs to `tenant`, not `other_tenant` -> looked up and not found
    assert exc.value.code == GatewayErrorCode.DEVICE_NOT_FOUND


def test_validate_self_approval_rejected_for_privileged_op(db_session, tenant_and_device):
    tenant, device = tenant_and_device
    env = build_envelope(
        tenant_id=tenant.id, requester_id="user-1", device_id=device.id,
        operation="WRITE", protocol="ssh", approval_id="user-1", secret=SECRET,
    )
    with pytest.raises(GatewayError) as exc:
        validate_envelope(db_session, env, secret=SECRET)
    assert exc.value.code == GatewayErrorCode.APPROVAL_INVALID


def test_validate_missing_approval_for_privileged_op(db_session, tenant_and_device):
    tenant, device = tenant_and_device
    env = build_envelope(
        tenant_id=tenant.id, requester_id="user-1", device_id=device.id,
        operation="WRITE", protocol="ssh", secret=SECRET,
    )
    with pytest.raises(GatewayError) as exc:
        validate_envelope(db_session, env, secret=SECRET)
    assert exc.value.code == GatewayErrorCode.APPROVAL_REQUIRED


def test_validate_invalid_operation(db_session, tenant_and_device):
    tenant, device = tenant_and_device
    env = _env(tenant, device, operation="DELETE_EVERYTHING")
    with pytest.raises(GatewayError) as exc:
        validate_envelope(db_session, env, secret=SECRET)
    assert exc.value.code == GatewayErrorCode.OPERATION_UNSUPPORTED


def test_validate_unsupported_protocol(db_session, tenant_and_device):
    tenant, device = tenant_and_device
    env = _env(tenant, device, protocol="telnet")
    with pytest.raises(GatewayError) as exc:
        validate_envelope(db_session, env, secret=SECRET)
    assert exc.value.code == GatewayErrorCode.PROTOCOL_UNSUPPORTED


def test_validate_malformed_envelope(db_session, tenant_and_device):
    tenant, device = tenant_and_device
    env = _env(tenant, device)
    env.device_id = ""
    with pytest.raises(GatewayError) as exc:
        validate_envelope(db_session, env, secret=SECRET)
    assert exc.value.code == GatewayErrorCode.MALFORMED_ENVELOPE


# ---------------------------------------------------------------------------
# Worker-level: timeout, connector failure, concurrency limiting.
# ---------------------------------------------------------------------------

from app.gateway import connectors, worker  # noqa: E402
from app.models.db import DeviceCredentialRef  # noqa: E402
from app.services import openbao_service as openbao_mod  # noqa: E402


def _add_credential_ref(db_session, tenant, device):
    db_session.add(DeviceCredentialRef(
        tenant_id=tenant.id, device_id=device.id, credential_ref="dev-abc", credential_type="ssh_password",
    ))
    db_session.commit()


def test_worker_processes_valid_job_via_mock_connector(db_session, tenant_and_device, monkeypatch):
    tenant, device = tenant_and_device
    _add_credential_ref(db_session, tenant, device)
    monkeypatch.setattr(
        openbao_mod, "get_device_credentials",
        lambda tenant_id, ref: openbao_mod.DeviceCredentials(credential_type="ssh_password", secret={"username": "a", "password": "b"}),
    )
    monkeypatch.setattr("app.gateway.worker.minio_service.put_object", lambda *a, **k: None)
    env = _env(tenant, device)
    result = worker.process_job(db_session, env, secret=SECRET)
    assert result["success"] is True
    assert result["normalized_data"]["vendor"] == "mock"


def test_worker_reports_credential_unavailable(db_session, tenant_and_device):
    tenant, device = tenant_and_device
    # No DeviceCredentialRef created.
    env = _env(tenant, device)
    result = worker.process_job(db_session, env, secret=SECRET)
    assert result["success"] is False
    assert result["error_code"] == GatewayErrorCode.CREDENTIAL_UNAVAILABLE.value


def test_worker_handles_connector_failure(db_session, tenant_and_device, monkeypatch):
    tenant, device = tenant_and_device
    _add_credential_ref(db_session, tenant, device)
    monkeypatch.setattr(
        openbao_mod, "get_device_credentials",
        lambda tenant_id, ref: openbao_mod.DeviceCredentials(credential_type="ssh_password", secret={"username": "a", "password": "b"}),
    )

    def _fail(device, operation, protocol, credentials):
        return connectors.NormalizedResult(
            device_id=device.id, protocol="ssh", operation=operation, success=False,
            error_code="DEVICE_UNREACHABLE", error_message="connection refused",
        )

    monkeypatch.setattr(worker.connectors, "execute", _fail)
    env = _env(tenant, device)
    result = worker.process_job(db_session, env, secret=SECRET)
    assert result["success"] is False
    assert result["error_code"] == "DEVICE_UNREACHABLE"


def test_worker_command_timeout(db_session, tenant_and_device, monkeypatch):
    tenant, device = tenant_and_device
    _add_credential_ref(db_session, tenant, device)
    monkeypatch.setattr(
        openbao_mod, "get_device_credentials",
        lambda tenant_id, ref: openbao_mod.DeviceCredentials(credential_type="ssh_password", secret={"username": "a", "password": "b"}),
    )
    monkeypatch.setattr(connectors, "CONNECT_TIMEOUT_SECONDS", 0.01)
    monkeypatch.setattr(connectors, "COMMAND_TIMEOUT_SECONDS", 0.01)
    monkeypatch.setattr(worker, "CONNECT_TIMEOUT_SECONDS", 0.01)
    monkeypatch.setattr(worker, "COMMAND_TIMEOUT_SECONDS", 0.01)

    def _slow(device, operation, protocol, credentials):
        time.sleep(0.2)
        return connectors.NormalizedResult(device_id=device.id, protocol="ssh", operation=operation, success=True)

    monkeypatch.setattr(worker.connectors, "execute", _slow)
    env = _env(tenant, device)
    result = worker.process_job(db_session, env, secret=SECRET)
    assert result["success"] is False
    assert result["error_code"] == GatewayErrorCode.COMMAND_TIMEOUT.value


def test_worker_concurrency_limit_per_device(db_session, tenant_and_device, monkeypatch):
    tenant, device = tenant_and_device
    _add_credential_ref(db_session, tenant, device)
    lock = worker._lock_for(device.id)
    assert lock.acquire(blocking=False)  # simulate an in-flight job
    try:
        env = _env(tenant, device)
        result = worker.process_job(db_session, env, secret=SECRET)
        assert result["success"] is False
        assert result["error_code"] == GatewayErrorCode.CONCURRENCY_LIMIT.value
    finally:
        lock.release()


# ---------------------------------------------------------------------------
# Security: credentials never appear in serialized jobs/results/logs.
# ---------------------------------------------------------------------------

def test_credentials_never_appear_in_envelope_or_result(db_session, tenant_and_device, monkeypatch):
    tenant, device = tenant_and_device
    _add_credential_ref(db_session, tenant, device)
    secret_password = "SuperSecretPW123"
    monkeypatch.setattr(
        openbao_mod, "get_device_credentials",
        lambda tenant_id, ref: openbao_mod.DeviceCredentials(credential_type="ssh_password", secret={"username": "a", "password": secret_password}),
    )
    monkeypatch.setattr("app.gateway.worker.minio_service.put_object", lambda *a, **k: None)
    env = _env(tenant, device)
    assert secret_password not in str(env.to_dict())
    result = worker.process_job(db_session, env, secret=SECRET)
    assert secret_password not in str(result)


def test_cross_tenant_gateway_job_record_isolated(db_session):
    t1 = Tenant(name="t1")
    t2 = Tenant(name="t2")
    db_session.add_all([t1, t2])
    db_session.commit()
    d1 = Device(tenant_id=t1.id, hostname="r1", vendor="mock")
    db_session.add(d1)
    db_session.commit()
    env = build_envelope(tenant_id=t2.id, requester_id="u", device_id=d1.id, operation="AUDIT", protocol="ssh", secret=SECRET)
    with pytest.raises(GatewayError) as exc:
        validate_envelope(db_session, env, secret=SECRET)
    assert exc.value.code == GatewayErrorCode.DEVICE_NOT_FOUND