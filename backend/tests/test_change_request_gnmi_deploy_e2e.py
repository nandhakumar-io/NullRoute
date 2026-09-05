"""End-to-end integration test for gNMI-transport deployment through the
actual HTTP router (spec sections 22-28/35/36), not just the adapter unit
tests in test_config_injection_gnmi.py. Exercises:

    POST /api/change-requests            (create + validate)
    POST /api/change-requests/{id}/approve
    POST /api/change-requests/{id}/deploy   transport="gnmi"

with the collector and the gNMI injector both mocked (no real network),
confirming deployment_service.py's transport plumbing, DeploymentRecord
persistence of gNMI metadata (request_hash/model/paths/operation), and
the post-deployment compliance-pipeline rerun all work together for the
gNMI path exactly as they already do for SSH in test_change_requests.py.
"""
from __future__ import annotations

import json

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from app.auth import dependencies as deps_mod
from app.auth import jwt as jwt_mod
from app.services import opa_service, openbao_service
from app.services.collectors.base import CollectionResult
from app.services.config_injection.result import GNMI_OK, GnmiResult

OPA_EVAL_URL = f"{opa_service.OPA_URL}/v1/data/compliance/evaluate"

GNMI_UPDATE_PAYLOAD = json.dumps([{
    "path": "/interfaces/interface[name=Gi0/1]/config/enabled",
    "value": True,
    "model": "openconfig-interfaces",
    "operation": "update",
}])


def _opa_pass():
    return {"result": {"decision": "PASS", "findings": [], "violations": [],
                        "evaluated_controls": [], "policy_version": "1.0.0"}}


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
    async def _fake_publish(subject, payload):
        return None
    monkeypatch.setattr("app.events.publish", _fake_publish)
    yield


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test.db")
    monkeypatch.setenv("AI_ENABLED", "false")
    monkeypatch.setenv("GNMI_ENABLED", "true")
    from app.main import app
    with TestClient(app) as c:
        yield c


def _create_device_with_creds(client):
    dev = client.post("/api/devices", json={"hostname": "r1", "vendor": "cisco", "management_address": "10.0.0.1"})
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


def test_gnmi_deploy_end_to_end_through_router(client, monkeypatch):
    device_id = _create_device_with_creds(client)

    with respx.mock:
        respx.post(OPA_EVAL_URL).mock(return_value=httpx.Response(200, json=_opa_pass()))
        cr = client.post("/api/change-requests", json={
            "device_id": device_id, "proposed_config": GNMI_UPDATE_PAYLOAD,
        }).json()
    assert cr["status"] == "PENDING_APPROVAL"

    approved = client.post(f"/api/change-requests/{cr['id']}/approve")
    assert approved.status_code == 200
    assert approved.json()["status"] == "APPROVED"

    # Mock the collector deployment_service.py uses for pre/post hash
    # verification -- returning the exact proposed text both times means
    # the post-deploy hash always matches (post_verification_passed=True)
    # without needing a real device.
    from app.services import deployment_service as depsvc

    class _FakeCollector:
        transport = "ssh"

        def collect_config(self, device, credentials):
            return CollectionResult(success=True, vendor="cisco", hostname="r1",
                                     raw_config=GNMI_UPDATE_PAYLOAD, transport="ssh")

    monkeypatch.setattr(depsvc, "get_collector", lambda vendor: _FakeCollector())
    monkeypatch.setattr(depsvc.minio_service, "get_object", lambda key: GNMI_UPDATE_PAYLOAD.encode("utf-8"))

    # Mock only the network-touching injector, not the deployer/bridge --
    # this exercises the real GnmiDeployer.push_config parsing/validation
    # logic, just not an actual gNMI socket.
    from app.services.config_injection import registry as injector_registry

    class _FakeInjector:
        transport = "gnmi"

        def capabilities(self, device, credentials):
            return GnmiResult(success=True, status=GNMI_OK, data={"supported_models": [{"name": "openconfig-interfaces"}]})

        def set(self, device, credentials, updates):
            return GnmiResult(success=True, status=GNMI_OK, request_hash="deadbeefcafe",
                               data={"response": [{"path": updates[0].path, "op": "UPDATE"}]})

    monkeypatch.setattr(injector_registry, "_INJECTORS", {"gnmi": _FakeInjector()})

    with respx.mock:
        respx.post(OPA_EVAL_URL).mock(return_value=httpx.Response(200, json=_opa_pass()))
        respx.get(url__regex=r"http://openbao\.test/v1/secret/data/.*").mock(
            return_value=httpx.Response(
                200,
                json={"data": {"data": {"credential_type": "ssh_password", "username": "admin", "password": "x"}}},
            )
        )
        deploy_resp = client.post(f"/api/change-requests/{cr['id']}/deploy", json={"transport": "gnmi"})

    assert deploy_resp.status_code == 200
    dr = deploy_resp.json()
    assert dr["transport"] == "gnmi"
    assert dr["status"] in ("VERIFIED", "DEPLOYED")
    assert dr["post_verification_passed"] is True
    # gNMI-specific metadata must be persisted onto the DeploymentRecord
    # (spec sections 26/47/53) -- never credentials.
    assert dr["request_hash"] == "deadbeefcafe"
    assert dr["model_name"] == "openconfig-interfaces"
    assert dr["operation"] == "update"
    assert dr["paths"] == ["/interfaces/interface[name=Gi0/1]/config/enabled"]

    cr_after = client.get(f"/api/change-requests/{cr['id']}").json()
    assert cr_after["status"] == "DEPLOYED"

    deployments = client.get(f"/api/change-requests/{cr['id']}/deployments").json()
    assert deployments["count"] == 1
    assert deployments["deployments"][0]["transport"] == "gnmi"


def test_gnmi_deploy_disabled_flag_returns_explicit_failure_not_silent_fallback(client, monkeypatch):
    """GNMI_ENABLED=false must produce an explicit GNMI_DISABLED failure,
    never a silent fallback to SSH (spec section 27)."""
    monkeypatch.setenv("GNMI_ENABLED", "false")
    device_id = _create_device_with_creds(client)

    with respx.mock:
        respx.post(OPA_EVAL_URL).mock(return_value=httpx.Response(200, json=_opa_pass()))
        cr = client.post("/api/change-requests", json={
            "device_id": device_id, "proposed_config": GNMI_UPDATE_PAYLOAD,
        }).json()
    client.post(f"/api/change-requests/{cr['id']}/approve")

    from app.services import deployment_service as depsvc

    class _FakeCollector:
        transport = "ssh"

        def collect_config(self, device, credentials):
            return CollectionResult(success=True, vendor="cisco", hostname="r1",
                                     raw_config=GNMI_UPDATE_PAYLOAD, transport="ssh")

    monkeypatch.setattr(depsvc, "get_collector", lambda vendor: _FakeCollector())
    monkeypatch.setattr(depsvc.minio_service, "get_object", lambda key: GNMI_UPDATE_PAYLOAD.encode("utf-8"))

    with respx.mock:
        respx.get(url__regex=r"http://openbao\.test/v1/secret/data/.*").mock(
            return_value=httpx.Response(
                200,
                json={"data": {"data": {"credential_type": "ssh_password", "username": "admin", "password": "x"}}},
            )
        )
        deploy_resp = client.post(f"/api/change-requests/{cr['id']}/deploy", json={"transport": "gnmi"})

    assert deploy_resp.status_code == 200
    dr = deploy_resp.json()
    assert dr["status"] == "FAILED"
    assert "GNMI_DISABLED" in dr["error"]
    assert dr["transport"] == "gnmi"  # never silently switched to another transport


def test_gnmi_deploy_aborts_on_stale_pre_change_hash(client, monkeypatch):
    """If the device's live config hash no longer matches the hash the
    ChangeRequest was validated against, deployment_service.py must abort
    (status=ABORTED_STALE_HASH) *before* ever calling the gNMI injector's
    Set -- spec sections 25/43. The push must never be attempted."""
    device_id = _create_device_with_creds(client)

    # ChangeRequest.current_config_hash is taken from the device's latest
    # known Scan at CR-creation time (change_request_service.latest_known_
    # config), not re-collected live -- so a device with no prior scan has
    # current_config_hash=None and the stale-hash check is a no-op (that's
    # documented, deliberate behavior for a device never scanned before).
    # To actually exercise the abort path, give the CR a concrete baseline
    # to have been validated against.
    from app.services import change_request_service as cr_svc
    monkeypatch.setattr(cr_svc, "latest_known_config", lambda db, device_id: "hostname r1\n! baseline config")

    with respx.mock:
        respx.post(OPA_EVAL_URL).mock(return_value=httpx.Response(200, json=_opa_pass()))
        cr = client.post("/api/change-requests", json={
            "device_id": device_id, "proposed_config": GNMI_UPDATE_PAYLOAD,
        }).json()
    assert cr["current_config_hash"] is not None
    client.post(f"/api/change-requests/{cr['id']}/approve")

    from app.services import deployment_service as depsvc

    class _DriftedCollector:
        """Returns config that differs from the baseline the CR was
        validated against, simulating an intervening out-of-band change
        on the device between validation and deployment."""
        transport = "ssh"

        def collect_config(self, device, credentials):
            return CollectionResult(success=True, vendor="cisco", hostname="r1",
                                     raw_config="hostname r1\n! SOMEONE CHANGED THIS OUT OF BAND",
                                     transport="ssh")

    monkeypatch.setattr(depsvc, "get_collector", lambda vendor: _DriftedCollector())
    monkeypatch.setattr(depsvc.minio_service, "get_object", lambda key: GNMI_UPDATE_PAYLOAD.encode("utf-8"))

    from app.services.config_injection import registry as injector_registry

    class _InjectorThatMustNotBeCalled:
        transport = "gnmi"

        def capabilities(self, device, credentials):
            raise AssertionError("capabilities() must not be called after a stale-hash abort")

        def set(self, device, credentials, updates):
            raise AssertionError("set() must not be called after a stale-hash abort")

    monkeypatch.setattr(injector_registry, "_INJECTORS", {"gnmi": _InjectorThatMustNotBeCalled()})

    with respx.mock:
        respx.get(url__regex=r"http://openbao\.test/v1/secret/data/.*").mock(
            return_value=httpx.Response(
                200,
                json={"data": {"data": {"credential_type": "ssh_password", "username": "admin", "password": "x"}}},
            )
        )
        deploy_resp = client.post(f"/api/change-requests/{cr['id']}/deploy", json={"transport": "gnmi"})

    assert deploy_resp.status_code == 200
    dr = deploy_resp.json()
    assert dr["status"] == "ABORTED_STALE_HASH"
    assert "does not match" in dr["error"]
    assert dr["post_config_hash"] is None  # never reached the push step

    cr_after = client.get(f"/api/change-requests/{cr['id']}").json()
    assert cr_after["status"] == "FAILED"


def test_gnmi_deploy_marks_drifted_on_post_verification_mismatch(client, monkeypatch):
    """If the gNMI Set reports success but the post-deployment collected
    config hash does not match the approved proposed hash, the deployment
    must be marked DRIFTED with post_verification_passed=False rather than
    silently reported as a clean success -- spec sections 44/50."""
    device_id = _create_device_with_creds(client)

    with respx.mock:
        respx.post(OPA_EVAL_URL).mock(return_value=httpx.Response(200, json=_opa_pass()))
        cr = client.post("/api/change-requests", json={
            "device_id": device_id, "proposed_config": GNMI_UPDATE_PAYLOAD,
        }).json()
    client.post(f"/api/change-requests/{cr['id']}/approve")

    from app.services import deployment_service as depsvc

    call_count = {"n": 0}

    class _MismatchingCollector:
        """Pre-check returns the expected config (hash matches, so the
        stale-hash guard passes); post-check returns something different,
        simulating a device that didn't actually apply the full change."""
        transport = "ssh"

        def collect_config(self, device, credentials):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return CollectionResult(success=True, vendor="cisco", hostname="r1",
                                         raw_config=GNMI_UPDATE_PAYLOAD, transport="ssh")
            return CollectionResult(success=True, vendor="cisco", hostname="r1",
                                     raw_config=GNMI_UPDATE_PAYLOAD + "\n! device only partially applied it",
                                     transport="ssh")

    monkeypatch.setattr(depsvc, "get_collector", lambda vendor: _MismatchingCollector())
    monkeypatch.setattr(depsvc.minio_service, "get_object", lambda key: GNMI_UPDATE_PAYLOAD.encode("utf-8"))

    from app.services.config_injection import registry as injector_registry

    class _FakeInjector:
        transport = "gnmi"

        def capabilities(self, device, credentials):
            return GnmiResult(success=True, status=GNMI_OK, data={"supported_models": [{"name": "openconfig-interfaces"}]})

        def set(self, device, credentials, updates):
            return GnmiResult(success=True, status=GNMI_OK, request_hash="deadbeefcafe",
                               data={"response": [{"path": updates[0].path, "op": "UPDATE"}]})

    monkeypatch.setattr(injector_registry, "_INJECTORS", {"gnmi": _FakeInjector()})

    with respx.mock:
        respx.post(OPA_EVAL_URL).mock(return_value=httpx.Response(200, json=_opa_pass()))
        respx.get(url__regex=r"http://openbao\.test/v1/secret/data/.*").mock(
            return_value=httpx.Response(
                200,
                json={"data": {"data": {"credential_type": "ssh_password", "username": "admin", "password": "x"}}},
            )
        )
        deploy_resp = client.post(f"/api/change-requests/{cr['id']}/deploy", json={"transport": "gnmi"})

    assert deploy_resp.status_code == 200
    dr = deploy_resp.json()
    assert dr["status"] == "DRIFTED"
    assert dr["post_verification_passed"] is False
    # The push itself succeeded, so the ChangeRequest is DEPLOYED -- the
    # drift is the reportable problem, not an undone/pretended deployment.
    cr_after = client.get(f"/api/change-requests/{cr['id']}").json()
    assert cr_after["status"] == "DEPLOYED"