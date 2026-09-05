"""Mocked tests for the optional gNMI/OpenConfig config-injection adapter
(spec sections 22-28). No test contacts a real device -- pygnmi's
gNMIclient is always monkeypatched with a MagicMock double.
"""
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.services.config_injection import gnmi as gnmi_mod
from app.services.config_injection import openconfig
from app.services.config_injection.registry import get_injector
from app.services.config_injection.result import (
    GNMI_DISABLED, GNMI_OK, GNMI_SCHEMA_MISMATCH, GNMI_UNAVAILABLE, GnmiUpdate,
)
from app.services.deployment.gnmi import GnmiDeployer
from app.services.openbao_service import DeviceCredentials


def _device(vendor="cisco_ios", hostname="r1", management_address="10.0.0.1"):
    return SimpleNamespace(vendor=vendor, hostname=hostname, management_address=management_address)


def _creds():
    return DeviceCredentials(credential_type="ssh_password", secret={"username": "admin", "password": "x"})


def _fake_client(capabilities_return=None, set_return=None, raise_on=None):
    fake = MagicMock()
    fake.__enter__ = MagicMock(return_value=fake)
    fake.__exit__ = MagicMock(return_value=False)
    if raise_on == "capabilities":
        fake.capabilities.side_effect = ConnectionError("no route to host")
    else:
        fake.capabilities.return_value = capabilities_return or {
            "supported_models": [{"name": "openconfig-interfaces"}]
        }
    if raise_on == "set":
        fake.set.side_effect = TimeoutError("gNMI Set timed out")
    else:
        fake.set.return_value = set_return or {"response": [{"path": "/interfaces", "op": "UPDATE"}]}
    return fake


@pytest.fixture(autouse=True)
def _enable_gnmi(monkeypatch):
    monkeypatch.setenv("GNMI_ENABLED", "true")
    monkeypatch.setenv("OPENCONFIG_ENABLED", "true")
    monkeypatch.setenv("GNMI_TLS_ENABLED", "false")
    monkeypatch.setattr(gnmi_mod, "PYGNMI_AVAILABLE", True)
    yield


def test_disabled_returns_gnmi_disabled_without_touching_network(monkeypatch):
    monkeypatch.setenv("GNMI_ENABLED", "false")
    injector = get_injector("gnmi")
    result = injector.capabilities(_device(), _creds())
    assert result.success is False
    assert result.status == GNMI_DISABLED


def test_unavailable_when_pygnmi_missing(monkeypatch):
    monkeypatch.setattr(gnmi_mod, "PYGNMI_AVAILABLE", False)
    injector = get_injector("gnmi")
    result = injector.capabilities(_device(), _creds())
    assert result.success is False
    assert result.status == GNMI_UNAVAILABLE
    assert "pygnmi is not installed" in result.error


def test_capabilities_success(monkeypatch):
    fake = _fake_client()
    monkeypatch.setattr(gnmi_mod, "gNMIclient", MagicMock(return_value=fake))
    injector = get_injector("gnmi")
    result = injector.capabilities(_device(), _creds())
    assert result.success is True
    assert result.status == GNMI_OK


def test_capabilities_failure_is_gnmi_unavailable(monkeypatch):
    fake = _fake_client(raise_on="capabilities")
    monkeypatch.setattr(gnmi_mod, "gNMIclient", MagicMock(return_value=fake))
    injector = get_injector("gnmi")
    result = injector.capabilities(_device(), _creds())
    assert result.success is False
    assert result.status == GNMI_UNAVAILABLE


def test_set_rejects_unsupported_model(monkeypatch):
    fake = _fake_client()
    monkeypatch.setattr(gnmi_mod, "gNMIclient", MagicMock(return_value=fake))
    injector = get_injector("gnmi")
    bad_update = GnmiUpdate(path="/foo/bar", value=True, model="not-a-real-model", operation="update")
    result = injector.set(_device(), _creds(), [bad_update])
    assert result.success is False
    assert result.status == GNMI_SCHEMA_MISMATCH
    fake.set.assert_not_called()  # never reaches the network with a bad schema


def test_set_rejects_invalid_path_for_model(monkeypatch):
    fake = _fake_client()
    monkeypatch.setattr(gnmi_mod, "gNMIclient", MagicMock(return_value=fake))
    injector = get_injector("gnmi")
    bad_update = GnmiUpdate(path="/system/foo", value="x", model="openconfig-interfaces", operation="update")
    result = injector.set(_device(), _creds(), [bad_update])
    assert result.success is False
    assert result.status == GNMI_SCHEMA_MISMATCH


def test_set_rejects_invalid_value_type(monkeypatch):
    fake = _fake_client()
    monkeypatch.setattr(gnmi_mod, "gNMIclient", MagicMock(return_value=fake))
    injector = get_injector("gnmi")
    bad_update = GnmiUpdate(path="/interfaces/interface[name=Gi0/1]/config/enabled",
                             value={"nested": "dict-not-allowed-for-interfaces-leaf"},
                             model="openconfig-interfaces", operation="update")
    result = injector.set(_device(), _creds(), [bad_update])
    assert result.success is False
    assert result.status == GNMI_SCHEMA_MISMATCH


def test_set_update_success(monkeypatch):
    fake = _fake_client()
    monkeypatch.setattr(gnmi_mod, "gNMIclient", MagicMock(return_value=fake))
    injector = get_injector("gnmi")
    update = GnmiUpdate(path="/interfaces/interface[name=Gi0/1]/config/enabled",
                         value=True, model="openconfig-interfaces", operation="update")
    result = injector.set(_device(), _creds(), [update])
    assert result.success is True
    assert result.status == GNMI_OK
    assert result.request_hash is not None
    fake.set.assert_called_once()
    _, kwargs = fake.set.call_args
    assert kwargs["update"] == [(update.path, True)]
    assert kwargs["replace"] is None
    assert kwargs["delete"] is None


def test_set_replace_success(monkeypatch):
    fake = _fake_client(capabilities_return={"supported_models": [{"name": "openconfig-system"}]})
    monkeypatch.setattr(gnmi_mod, "gNMIclient", MagicMock(return_value=fake))
    injector = get_injector("gnmi")
    update = GnmiUpdate(path="/system/config/hostname", value="r1-new",
                         model="openconfig-system", operation="replace")
    result = injector.set(_device(), _creds(), [update])
    assert result.success is True
    _, kwargs = fake.set.call_args
    assert kwargs["replace"] == [(update.path, "r1-new")]


def test_set_delete_success(monkeypatch):
    fake = _fake_client(capabilities_return={"supported_models": [{"name": "openconfig-acl"}]})
    monkeypatch.setattr(gnmi_mod, "gNMIclient", MagicMock(return_value=fake))
    injector = get_injector("gnmi")
    update = GnmiUpdate(path="/acl/acl-sets/acl-set[name=BLOCK]", value=None,
                         model="openconfig-acl", operation="delete")
    result = injector.set(_device(), _creds(), [update])
    assert result.success is True
    _, kwargs = fake.set.call_args
    assert kwargs["delete"] == [update.path]


def test_set_authentication_failure(monkeypatch):
    fake = _fake_client(raise_on="set")
    monkeypatch.setattr(gnmi_mod, "gNMIclient", MagicMock(return_value=fake))
    fake.capabilities.side_effect = None
    injector = get_injector("gnmi")
    update = GnmiUpdate(path="/interfaces/interface[name=Gi0/1]/config/enabled",
                         value=True, model="openconfig-interfaces", operation="update")
    result = injector.set(_device(), _creds(), [update])
    assert result.success is False
    assert "timed out" in result.error.lower() or "timeout" in result.error.lower()


def test_set_timeout(monkeypatch):
    fake = _fake_client(raise_on="set")
    fake.capabilities.side_effect = None
    monkeypatch.setattr(gnmi_mod, "gNMIclient", MagicMock(return_value=fake))
    injector = get_injector("gnmi")
    update = GnmiUpdate(path="/interfaces/interface[name=Gi0/1]/config/enabled",
                         value=True, model="openconfig-interfaces", operation="update")
    result = injector.set(_device(), _creds(), [update])
    assert result.success is False


def test_set_rejects_model_not_in_device_capabilities(monkeypatch):
    """Device Capabilities() doesn't report the requested model -- must
    fail even though our own static allow-list thinks the model exists."""
    fake = _fake_client(capabilities_return={"supported_models": [{"name": "openconfig-system"}]})
    monkeypatch.setattr(gnmi_mod, "gNMIclient", MagicMock(return_value=fake))
    injector = get_injector("gnmi")
    update = GnmiUpdate(path="/interfaces/interface[name=Gi0/1]/config/enabled",
                         value=True, model="openconfig-interfaces", operation="update")
    result = injector.set(_device(), _creds(), [update])
    assert result.success is False
    assert result.status == GNMI_SCHEMA_MISMATCH
    fake.set.assert_not_called()


# --- GnmiDeployer (bridges into the BaseDeployer/ChangeRequest pipeline) ---

def test_deployer_rejects_non_json_config_lines(monkeypatch):
    deployer = GnmiDeployer()
    result = deployer.push_config(_device(), _creds(), ["interface Gi0/1", "no shutdown"])
    assert result.success is False
    assert GNMI_SCHEMA_MISMATCH in result.error


def test_deployer_full_success_path(monkeypatch):
    fake = _fake_client()
    monkeypatch.setattr(gnmi_mod, "gNMIclient", MagicMock(return_value=fake))
    deployer = GnmiDeployer()
    config_lines = [
        '[{"path": "/interfaces/interface[name=Gi0/1]/config/enabled", '
        '"value": true, "model": "openconfig-interfaces", "operation": "update"}]'
    ]
    result = deployer.push_config(_device(), _creds(), config_lines)
    assert result.success is True
    assert result.transport == "gnmi"


def test_deployer_capabilities_failure_aborts_before_set(monkeypatch):
    fake = _fake_client(raise_on="capabilities")
    monkeypatch.setattr(gnmi_mod, "gNMIclient", MagicMock(return_value=fake))
    deployer = GnmiDeployer()
    config_lines = [
        '[{"path": "/interfaces/interface[name=Gi0/1]/config/enabled", '
        '"value": true, "model": "openconfig-interfaces", "operation": "update"}]'
    ]
    result = deployer.push_config(_device(), _creds(), config_lines)
    assert result.success is False
    fake.set.assert_not_called()


def test_openconfig_validate_helpers_directly():
    with pytest.raises(openconfig.SchemaMismatch):
        openconfig.validate_model("not-a-model")
    with pytest.raises(openconfig.SchemaMismatch):
        openconfig.validate_path("openconfig-system", "/interfaces/foo")
    openconfig.validate_path("openconfig-system", "/system/config/hostname")  # no raise