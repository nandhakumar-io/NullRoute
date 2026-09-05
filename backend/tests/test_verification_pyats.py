"""Mocked tests for the optional pyATS/Genie supplemental verifier (spec
sections 29-34). No test contacts a real Cisco device -- pyats.topology's
loader is always monkeypatched with a MagicMock double.
"""
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.services.openbao_service import DeviceCredentials
from app.services.verification import pyats_genie as pyats_mod
from app.services.verification.base import (
    PYATS_DISABLED, PYATS_OK, PYATS_UNAVAILABLE, PYATS_UNSUPPORTED,
)
from app.services.verification.registry import get_verifier


def _device(vendor="cisco_ios", hostname="r1", management_address="10.0.0.1"):
    return SimpleNamespace(vendor=vendor, hostname=hostname, management_address=management_address)


def _creds():
    return DeviceCredentials(credential_type="ssh_password", secret={"username": "admin", "password": "x"})


@pytest.fixture(autouse=True)
def _enable_pyats(monkeypatch):
    monkeypatch.setenv("PYATS_ENABLED", "true")
    monkeypatch.setattr(pyats_mod, "PYATS_AVAILABLE", True)
    yield


def test_disabled_returns_pyats_disabled(monkeypatch):
    monkeypatch.setenv("PYATS_ENABLED", "false")
    verifier = get_verifier("pyats_genie")
    result = verifier.verify(_device(), _creds())
    assert result.success is False
    assert result.status == PYATS_DISABLED


def test_unavailable_when_library_missing(monkeypatch):
    monkeypatch.setattr(pyats_mod, "PYATS_AVAILABLE", False)
    verifier = get_verifier("pyats_genie")
    result = verifier.verify(_device(), _creds())
    assert result.success is False
    assert result.status == PYATS_UNAVAILABLE


def test_unsupported_vendor_is_explicit_not_a_crash(monkeypatch):
    verifier = get_verifier("pyats_genie")
    result = verifier.verify(_device(vendor="juniper"), _creds())
    assert result.success is False
    assert result.status == PYATS_UNSUPPORTED
    assert "Cisco" in result.error


def _fake_genie_device(parse_map=None, connect_raises=None):
    dev = MagicMock()
    if connect_raises:
        dev.connect.side_effect = connect_raises
    if parse_map is not None:
        def _parse(cmd):
            if cmd not in parse_map:
                raise RuntimeError(f"SchemaEmptyParserError: no parser for {cmd}")
            return parse_map[cmd]
        dev.parse.side_effect = _parse
    return dev


def test_connection_failure(monkeypatch):
    fake_device = _fake_genie_device(connect_raises=ConnectionError("no route to host"))
    fake_testbed = MagicMock()
    fake_testbed.devices = {"r1": fake_device}
    monkeypatch.setattr(pyats_mod, "pyats_loader", SimpleNamespace(load=MagicMock(return_value=fake_testbed)))

    verifier = get_verifier("pyats_genie")
    result = verifier.verify(_device(), _creds())
    assert result.success is False
    assert "connect" in result.error.lower()


def test_supported_parser_success(monkeypatch):
    fake_device = _fake_genie_device(parse_map={
        "show interfaces": {"GigabitEthernet0/1": {"oper_status": "up"}},
        "show ip route": {"vrf": {"default": {}}},
        "show vlan": {"vlans": {"1": {"name": "default"}}},
    })
    fake_testbed = MagicMock()
    fake_testbed.devices = {"r1": fake_device}
    monkeypatch.setattr(pyats_mod, "pyats_loader", SimpleNamespace(load=MagicMock(return_value=fake_testbed)))

    verifier = get_verifier("pyats_genie")
    result = verifier.verify(_device(), _creds())
    assert result.success is True
    assert result.status == PYATS_OK
    assert "show interfaces" in result.commands_run
    fake_device.disconnect.assert_called_once()


def test_unsupported_parser_for_some_commands_still_succeeds_with_others(monkeypatch):
    fake_device = _fake_genie_device(parse_map={
        "show interfaces": {"GigabitEthernet0/1": {"oper_status": "up"}},
        # "show ip route" and "show vlan" deliberately absent -> unsupported
    })
    fake_testbed = MagicMock()
    fake_testbed.devices = {"r1": fake_device}
    monkeypatch.setattr(pyats_mod, "pyats_loader", SimpleNamespace(load=MagicMock(return_value=fake_testbed)))

    verifier = get_verifier("pyats_genie")
    result = verifier.verify(_device(), _creds())
    assert result.success is True
    assert result.commands_run == ["show interfaces"]
    assert result.error  # unsupported commands recorded, not silently dropped


def test_all_parsers_unsupported_is_explicit_pyats_unsupported(monkeypatch):
    fake_device = _fake_genie_device(parse_map={})
    fake_testbed = MagicMock()
    fake_testbed.devices = {"r1": fake_device}
    monkeypatch.setattr(pyats_mod, "pyats_loader", SimpleNamespace(load=MagicMock(return_value=fake_testbed)))

    verifier = get_verifier("pyats_genie")
    result = verifier.verify(_device(), _creds())
    assert result.success is False
    assert result.status == PYATS_UNSUPPORTED
    fake_device.disconnect.assert_called_once()  # cleanup still happens


def test_credentials_never_written_to_disk(monkeypatch, tmp_path):
    """Regression guard: pyATS testbed is built as an in-memory dict, never
    a YAML file -- assert loader.load() is called with a dict, not a path."""
    fake_device = _fake_genie_device(parse_map={"show interfaces": {}})
    fake_testbed = MagicMock()
    fake_testbed.devices = {"r1": fake_device}
    load_mock = MagicMock(return_value=fake_testbed)
    monkeypatch.setattr(pyats_mod, "pyats_loader", SimpleNamespace(load=load_mock))

    verifier = get_verifier("pyats_genie")
    verifier.verify(_device(), _creds())

    args, _ = load_mock.call_args
    assert isinstance(args[0], dict)