from types import SimpleNamespace
from unittest.mock import MagicMock

import httpx
import pytest
import respx

from app.services.collectors import registry as registry_mod
from app.services.collectors import ssh as ssh_mod
from app.services.collectors import restconf as restconf_mod
from app.services.collectors.base import CollectionResult
from app.services.openbao_service import DeviceCredentials


def _device(vendor="cisco", hostname="r1", management_address="10.0.0.1"):
    return SimpleNamespace(vendor=vendor, hostname=hostname, management_address=management_address)


def test_registry_picks_preferred_transport():
    assert registry_mod.preferred_transport("juniper") == "netconf"
    assert registry_mod.preferred_transport("cisco_ios") == "ssh"
    collector = registry_mod.get_collector("cisco", transport="ssh")
    assert collector.transport == "ssh"


def test_registry_rejects_unknown_transport():
    with pytest.raises(ValueError):
        registry_mod.get_collector("cisco", transport="carrier-pigeon")


def test_ssh_collector_unavailable_when_netmiko_missing(monkeypatch):
    monkeypatch.setattr(ssh_mod, "NETMIKO_AVAILABLE", False)
    collector = ssh_mod.SSHCollector()
    creds = DeviceCredentials(credential_type="ssh_password", secret={"username": "admin", "password": "x"})
    result = collector.collect_config(_device(), creds)
    assert result.success is False
    assert "netmiko is not installed" in result.error
    assert result.transport == "ssh"


def test_ssh_collector_unsupported_vendor(monkeypatch):
    monkeypatch.setattr(ssh_mod, "NETMIKO_AVAILABLE", True)
    collector = ssh_mod.SSHCollector()
    creds = DeviceCredentials(credential_type="ssh_password", secret={"username": "admin", "password": "x"})
    result = collector.collect_config(_device(vendor="totally-unknown-vendor"), creds)
    assert result.success is False
    assert "No SSH collection profile" in result.error


def test_ssh_collector_success(monkeypatch):
    monkeypatch.setattr(ssh_mod, "NETMIKO_AVAILABLE", True)

    fake_conn = MagicMock()
    fake_conn.__enter__ = MagicMock(return_value=fake_conn)
    fake_conn.__exit__ = MagicMock(return_value=False)
    fake_conn.send_command.return_value = "hostname r1\nline vty 0 4\n transport input ssh\n"

    monkeypatch.setattr(ssh_mod, "ConnectHandler", MagicMock(return_value=fake_conn))

    collector = ssh_mod.SSHCollector()
    creds = DeviceCredentials(credential_type="ssh_password", secret={"username": "admin", "password": "x"})
    result = collector.collect_config(_device(), creds)

    assert result.success is True
    assert "transport input ssh" in result.raw_config
    assert result.config_hash is not None
    assert result.transport == "ssh"
    assert result.duration_ms >= 0


def test_ssh_collector_auth_failure(monkeypatch):
    monkeypatch.setattr(ssh_mod, "NETMIKO_AVAILABLE", True)

    def _raise(**kwargs):
        raise ssh_mod.NetmikoAuthenticationException("bad creds")

    monkeypatch.setattr(ssh_mod, "ConnectHandler", _raise)

    collector = ssh_mod.SSHCollector()
    creds = DeviceCredentials(credential_type="ssh_password", secret={"username": "admin", "password": "wrong"})
    result = collector.collect_config(_device(), creds)
    assert result.success is False
    assert "Authentication failed" in result.error


@respx.mock
def test_restconf_collector_success():
    respx.get("https://10.0.0.1/restconf/data/Cisco-IOS-XE-native:native").mock(
        return_value=httpx.Response(200, json={"native": {"hostname": "r1"}})
    )
    collector = restconf_mod.RestconfCollector()
    creds = DeviceCredentials(credential_type="ssh_password", secret={"username": "admin", "password": "x", "verify_tls": False})
    result = collector.collect_config(_device(vendor="cisco_xe"), creds)
    assert result.success is True
    assert "hostname" in result.raw_config


@respx.mock
def test_restconf_collector_auth_failure():
    respx.get("https://10.0.0.1/restconf/data/Cisco-IOS-XE-native:native").mock(return_value=httpx.Response(401))
    collector = restconf_mod.RestconfCollector()
    creds = DeviceCredentials(credential_type="ssh_password", secret={"username": "admin", "password": "wrong"})
    result = collector.collect_config(_device(vendor="cisco_xe"), creds)
    assert result.success is False
    assert "401" in result.error


def test_restconf_collector_unsupported_vendor():
    collector = restconf_mod.RestconfCollector()
    creds = DeviceCredentials(credential_type="ssh_password", secret={})
    result = collector.collect_config(_device(vendor="totally-unknown"), creds)
    assert result.success is False
