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


# ---------------------------------------------------------------------------
# SNMP collector tests (pysnmp >=6.0.0, asyncio.run() wrapper)
# ---------------------------------------------------------------------------
from app.services.collectors import snmp as snmp_mod
from app.services.collectors.base import StructuredResult


def test_snmp_get_facts_unavailable(monkeypatch):
    monkeypatch.setattr(snmp_mod, "PYSNMP_AVAILABLE", False)
    collector = snmp_mod.SNMPCollector()
    creds = DeviceCredentials(credential_type="snmp_community", secret={"community": "public"})
    result = collector.get_facts(_device(), creds)
    assert result.success is False
    assert "pysnmp is not installed" in result.error
    assert result.transport == "snmp"


def test_snmp_collect_config_unavailable(monkeypatch):
    monkeypatch.setattr(snmp_mod, "PYSNMP_AVAILABLE", False)
    collector = snmp_mod.SNMPCollector()
    creds = DeviceCredentials(credential_type="snmp_community", secret={"community": "public"})
    result = collector.collect_config(_device(), creds)
    assert result.success is False
    assert "pysnmp is not installed" in result.error


def test_snmp_get_facts_success(monkeypatch):
    """Patch _run_async to return fabricated MIB-II scalar values without
    touching the real asyncio / pysnmp stack."""
    monkeypatch.setattr(snmp_mod, "PYSNMP_AVAILABLE", True)

    # var_binds: list of (oid, value) pairs matching SYS_DESCR, SYS_OID, SYS_UPTIME, SYS_NAME
    fake_var_binds = [
        (snmp_mod.SYS_DESCR_OID,     "Cisco IOS Software, Version 15.6"),
        (snmp_mod.SYS_OBJECT_ID_OID, "1.3.6.1.4.1.9"),
        (snmp_mod.SYS_UPTIME_OID,    "1234567"),
        (snmp_mod.SYS_NAME_OID,      "router1"),
    ]

    # _run_async is the boundary between sync collector code and async pysnmp.
    # Patching it avoids needing a real event loop or pysnmp installed.
    monkeypatch.setattr(snmp_mod, "_run_async", lambda coro: (None, None, None, fake_var_binds))
    # Stub pysnmp object constructors so _auth_data / _transport don't crash.
    monkeypatch.setattr(snmp_mod, "SnmpEngine", lambda: None)
    monkeypatch.setattr(snmp_mod, "CommunityData", lambda *a, **kw: None)
    monkeypatch.setattr(snmp_mod, "UdpTransportTarget", lambda *a, **kw: None)
    monkeypatch.setattr(snmp_mod, "ContextData", lambda: None)
    monkeypatch.setattr(snmp_mod, "ObjectType", lambda *a: a)
    monkeypatch.setattr(snmp_mod, "ObjectIdentity", lambda oid: oid)

    collector = snmp_mod.SNMPCollector()
    creds = DeviceCredentials(credential_type="snmp_community", secret={"community": "public"})
    result = collector.get_facts(_device(), creds)

    assert result.success is True
    assert result.data["sys_name"] == "router1"
    assert result.data["sys_descr"] == "Cisco IOS Software, Version 15.6"
    assert result.hostname == "router1"
    assert result.transport == "snmp"


def test_snmp_get_interfaces_success(monkeypatch):
    """Patch _run_async to return one IF-MIB row per column walk."""
    monkeypatch.setattr(snmp_mod, "PYSNMP_AVAILABLE", True)

    field_names = list(snmp_mod._IF_MIB_COLUMNS.keys())
    base_oids = list(snmp_mod._IF_MIB_COLUMNS.values())
    call_count = [0]

    def _fake_run_async(coro):
        """Each call corresponds to one column walk (_walk() coroutine)."""
        idx = call_count[0] % len(base_oids)
        call_count[0] += 1
        base = base_oids[idx]
        field = field_names[idx]
        val_str = {
            "index": "1", "name": "Gi0/0", "admin_status": "1",
            "oper_status": "1", "speed_bps": "1000000000", "mac_address": "00:11:22:33:44:55",
        }.get(field, "")

        class FakeVal:
            def __str__(self): return val_str
            def prettyPrint(self): return val_str
            def __int__(self): return int(val_str) if val_str.isdigit() else 0

        # _walk() returns a list of (errInd, errStatus, errIdx, varBinds) tuples
        return [(None, None, None, [(f"{base}.1", FakeVal())])]

    monkeypatch.setattr(snmp_mod, "_run_async", _fake_run_async)
    monkeypatch.setattr(snmp_mod, "SnmpEngine", lambda: None)
    monkeypatch.setattr(snmp_mod, "CommunityData", lambda *a, **kw: None)
    monkeypatch.setattr(snmp_mod, "UdpTransportTarget", lambda *a, **kw: None)
    monkeypatch.setattr(snmp_mod, "ContextData", lambda: None)
    monkeypatch.setattr(snmp_mod, "ObjectType", lambda *a: a)
    monkeypatch.setattr(snmp_mod, "ObjectIdentity", lambda oid: oid)

    collector = snmp_mod.SNMPCollector()
    creds = DeviceCredentials(credential_type="snmp_community", secret={"community": "public"})
    result = collector.get_interfaces(_device(), creds)

    assert result.success is True
    assert "interfaces" in result.data
    assert result.transport == "snmp"


# ---------------------------------------------------------------------------
# SSH get_interfaces tests
# ---------------------------------------------------------------------------

CISCO_IP_INT_BRIEF = """\
Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0    192.168.1.1    YES NVRAM  up                    up
GigabitEthernet0/1    unassigned      YES NVRAM  administratively down down
Loopback0             10.0.0.1       YES NVRAM  up                    up
"""

ARISTA_INT_STATUS = """\
Port       Name   Status       Vlan     Duplex Speed  Type
Et1               connected    1        full   1000   EthernetZ
Et2               notconnect   1        auto   auto   EthernetZ
Ma1               connected    routed   full   1000   10/100/1000
"""

JUNIPER_TERSE = """\
Interface               Admin Link Proto    Local                 Remote
ge-0/0/0                up    up
ge-0/0/0.0              up    up   inet     192.168.1.1/24
lo0                     up    up
lo0.0                   up    up   inet     127.0.0.1
"""


def test_ssh_get_interfaces_unavailable_netmiko(monkeypatch):
    monkeypatch.setattr(ssh_mod, "NETMIKO_AVAILABLE", False)
    collector = ssh_mod.SSHCollector()
    creds = DeviceCredentials(credential_type="ssh_password", secret={"username": "admin", "password": "x"})
    result = collector.get_interfaces(_device(), creds)
    assert result.success is False
    assert "netmiko is not installed" in result.error
    assert result.transport == "ssh"


def test_ssh_get_interfaces_unknown_vendor(monkeypatch):
    monkeypatch.setattr(ssh_mod, "NETMIKO_AVAILABLE", True)
    collector = ssh_mod.SSHCollector()
    creds = DeviceCredentials(credential_type="ssh_password", secret={"username": "admin", "password": "x"})
    result = collector.get_interfaces(_device(vendor="unknown-vendor"), creds)
    # Unknown vendor should succeed with empty list + a note, not an error
    assert result.success is True
    assert result.data["interfaces"] == []
    assert "note" in result.data


def test_ssh_get_interfaces_cisco_success(monkeypatch):
    monkeypatch.setattr(ssh_mod, "NETMIKO_AVAILABLE", True)

    fake_conn = MagicMock()
    fake_conn.__enter__ = MagicMock(return_value=fake_conn)
    fake_conn.__exit__ = MagicMock(return_value=False)
    fake_conn.send_command.return_value = CISCO_IP_INT_BRIEF

    monkeypatch.setattr(ssh_mod, "ConnectHandler", MagicMock(return_value=fake_conn))

    collector = ssh_mod.SSHCollector()
    creds = DeviceCredentials(credential_type="ssh_password", secret={"username": "admin", "password": "x"})
    result = collector.get_interfaces(_device(vendor="cisco"), creds)

    assert result.success is True
    assert result.transport == "ssh"
    ifaces = result.data["interfaces"]
    assert len(ifaces) >= 2
    gi0 = next(i for i in ifaces if "GigabitEthernet0/0" in i["name"])
    assert gi0["admin_status"] == "up"
    assert gi0["oper_status"] == "up"
    assert gi0["ip_address"] == "192.168.1.1"


def test_ssh_get_interfaces_arista_success(monkeypatch):
    monkeypatch.setattr(ssh_mod, "NETMIKO_AVAILABLE", True)

    fake_conn = MagicMock()
    fake_conn.__enter__ = MagicMock(return_value=fake_conn)
    fake_conn.__exit__ = MagicMock(return_value=False)
    fake_conn.send_command.return_value = ARISTA_INT_STATUS

    monkeypatch.setattr(ssh_mod, "ConnectHandler", MagicMock(return_value=fake_conn))

    collector = ssh_mod.SSHCollector()
    creds = DeviceCredentials(credential_type="ssh_password", secret={"username": "admin", "password": "x"})
    result = collector.get_interfaces(_device(vendor="arista"), creds)

    assert result.success is True
    ifaces = result.data["interfaces"]
    et1 = next(i for i in ifaces if i["name"] == "Et1")
    assert et1["oper_status"] == "up"
    et2 = next(i for i in ifaces if i["name"] == "Et2")
    assert et2["oper_status"] == "down"


def test_ssh_get_interfaces_cisco_auth_failure(monkeypatch):
    monkeypatch.setattr(ssh_mod, "NETMIKO_AVAILABLE", True)

    def _raise(**kwargs):
        raise ssh_mod.NetmikoAuthenticationException("bad creds")

    monkeypatch.setattr(ssh_mod, "ConnectHandler", _raise)

    collector = ssh_mod.SSHCollector()
    creds = DeviceCredentials(credential_type="ssh_password", secret={"username": "admin", "password": "wrong"})
    result = collector.get_interfaces(_device(vendor="cisco"), creds)
    assert result.success is False
    assert "Authentication failed" in result.error

