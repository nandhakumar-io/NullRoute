"""Phase 16 -- unified ingestion: gNMI/RESTCONF get_facts/get_interfaces.

Extends test_collectors.py's coverage (collect_config only) to the
structured StructuredResult hooks added so gNMI and RESTCONF match the
SSH/SNMP collectors' {"interfaces": [...], "interface_count": N} contract.
"""
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx

from app.services.collectors import gnmi as gnmi_mod
from app.services.collectors import restconf as restconf_mod
from app.services.openbao_service import DeviceCredentials


def _device(vendor="cisco_xe", hostname="r1", management_address="10.0.0.1"):
    return SimpleNamespace(vendor=vendor, hostname=hostname, management_address=management_address)


# --------------------------------------------------------------------- #
# RESTCONF: Cisco IOS-XE
# --------------------------------------------------------------------- #

@respx.mock
def test_restconf_get_facts_cisco_xe():
    respx.get("https://10.0.0.1/restconf/data/ietf-yang-library:yang-library").mock(
        return_value=httpx.Response(200, json={
            "ietf-yang-library:yang-library": {"content-id": "42", "module-set": [{"name": "a"}, {"name": "b"}]}
        })
    )
    collector = restconf_mod.RestconfCollector()
    creds = DeviceCredentials(credential_type="ssh_password", secret={"username": "a", "password": "b", "verify_tls": False})
    result = collector.get_facts(_device(), creds)
    assert result.success is True
    assert result.data["yang_content_id"] == "42"
    assert result.data["module_set_count"] == 2


@respx.mock
def test_restconf_get_interfaces_cisco_xe():
    respx.get("https://10.0.0.1/restconf/data/ietf-interfaces:interfaces-state").mock(
        return_value=httpx.Response(200, json={
            "ietf-interfaces:interfaces-state": {"interface": [
                {"name": "GigabitEthernet1", "admin-status": "up", "oper-status": "up",
                 "speed": "1000000000", "phys-address": "aa:bb:cc:dd:ee:ff"},
                {"name": "GigabitEthernet2", "admin-status": "down", "oper-status": "down"},
            ]}
        })
    )
    collector = restconf_mod.RestconfCollector()
    creds = DeviceCredentials(credential_type="ssh_password", secret={"username": "a", "password": "b", "verify_tls": False})
    result = collector.get_interfaces(_device(), creds)
    assert result.success is True
    assert result.data["interface_count"] == 2
    row = result.data["interfaces"][0]
    assert row["name"] == "GigabitEthernet1"
    assert row["admin_status"] == "up"
    assert row["speed_bps"] == 1_000_000_000
    assert row["mac_address"] == "aa:bb:cc:dd:ee:ff"


# --------------------------------------------------------------------- #
# RESTCONF: FortiGate
# --------------------------------------------------------------------- #

@respx.mock
def test_restconf_get_facts_fortigate():
    respx.get("https://10.0.0.2/api/v2/monitor/system/status").mock(
        return_value=httpx.Response(200, json={"results": {"hostname": "fw1", "version": "v7.4.1", "serial": "FGT123"}})
    )
    collector = restconf_mod.RestconfCollector()
    creds = DeviceCredentials(credential_type="ssh_password", secret={"username": "a", "password": "b", "verify_tls": False})
    result = collector.get_facts(_device(vendor="fortigate", management_address="10.0.0.2"), creds)
    assert result.success is True
    assert result.data["hostname"] == "fw1"
    assert result.data["serial_number"] == "FGT123"


@respx.mock
def test_restconf_get_interfaces_fortigate():
    respx.get("https://10.0.0.2/api/v2/cmdb/system/interface").mock(
        return_value=httpx.Response(200, json={"results": [{"name": "port1", "status": "up"}]})
    )
    collector = restconf_mod.RestconfCollector()
    creds = DeviceCredentials(credential_type="ssh_password", secret={"username": "a", "password": "b", "verify_tls": False})
    result = collector.get_interfaces(_device(vendor="fortigate", management_address="10.0.0.2"), creds)
    assert result.success is True
    assert result.data["interfaces"][0]["name"] == "port1"
    assert result.data["interfaces"][0]["admin_status"] == "up"


def test_restconf_get_facts_unsupported_vendor():
    collector = restconf_mod.RestconfCollector()
    creds = DeviceCredentials(credential_type="ssh_password", secret={})
    result = collector.get_facts(_device(vendor="juniper"), creds)
    assert result.success is False
    assert "not supported" in result.error


# --------------------------------------------------------------------- #
# gNMI
# --------------------------------------------------------------------- #

def _gnmi_response_for(path_fragment: str, val: dict) -> dict:
    return {"notification": [{"update": [{"path": path_fragment, "val": val}]}]}


@pytest.mark.skipif(not gnmi_mod.PYGNMI_AVAILABLE, reason="pygnmi not installed in this environment")
def test_gnmi_get_facts_parses_system_state():
    fake_gc = MagicMock()
    fake_gc.__enter__.return_value = fake_gc
    fake_gc.__exit__.return_value = False
    fake_gc.get.return_value = _gnmi_response_for(
        "system/state", {"hostname": "sw1", "software-version": "4.28.0F"}
    )
    collector = gnmi_mod.GNMICollector()
    creds = DeviceCredentials(credential_type="gnmi", secret={"username": "a", "password": "b"})
    with patch.object(gnmi_mod.GNMICollector, "_client", return_value=fake_gc):
        result = collector.get_facts(_device(vendor="arista"), creds)
    assert result.success is True
    assert result.data["hostname"] == "sw1"
    assert result.data["version"] == "4.28.0F"


@pytest.mark.skipif(not gnmi_mod.PYGNMI_AVAILABLE, reason="pygnmi not installed in this environment")
def test_gnmi_get_interfaces_parses_openconfig_list():
    fake_gc = MagicMock()
    fake_gc.__enter__.return_value = fake_gc
    fake_gc.__exit__.return_value = False
    fake_gc.get.return_value = _gnmi_response_for("interfaces", {"interface": [
        {"name": "Ethernet1", "state": {"admin-status": "UP", "oper-status": "UP",
                                          "openconfig-if-ethernet:port-speed": "SPEED_10GB"}},
    ]})
    collector = gnmi_mod.GNMICollector()
    creds = DeviceCredentials(credential_type="gnmi", secret={"username": "a", "password": "b"})
    with patch.object(gnmi_mod.GNMICollector, "_client", return_value=fake_gc):
        result = collector.get_interfaces(_device(vendor="arista"), creds)
    assert result.success is True
    assert result.data["interface_count"] == 1
    row = result.data["interfaces"][0]
    assert row["name"] == "Ethernet1"
    assert row["speed_bps"] == 10_000_000_000


def test_gnmi_get_facts_unsupported_vendor():
    collector = gnmi_mod.GNMICollector()
    creds = DeviceCredentials(credential_type="gnmi", secret={})
    result = collector.get_facts(_device(vendor="fortigate"), creds)
    assert result.success is False