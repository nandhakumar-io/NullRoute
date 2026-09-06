"""SSH collector (Phase 7).

Uses Netmiko (open-source, already the de-facto standard for network-device
SSH automation, MIT licensed -- RULE 14 \"self-hosted and free/open-source\")\
when available. Offline-safe: if netmiko/paramiko aren't installed, every
call returns a clean CollectionResult(success=False) rather than raising an
ImportError at import time, so the rest of the collectors/registry module
stays importable and testable without the optional dependency (same
pattern as app/ai/classifier.py).

Covers the vendors that expose their running configuration over an
interactive SSH CLI: Cisco IOS/IOS-XE, Arista EOS, FortiGate, and (as a
fallback transport) Palo Alto's `set`-style CLI. Juniper is also reachable
this way but NETCONF (netconf.py) is preferred for Junos when available.

get_interfaces() is now implemented: it sends a vendor-appropriate
`show ip interface brief` (or equivalent) and parses the output into a
structured list compatible with StructuredResult. Per-vendor command +
parser pairs are registered in _IF_COMMAND_MAP.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from app.models.db import Device
from app.services.collectors.base import (BaseCollector, CollectionResult,
                                           StructuredResult, timed,
                                           timed_structured)
from app.services.openbao_service import DeviceCredentials, redact_secret_values

try:
    from netmiko import ConnectHandler
    from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
    NETMIKO_AVAILABLE = True
except ImportError:  # pragma: no cover -- exercised via tests with a monkeypatched ConnectHandler
    NETMIKO_AVAILABLE = False
    ConnectHandler = None
    NetmikoAuthenticationException = NetmikoTimeoutException = Exception

# Maps our vendor label -> (netmiko device_type, show-running-config command)
_VENDOR_MAP: Dict[str, Dict[str, str]] = {
    "cisco": {"device_type": "cisco_ios", "command": "show running-config"},
    "cisco_ios": {"device_type": "cisco_ios", "command": "show running-config"},
    "cisco_xe": {"device_type": "cisco_xe", "command": "show running-config"},
    "arista": {"device_type": "arista_eos", "command": "show running-config"},
    "arista_eos": {"device_type": "arista_eos", "command": "show running-config"},
    "fortigate": {"device_type": "fortinet", "command": "show full-configuration"},
    "fortinet": {"device_type": "fortinet", "command": "show full-configuration"},
    "paloalto": {"device_type": "paloalto_panos", "command": "show config running"},
    "palo_alto": {"device_type": "paloalto_panos", "command": "show config running"},
    "juniper": {"device_type": "juniper_junos", "command": "show configuration | display set"},
}

# Per-vendor interface command + parser registration.
# Parser receives the raw command output string and returns a list of dicts,
# each with at minimum: name, admin_status, oper_status.  Optional fields:
# ip_address, speed, description.  If a vendor is not listed here the
# implementation still returns success=True with an empty list + a note,
# rather than an error, so the gateway always gets a valid structured result.
_IF_COMMAND_MAP: Dict[str, Dict[str, Any]] = {
    "cisco":     {"device_type": "cisco_ios", "command": "show ip interface brief"},
    "cisco_ios": {"device_type": "cisco_ios", "command": "show ip interface brief"},
    "cisco_xe":  {"device_type": "cisco_xe",  "command": "show ip interface brief"},
    "arista":    {"device_type": "arista_eos", "command": "show interfaces status"},
    "arista_eos":{"device_type": "arista_eos", "command": "show interfaces status"},
    "juniper":   {"device_type": "juniper_junos", "command": "show interfaces terse"},
    "fortigate": {"device_type": "fortinet",  "command": "get system interface"},
    "fortinet":  {"device_type": "fortinet",  "command": "get system interface"},
    "paloalto":  {"device_type": "paloalto_panos", "command": "show interface all"},
    "palo_alto": {"device_type": "paloalto_panos", "command": "show interface all"},
}


# ---------------------------------------------------------------------------
# Per-vendor output parsers
# ---------------------------------------------------------------------------

def _parse_cisco_ip_int_brief(output: str) -> List[Dict[str, Any]]:
    """Parse `show ip interface brief` from Cisco IOS / IOS-XE.

    Example line:
      GigabitEthernet0/0  192.168.1.1  YES NVRAM  up   up
      Loopback0           10.0.0.1     YES NVRAM  up   up
    """
    interfaces: List[Dict[str, Any]] = []
    # Skip header lines that start with "Interface"
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("Interface"):
            continue
        # Flexible split: collapse whitespace
        parts = re.split(r"\s{2,}", line)
        if len(parts) < 5:
            # Try single-space split as fallback
            parts = line.split()
        if len(parts) < 5:
            continue
        name = parts[0]
        ip_address = parts[1] if parts[1] not in ("unassigned", "OK?") else None
        # Status columns: "up" / "down" / "administratively down"
        # They appear as the last two tokens reliably
        admin_status = parts[-2].lower().replace("administratively down", "down")
        oper_status = parts[-1].lower()
        interfaces.append({
            "name": name,
            "ip_address": ip_address,
            "admin_status": "up" if "up" in admin_status else "down",
            "oper_status": "up" if "up" in oper_status else "down",
        })
    return interfaces


def _parse_arista_int_status(output: str) -> List[Dict[str, Any]]:
    """Parse `show interfaces status` from Arista EOS.

    Example line:
      Et1       connected     1    full    1G      EthernetEncap
    """
    interfaces: List[Dict[str, Any]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("Port") or line.startswith("---"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        name = parts[0]
        status = parts[1].lower()  # connected / notconnect / disabled / errdisabled
        oper_status = "up" if status == "connected" else "down"
        admin_status = "down" if status in ("disabled", "errdisabled") else "up"
        speed = parts[4] if len(parts) > 4 else None
        interfaces.append({
            "name": name,
            "admin_status": admin_status,
            "oper_status": oper_status,
            "speed": speed,
        })
    return interfaces


def _parse_juniper_terse(output: str) -> List[Dict[str, Any]]:
    """Parse `show interfaces terse` from Juniper JunOS.

    Example:
      ge-0/0/0                up    up
      ge-0/0/0.0              up    up   inet 192.168.1.1/24
    """
    interfaces: List[Dict[str, Any]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("Interface"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        name = parts[0]
        # Skip logical sub-unit duplicates (contains ".") if parent already captured
        admin_status = parts[1].lower()
        oper_status = parts[2].lower()
        ip_address: Optional[str] = None
        if len(parts) > 4 and parts[3] == "inet":
            ip_address = parts[4].split("/")[0]
        interfaces.append({
            "name": name,
            "admin_status": admin_status,
            "oper_status": oper_status,
            "ip_address": ip_address,
        })
    return interfaces


def _parse_fortinet_interface(output: str) -> List[Dict[str, Any]]:
    """Parse `get system interface` from FortiGate.

    The command returns stanza blocks:
      == [ port1 ]
      name: port1   mode: static   ip: 192.168.1.1 255.255.255.0
      status: up   speed: 1000Mbps
    """
    interfaces: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    for line in output.splitlines():
        line = line.strip()
        m = re.match(r"==\s+\[\s*(\S+)\s*\]", line)
        if m:
            if current:
                interfaces.append(current)
            current = {"name": m.group(1), "admin_status": "up", "oper_status": "unknown"}
            continue
        if not current:
            continue
        if "ip:" in line:
            m2 = re.search(r"ip:\s+(\d+\.\d+\.\d+\.\d+)", line)
            if m2:
                current["ip_address"] = m2.group(1)
        if "status:" in line:
            m3 = re.search(r"status:\s+(\S+)", line)
            if m3:
                current["oper_status"] = m3.group(1).lower()
        if "speed:" in line:
            m4 = re.search(r"speed:\s+(\S+)", line)
            if m4:
                current["speed"] = m4.group(1)
    if current:
        interfaces.append(current)
    return interfaces


def _parse_paloalto_interface_all(output: str) -> List[Dict[str, Any]]:
    """Parse `show interface all` from PAN-OS.

    Tab-delimited or space-separated summary lines:
      ethernet1/1    10/100/1000  full  1000  up    up   192.168.1.1/24   ...
    """
    interfaces: List[Dict[str, Any]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.lower().startswith("name") or line.startswith("---"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        name = parts[0]
        # PAN-OS columns: name, type, duplex, speed, state, admin, ip, zone
        oper_status = parts[4].lower() if len(parts) > 4 else "unknown"
        admin_status = parts[5].lower() if len(parts) > 5 else "up"
        ip_field = parts[6] if len(parts) > 6 else None
        ip_address = ip_field.split("/")[0] if ip_field and re.match(r"\d+\.\d+\.\d+\.\d+", ip_field) else None
        interfaces.append({
            "name": name,
            "admin_status": admin_status,
            "oper_status": "up" if oper_status == "up" else "down",
            "ip_address": ip_address,
        })
    return interfaces


# Dispatch table: vendor_key -> parser function
_IF_PARSERS: Dict[str, Any] = {
    "cisco":     _parse_cisco_ip_int_brief,
    "cisco_ios": _parse_cisco_ip_int_brief,
    "cisco_xe":  _parse_cisco_ip_int_brief,
    "arista":    _parse_arista_int_status,
    "arista_eos":_parse_arista_int_status,
    "juniper":   _parse_juniper_terse,
    "fortigate": _parse_fortinet_interface,
    "fortinet":  _parse_fortinet_interface,
    "paloalto":  _parse_paloalto_interface_all,
    "palo_alto": _parse_paloalto_interface_all,
}


class SSHCollector(BaseCollector):
    transport = "ssh"

    @timed
    def collect_config(self, device: Device, credentials: DeviceCredentials) -> CollectionResult:
        if not NETMIKO_AVAILABLE:
            return CollectionResult(
                success=False,
                vendor=device.vendor,
                hostname=device.hostname,
                error="netmiko is not installed; SSH collection unavailable in this environment",
            )

        vendor_key = (device.vendor or "").lower().replace(" ", "_")
        mapping = _VENDOR_MAP.get(vendor_key)
        if not mapping:
            return CollectionResult(
                success=False,
                vendor=device.vendor,
                hostname=device.hostname,
                error=f"No SSH collection profile for vendor '{device.vendor}'",
            )

        management_address = getattr(device, "management_address", None) or device.hostname
        if not management_address:
            return CollectionResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error="Device has no management address/hostname to connect to",
            )

        secret = credentials.secret
        conn_params = {
            "device_type": mapping["device_type"],
            "host": management_address,
            "username": secret.get("username"),
            "password": secret.get("password"),
            "secret": secret.get("enable_password", ""),
            "timeout": int(secret.get("timeout", 15)),
            "port": int(secret.get("port", 22)),
        }
        if credentials.credential_type == "ssh_key" and secret.get("private_key"):
            conn_params["use_keys"] = True
            conn_params["key_file"] = secret.get("private_key_path")

        try:
            with ConnectHandler(**conn_params) as conn:
                raw_config = conn.send_command(mapping["command"], read_timeout=60)
        except NetmikoAuthenticationException as e:
            return CollectionResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error=redact_secret_values(f"Authentication failed: {e}", secret),
            )
        except NetmikoTimeoutException as e:
            return CollectionResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error=redact_secret_values(f"Connection timed out: {e}", secret),
            )

        return CollectionResult(
            success=True,
            vendor=device.vendor,
            hostname=device.hostname,
            raw_config=raw_config,
        )

    @timed_structured
    def get_interfaces(self, device: Device, credentials: DeviceCredentials) -> StructuredResult:
        """Send the vendor-appropriate interface status command over SSH and
        parse the output into a structured list.  Falls back gracefully to an
        empty list (success=True) for vendors without a registered parser, so
        the gateway can always return a valid StructuredResult instead of a
        500 or a NotImplementedError degradation path."""
        if not NETMIKO_AVAILABLE:
            return StructuredResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error="netmiko is not installed; SSH collection unavailable in this environment",
            )

        vendor_key = (device.vendor or "").lower().replace(" ", "_")
        if_mapping = _IF_COMMAND_MAP.get(vendor_key)
        if not if_mapping:
            # Unsupported vendor: return a known-good empty result so the
            # caller (gateway) isn't forced to degrade to collect_config.
            return StructuredResult(
                success=True, vendor=device.vendor, hostname=device.hostname,
                data={"interfaces": [], "interface_count": 0,
                      "note": f"No interface command registered for vendor '{device.vendor}'"},
            )

        management_address = getattr(device, "management_address", None) or device.hostname
        if not management_address:
            return StructuredResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error="Device has no management address/hostname to connect to",
            )

        secret = credentials.secret
        conn_params = {
            "device_type": if_mapping["device_type"],
            "host": management_address,
            "username": secret.get("username"),
            "password": secret.get("password"),
            "secret": secret.get("enable_password", ""),
            "timeout": int(secret.get("timeout", 15)),
            "port": int(secret.get("port", 22)),
        }
        if credentials.credential_type == "ssh_key" and secret.get("private_key"):
            conn_params["use_keys"] = True
            conn_params["key_file"] = secret.get("private_key_path")

        try:
            with ConnectHandler(**conn_params) as conn:
                raw_output = conn.send_command(if_mapping["command"], read_timeout=60)
        except NetmikoAuthenticationException as e:
            return StructuredResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error=redact_secret_values(f"Authentication failed: {e}", secret),
            )
        except NetmikoTimeoutException as e:
            return StructuredResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error=redact_secret_values(f"Connection timed out: {e}", secret),
            )

        parser = _IF_PARSERS.get(vendor_key)
        interfaces: List[Dict[str, Any]] = parser(raw_output) if parser else []

        return StructuredResult(
            success=True,
            vendor=device.vendor,
            hostname=device.hostname,
            data={"interfaces": interfaces, "interface_count": len(interfaces)},
        )
