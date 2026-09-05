"""SSH collector (Phase 7).

Uses Netmiko (open-source, already the de-facto standard for network-device
SSH automation, MIT licensed -- RULE 14 "self-hosted and free/open-source")
when available. Offline-safe: if netmiko/paramiko aren't installed, every
call returns a clean CollectionResult(success=False) rather than raising an
ImportError at import time, so the rest of the collectors/registry module
stays importable and testable without the optional dependency (same
pattern as app/ai/classifier.py).

Covers the vendors that expose their running configuration over an
interactive SSH CLI: Cisco IOS/IOS-XE, Arista EOS, FortiGate, and (as a
fallback transport) Palo Alto's `set`-style CLI. Juniper is also reachable
this way but NETCONF (netconf.py) is preferred for Junos when available.
"""
from __future__ import annotations

from typing import Dict

from app.models.db import Device
from app.services.collectors.base import BaseCollector, CollectionResult, timed
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
