"""SSH deployer (Phase 15).

Uses Netmiko's `send_config_set`, same optional-dependency pattern as
services/collectors/ssh.py: importable/testable even when netmiko isn't
installed, degrading to a clean DeploymentResult(success=False).
"""
from __future__ import annotations

from typing import Dict, List

from app.models.db import Device
from app.services.deployment.base import BaseDeployer, DeploymentResult, timed
from app.services.openbao_service import DeviceCredentials

try:
    from netmiko import ConnectHandler
    from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
    NETMIKO_AVAILABLE = True
except ImportError:  # pragma: no cover
    NETMIKO_AVAILABLE = False
    ConnectHandler = None
    NetmikoAuthenticationException = NetmikoTimeoutException = Exception

_VENDOR_DEVICE_TYPE: Dict[str, str] = {
    "cisco": "cisco_ios", "cisco_ios": "cisco_ios", "cisco_xe": "cisco_xe",
    "arista": "arista_eos", "arista_eos": "arista_eos",
    "fortigate": "fortinet", "fortinet": "fortinet",
    "paloalto": "paloalto_panos", "palo_alto": "paloalto_panos",
    "juniper": "juniper_junos",
}


class SSHDeployer(BaseDeployer):
    transport = "ssh"

    @timed
    def push_config(self, device: Device, credentials: DeviceCredentials, config_lines: List[str]) -> DeploymentResult:
        if not NETMIKO_AVAILABLE:
            return DeploymentResult(success=False, error="netmiko is not installed; SSH deployment unavailable in this environment")

        vendor_key = (device.vendor or "").lower().replace(" ", "_")
        device_type = _VENDOR_DEVICE_TYPE.get(vendor_key)
        if not device_type:
            return DeploymentResult(success=False, error=f"No SSH deployment profile for vendor '{device.vendor}'")

        management_address = getattr(device, "management_address", None) or device.hostname
        if not management_address:
            return DeploymentResult(success=False, error="Device has no management address/hostname to connect to")

        secret = credentials.secret
        conn_params = {
            "device_type": device_type,
            "host": management_address,
            "username": secret.get("username"),
            "password": secret.get("password"),
            "secret": secret.get("enable_password", ""),
            "timeout": int(secret.get("timeout", 20)),
            "port": int(secret.get("port", 22)),
            "ssh_config_file": "/opt/NullRoute/backend/.ssh_config",
        }

        try:
            with ConnectHandler(**conn_params) as conn:
                output = conn.send_config_set(config_lines, read_timeout=90)
                try:
                    conn.save_config()
                except Exception:  # noqa: BLE001 -- not every vendor/device_type supports save_config()
                    pass
        except NetmikoAuthenticationException as e:
            return DeploymentResult(success=False, error=f"Authentication failed: {e}")
        except NetmikoTimeoutException as e:
            return DeploymentResult(success=False, error=f"Connection timed out: {e}")

        return DeploymentResult(success=True, output=output)