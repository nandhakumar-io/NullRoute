"""SSH deployer (Phase 15).

Uses Netmiko's `send_config_set`, same optional-dependency pattern as
services/collectors/ssh.py: importable/testable even when netmiko isn't
installed, degrading to a clean DeploymentResult(success=False).
"""
from __future__ import annotations

import os
from typing import Dict, List

from app.models.db import Device
from app.services.deployment.base import BaseDeployer, DeploymentResult, timed
from app.services.openbao_service import DeviceCredentials, redact_secret_values

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
        conn_params = _conn_params(device_type, management_address, secret)
        is_junos = device_type == "juniper_junos"

        try:
            with ConnectHandler(**conn_params) as conn:
                if is_junos:
                    # Junos needs an explicit commit (save_config() is not
                    # implemented and used to be silently skipped, so nothing
                    # ever landed). `commit confirmed` auto-reverts the device
                    # if we lose it; confirm_commit() finalises after verify.
                    output = conn.send_config_set(config_lines, read_timeout=90, exit_config_mode=False)
                    output += "\n" + conn.commit(confirm=True, confirm_delay=JUNOS_CONFIRM_MINUTES, comment="NetSecAuditor change request")
                    try:
                        conn.exit_config_mode()
                    except Exception:  # noqa: BLE001
                        pass
                    return DeploymentResult(success=True, output=output, pending_confirm=True)
                output = conn.send_config_set(config_lines, read_timeout=90)
                try:
                    conn.save_config()
                except Exception:  # noqa: BLE001 -- not every vendor/device_type supports save_config()
                    pass
        except NetmikoAuthenticationException as e:
            return DeploymentResult(success=False, error=redact_secret_values(f"Authentication failed: {e}", secret))
        except NetmikoTimeoutException as e:
            return DeploymentResult(success=False, error=redact_secret_values(f"Connection timed out: {e}", secret))

        return DeploymentResult(success=True, output=output)

    def confirm_commit(self, device: Device, credentials: DeviceCredentials) -> DeploymentResult:
        if not NETMIKO_AVAILABLE:
            return DeploymentResult(success=False, transport=self.transport, error="netmiko is not installed")
        device_type = _VENDOR_DEVICE_TYPE.get((device.vendor or "").lower().replace(" ", "_"))
        if device_type != "juniper_junos":
            return DeploymentResult(success=True, transport=self.transport, output="nothing to confirm")
        secret = credentials.secret
        addr = getattr(device, "management_address", None) or device.hostname
        try:
            with ConnectHandler(**_conn_params(device_type, addr, secret)) as conn:
                out = conn.commit(comment="NetSecAuditor confirm")
                try:
                    conn.exit_config_mode()
                except Exception:  # noqa: BLE001
                    pass
            return DeploymentResult(success=True, transport=self.transport, output=out)
        except Exception as e:  # noqa: BLE001
            return DeploymentResult(success=False, transport=self.transport,
                                    error=redact_secret_values(f"Commit confirm failed: {e}", secret))


# Minutes the device waits for confirmation before auto-reverting (Junos).
JUNOS_CONFIRM_MINUTES = int(os.getenv("JUNOS_COMMIT_CONFIRM_MINUTES", "5"))


def _conn_params(device_type: str, host: str, secret: dict) -> dict:
    params = {
        "device_type": device_type,
        "host": host,
        "username": secret.get("username"),
        "password": secret.get("password"),
        "secret": secret.get("enable_password", ""),
        "timeout": int(secret.get("timeout", 20)),
        "port": int(secret.get("port", 22)),
    }
    ssh_cfg = os.getenv("SSH_CONFIG_FILE", "/opt/NullRoute/backend/.ssh_config")
    if ssh_cfg and os.path.exists(ssh_cfg):
        params["ssh_config_file"] = ssh_cfg
    return params
