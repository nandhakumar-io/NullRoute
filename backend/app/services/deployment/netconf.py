"""NETCONF deployer (Phase 15).

Pushes configuration changes to a NETCONF-capable device using ncclient's
``edit-config`` operation.  The configuration lines are expected in Juniper
set-format or Cisco XML format depending on the vendor.

Same optional-dependency pattern as every other service in this package:
importable and testable even when ncclient is not installed -- degrading to a
clean DeploymentResult(success=False) rather than an ImportError.
"""
from __future__ import annotations

from typing import List

from app.models.db import Device
from app.services.deployment.base import BaseDeployer, DeploymentResult, timed
from app.services.openbao_service import DeviceCredentials, redact_secret_values

try:
    from ncclient import manager as ncclient_manager
    NCCLIENT_AVAILABLE = True
except ImportError:  # pragma: no cover
    NCCLIENT_AVAILABLE = False
    ncclient_manager = None

_NETCONF_VENDORS = {"juniper", "cisco_xe", "cisco"}


def _juniper_set_rpc(config_lines: List[str]) -> str:
    """Build a Juniper load-override RPC from a list of set-format lines."""
    set_text = "\n".join(config_lines)
    return f"""
<load-configuration action="set" format="text">
  <configuration-set>
{set_text}
  </configuration-set>
</load-configuration>
"""


def _cisco_edit_config_xml(config_lines: List[str]) -> str:
    """Wrap text config in a minimal XML edit-config payload for Cisco devices."""
    body = "\n".join(f"    <cli-config-data-block>{line}</cli-config-data-block>" for line in config_lines)
    return (
        "<config>"
        "<cli-config-data xmlns=\"http://cisco.com/ns/yang/Cisco-IOS-XE-native\">"
        f"{body}"
        "</cli-config-data>"
        "</config>"
    )


class NetconfDeployer(BaseDeployer):
    transport = "netconf"

    @timed
    def push_config(self, device: Device, credentials: DeviceCredentials, config_lines: List[str]) -> DeploymentResult:
        if not NCCLIENT_AVAILABLE:
            return DeploymentResult(
                success=False,
                transport=self.transport,
                error="ncclient is not installed; NETCONF deployment unavailable in this environment",
            )

        vendor_key = (device.vendor or "").lower().replace(" ", "_")
        if vendor_key not in _NETCONF_VENDORS:
            return DeploymentResult(
                success=False,
                transport=self.transport,
                error=f"NETCONF deployment not supported for vendor '{device.vendor}'; "
                      f"supported: {sorted(_NETCONF_VENDORS)}",
            )

        management_address = getattr(device, "management_address", None) or device.hostname
        if not management_address:
            return DeploymentResult(
                success=False, transport=self.transport,
                error="Device has no management address/hostname to connect to",
            )

        secret = credentials.secret
        device_params = {"name": "junos"} if vendor_key == "juniper" else None

        try:
            with ncclient_manager.connect(
                host=management_address,
                port=int(secret.get("port", 830)),
                username=secret.get("username"),
                password=secret.get("password"),
                hostkey_verify=False,
                device_params=device_params,
                timeout=int(secret.get("timeout", 30)),
            ) as m:
                if vendor_key == "juniper":
                    # Juniper: load-override with set-format text
                    rpc_xml = _juniper_set_rpc(config_lines)
                    m.dispatch(ncclient_manager.to_ele(rpc_xml))
                    # Commit the candidate
                    m.commit()
                    output = "Juniper NETCONF load + commit succeeded"
                else:
                    # Cisco XE / generic: edit-config running
                    config_xml = _cisco_edit_config_xml(config_lines)
                    m.edit_config(target="running", config=config_xml)
                    output = "NETCONF edit-config on running datastore succeeded"

        except Exception as e:  # noqa: BLE001
            return DeploymentResult(
                success=False,
                transport=self.transport,
                error=redact_secret_values(f"{type(e).__name__}: {e}", secret),
            )

        return DeploymentResult(success=True, transport=self.transport, output=output)
