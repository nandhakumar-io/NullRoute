"""Deployer registry (Phase 15). Same shape as collectors/registry.py.

NETCONF push is not implemented in this phase (only SSH `send_config_set`
is available today); requesting transport="netconf" returns a clean
NotImplementedError-carrying DeploymentResult rather than pretending to
succeed.
"""
from __future__ import annotations

from typing import Dict, Optional

from app.services.deployment.base import BaseDeployer, DeploymentResult
from app.services.deployment.gnmi import GnmiDeployer
from app.services.deployment.ssh import SSHDeployer


class _UnsupportedDeployer(BaseDeployer):
    transport = "netconf"

    def push_config(self, device, credentials, config_lines) -> DeploymentResult:
        return DeploymentResult(success=False, transport=self.transport,
                                 error="NETCONF deployment is not yet implemented")


_DEPLOYERS: Dict[str, BaseDeployer] = {
    "ssh": SSHDeployer(),
    "netconf": _UnsupportedDeployer(),
    # Optional standards-based transport (spec sections 22-28). Disabled
    # by default via GNMI_ENABLED; GnmiDeployer itself returns an explicit
    # GNMI_DISABLED/GNMI_UNAVAILABLE/... DeploymentResult rather than the
    # registry silently omitting or substituting another transport.
    "gnmi": GnmiDeployer(),
}


def get_deployer(transport: Optional[str] = None) -> BaseDeployer:
    key = transport or "ssh"
    if key not in _DEPLOYERS:
        raise ValueError(f"Unknown deployment transport '{key}'; must be one of {sorted(_DEPLOYERS)}")
    return _DEPLOYERS[key]