"""Deployer registry (Phase 15). Same shape as collectors/registry.py."""
from __future__ import annotations

from typing import Dict, Optional

from app.services.deployment.base import BaseDeployer, DeploymentResult
from app.services.deployment.gnmi import GnmiDeployer
from app.services.deployment.netconf import NetconfDeployer
from app.services.deployment.ssh import SSHDeployer


_DEPLOYERS: Dict[str, BaseDeployer] = {
    "ssh": SSHDeployer(),
    "netconf": NetconfDeployer(),
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