"""gNMI deployer (spec sections 22-28) -- bridges the standalone gNMI
config-injection layer (services/config_injection/) into the existing
BaseDeployer interface so it flows through the SAME ChangeRequest
approval/pre-hash/post-verification pipeline as SSH (services/
deployment_service.py) without a second deployment workflow (RULE 24
"Never allow AI -> gNMI Set" / "browser -> gNMI Set" is enforced upstream
by that pipeline already requiring status == APPROVED).

The proposed configuration for a gNMI change request is authored as a
JSON array of {"path", "value", "model", "operation"} objects (rather
than raw CLI lines) -- that's what config_lines contains for this
transport. Anything else is an explicit GNMI_SCHEMA_MISMATCH, not a best-
effort parse.
"""
from __future__ import annotations

import json
from typing import List

from app.models.db import Device
from app.services.config_injection.registry import get_injector
from app.services.config_injection.result import GNMI_SCHEMA_MISMATCH, GnmiUpdate
from app.services.deployment.base import BaseDeployer, DeploymentResult, timed
from app.services.openbao_service import DeviceCredentials


def _parse_updates(config_lines: List[str]) -> List[GnmiUpdate]:
    text = "\n".join(config_lines).strip()
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(
            f"gNMI proposed configuration must be a JSON array of "
            f"{{path, value, model, operation}} objects: {e}"
        )
    if not isinstance(raw, list):
        raise ValueError("gNMI proposed configuration must be a JSON array")

    updates: List[GnmiUpdate] = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict) or "path" not in item or "model" not in item:
            raise ValueError(f"gNMI update #{i} is missing required 'path'/'model' fields")
        updates.append(GnmiUpdate(
            path=item["path"], value=item.get("value"), model=item["model"],
            operation=item.get("operation", "update"),
        ))
    return updates


class GnmiDeployer(BaseDeployer):
    transport = "gnmi"

    @timed
    def push_config(self, device: Device, credentials: DeviceCredentials, config_lines: List[str]) -> DeploymentResult:
        try:
            updates = _parse_updates(config_lines)
        except ValueError as e:
            return DeploymentResult(success=False, error=f"{GNMI_SCHEMA_MISMATCH}: {e}")

        injector = get_injector("gnmi")

        caps_result = injector.capabilities(device, credentials)
        if not caps_result.success:
            return DeploymentResult(
                success=False,
                error=f"{caps_result.status}: gNMI Capabilities() check failed before Set(): {caps_result.error}",
            )

        set_result = injector.set(device, credentials, updates)
        output = json.dumps(set_result.as_metadata(), default=str)
        if not set_result.success:
            return DeploymentResult(success=False, output=output, error=f"{set_result.status}: {set_result.error}")

        return DeploymentResult(success=True, output=output)