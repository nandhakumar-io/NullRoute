"""gNMI deployer -- bridges the ChangeRequest/deployment pipeline (which
speaks BaseDeployer.push_config(device, credentials, config_lines: List[str]))
into the structured OpenConfig/gNMI injector in
app/services/config_injection/ (spec sections 22-28, 35).

`config_lines` for this transport is a single-element list containing a
JSON array of update objects, produced upstream from the validated,
approved ChangeRequest:

    ['[{"path": "...", "value": true,
        "model": "openconfig-interfaces", "operation": "update"}]']

This keeps deployment_service.py itself transport-agnostic (it doesn't
need to know gNMI exists) while giving the gNMI path the structured
request it actually needs, instead of a flat command-line list.
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
    if not config_lines:
        raise ValueError(f"{GNMI_SCHEMA_MISMATCH}: empty gNMI request payload")
    try:
        raw = json.loads(config_lines[0])
    except (json.JSONDecodeError, TypeError) as e:
        raise ValueError(f"{GNMI_SCHEMA_MISMATCH}: gNMI request payload is not valid JSON: {e}")
    if not isinstance(raw, list) or not raw:
        raise ValueError(f"{GNMI_SCHEMA_MISMATCH}: gNMI request payload must be a non-empty JSON array of updates")
    try:
        return [GnmiUpdate(path=u["path"], value=u.get("value"), model=u["model"], operation=u["operation"]) for u in raw]
    except (KeyError, TypeError) as e:
        raise ValueError(f"{GNMI_SCHEMA_MISMATCH}: malformed gNMI update entry: {e}")


class GnmiDeployer(BaseDeployer):
    transport = "gnmi"

    @timed
    def push_config(self, device: Device, credentials: DeviceCredentials, config_lines: List[str]) -> DeploymentResult:
        try:
            updates = _parse_updates(config_lines)
        except ValueError as e:
            return DeploymentResult(success=False, error=str(e))

        injector = get_injector("gnmi")
        result = injector.set(device, credentials, updates)
        if not result.success:
            return DeploymentResult(success=False, error=f"{result.status}: {result.error}")

        metadata = {
            "request_hash": result.request_hash,
            "model": updates[0].model,
            "paths": [u.path for u in updates],
            "operation": updates[0].operation,
            "response": result.data,
        }
        return DeploymentResult(success=True, output=json.dumps(metadata, default=str))
