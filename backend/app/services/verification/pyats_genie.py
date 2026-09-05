"""pyATS/Genie supplemental verification adapter (spec sections 29-34).

Cisco-only, optional, and never authoritative. If PYATS_ENABLED is not
set, the library isn't installed, or no Genie parser exists for any of
the configured commands, this returns an explicit non-success
VerificationResult (PYATS_DISABLED / PYATS_UNAVAILABLE / PYATS_UNSUPPORTED)
instead of raising -- a missing parser must never fail the whole
compliance scan (section 32).

Credentials come from OpenBao via the same DeviceCredentials object used
everywhere else and are assembled into an in-memory pyATS testbed dict
for the duration of this call only -- never written to disk, never
logged (section 31).
"""
from __future__ import annotations

import os
from typing import Any, Dict, List

from app.models.db import Device
from app.services.openbao_service import DeviceCredentials, redact_secret_values
from app.services.verification.base import (
    PYATS_DISABLED, PYATS_FAILED, PYATS_OK, PYATS_UNAVAILABLE,
    PYATS_UNSUPPORTED, BaseVerifier, VerificationResult,
)

try:
    from pyats.topology import loader as pyats_loader
    PYATS_AVAILABLE = True
except ImportError:  # pragma: no cover
    PYATS_AVAILABLE = False
    pyats_loader = None

_CISCO_VENDOR_KEYS = {"cisco", "cisco_ios", "cisco_xe", "cisco_ios_xe"}

# Conservative default set of commands known to have Genie parsers on
# IOS/IOS-XE. Overridable via PYATS_VERIFY_COMMANDS (comma-separated).
_DEFAULT_COMMANDS = ["show interfaces", "show ip route", "show vlan"]


def _pyats_enabled() -> bool:
    return os.environ.get("PYATS_ENABLED", "false").strip().lower() == "true"


def _configured_commands() -> List[str]:
    raw = os.environ.get("PYATS_VERIFY_COMMANDS", "").strip()
    if not raw:
        return list(_DEFAULT_COMMANDS)
    return [c.strip() for c in raw.split(",") if c.strip()]


def _build_testbed_dict(device: Device, credentials: DeviceCredentials) -> Dict[str, Any]:
    secret = credentials.secret
    management_address = getattr(device, "management_address", None) or device.hostname
    return {
        "devices": {
            device.hostname: {
                "os": "iosxe",
                "type": "router",
                "connections": {
                    "cli": {
                        "protocol": "ssh",
                        "ip": management_address,
                        "port": int(secret.get("port", 22)),
                    }
                },
                "credentials": {
                    "default": {
                        "username": secret.get("username"),
                        "password": secret.get("password"),
                    }
                },
            }
        }
    }


class PyatsGenieVerifier(BaseVerifier):
    engine = "pyats_genie"

    def verify(self, device: Device, credentials: DeviceCredentials) -> VerificationResult:
        if not _pyats_enabled():
            return VerificationResult(engine=self.engine, success=False, status=PYATS_DISABLED,
                                       error="PYATS_ENABLED is not set to true")

        if not PYATS_AVAILABLE:
            return VerificationResult(engine=self.engine, success=False, status=PYATS_UNAVAILABLE,
                                       error="pyats/genie is not installed")

        vendor_key = (device.vendor or "").lower().replace(" ", "_")
        if vendor_key not in _CISCO_VENDOR_KEYS:
            return VerificationResult(engine=self.engine, success=False, status=PYATS_UNSUPPORTED,
                                       error=f"no Genie support for vendor '{device.vendor}'; Cisco-only")

        testbed_dict = _build_testbed_dict(device, credentials)
        secret = credentials.secret
        try:
            tb = pyats_loader.load(testbed_dict)
            dev = tb.devices[device.hostname]
        except Exception as e:  # noqa: BLE001 -- must degrade, never crash the deployment flow
            return VerificationResult(
                engine=self.engine, success=False, status=PYATS_FAILED,
                error=redact_secret_values(f"failed to load testbed: {type(e).__name__}: {e}", secret))

        try:
            dev.connect(log_stdout=False, learn_hostname=False, init_config_commands=[])
        except Exception as e:  # noqa: BLE001
            return VerificationResult(
                engine=self.engine, success=False, status=PYATS_FAILED,
                error=redact_secret_values(f"failed to connect: {type(e).__name__}: {e}", secret))

        commands = _configured_commands()
        commands_run: List[str] = []
        unsupported: List[str] = []
        parsed: Dict[str, Any] = {}
        try:
            for cmd in commands:
                try:
                    parsed[cmd] = dev.parse(cmd)
                    commands_run.append(cmd)
                except Exception:  # noqa: BLE001 -- e.g. SchemaEmptyParserError; a missing parser, not a crash
                    unsupported.append(cmd)
        finally:
            dev.disconnect()

        if not commands_run:
            return VerificationResult(engine=self.engine, success=False, status=PYATS_UNSUPPORTED,
                                       commands_run=[], error=f"no known Genie parser succeeded for any of {commands}")

        error = f"no Genie parser available for: {unsupported}" if unsupported else None
        return VerificationResult(engine=self.engine, success=True, status=PYATS_OK,
                                   commands_run=commands_run, data=parsed, error=error)
