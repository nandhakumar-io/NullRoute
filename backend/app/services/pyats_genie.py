"""pyATS/Genie verifier (spec sections 29-34).

Optional supplemental post-deployment verification for Cisco devices
only -- Genie provides structured parsing of operational CLI output
(`device.parse()`). This is never authoritative for compliance (OPA) or
network behavior (Batfish); it only adds structured evidence.

Same optional-dependency pattern as every other transport in this
codebase: importable/testable even when pyats/genie aren't installed,
degrading to an explicit PYATS_UNAVAILABLE result rather than failing to
import. Credentials are resolved by the caller and passed in for the
single connect() call only -- never logged, cached, or persisted
(RULE 6); no testbed YAML file with embedded credentials is ever written
to disk.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List

from app.models.db import Device
from app.services.openbao_service import DeviceCredentials
from app.services.verification.base import (
    PYATS_DISABLED, PYATS_FAILED, PYATS_OK, PYATS_UNAVAILABLE,
    PYATS_UNSUPPORTED, BaseVerifier, VerificationResult, timed,
)

try:
    from pyats.topology import loader as pyats_loader
    PYATS_AVAILABLE = True
except ImportError:  # pragma: no cover
    PYATS_AVAILABLE = False
    pyats_loader = None

# Only Cisco platforms are supported (spec section 29/32) -- do not
# assume a Genie parser exists for every platform. os key must match
# what pyATS testbed `os:` expects.
_SUPPORTED_CISCO_OS = {"cisco_ios": "ios", "cisco_xe": "iosxe", "cisco": "ios"}

_DEFAULT_COMMANDS = ["show interfaces", "show ip route", "show vlan"]


def _flag(name: str, default: str = "false") -> bool:
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes", "on")


def _commands() -> List[str]:
    raw = os.environ.get("PYATS_VERIFY_COMMANDS")
    if not raw:
        return list(_DEFAULT_COMMANDS)
    return [c.strip() for c in raw.split(",") if c.strip()]


class PyatsGenieVerifier(BaseVerifier):
    engine = "pyats_genie"

    @timed
    def verify(self, device: Device, credentials: DeviceCredentials) -> VerificationResult:
        if not _flag("PYATS_ENABLED"):
            return VerificationResult(success=False, status=PYATS_DISABLED,
                                       error="pyATS/Genie verification is disabled (PYATS_ENABLED=false)")
        if not PYATS_AVAILABLE:
            return VerificationResult(success=False, status=PYATS_UNAVAILABLE,
                                       error="pyats/genie is not installed; verification unavailable in this environment")

        vendor_key = (device.vendor or "").lower().replace(" ", "_")
        pyats_os = _SUPPORTED_CISCO_OS.get(vendor_key)
        if not pyats_os:
            return VerificationResult(success=False, status=PYATS_UNSUPPORTED,
                                       error=f"pyATS/Genie verification is only supported for Cisco devices; got vendor '{device.vendor}'")

        management_address = getattr(device, "management_address", None) or device.hostname
        if not management_address:
            return VerificationResult(success=False, status=PYATS_FAILED,
                                       error="Device has no management address/hostname to connect to")

        secret = credentials.secret
        timeout = int(os.environ.get("PYATS_TIMEOUT", 30))

        # Built entirely in memory -- never written to disk -- so
        # credentials never touch a testbed YAML file (RULE 6).
        testbed_dict: Dict[str, Any] = {
            "devices": {
                device.hostname or management_address: {
                    "os": pyats_os,
                    "credentials": {
                        "default": {
                            "username": secret.get("username"),
                            "password": secret.get("password"),
                        }
                    },
                    "connections": {
                        "cli": {
                            "protocol": "ssh",
                            "ip": management_address,
                            "port": int(secret.get("port", 22)),
                        }
                    },
                }
            }
        }

        try:
            testbed = pyats_loader.load(testbed_dict)
            genie_device = testbed.devices[device.hostname or management_address]
            genie_device.connect(connection_timeout=timeout, log_stdout=False)
        except Exception as e:  # noqa: BLE001 -- pyATS raises many connection-specific exceptions
            return VerificationResult(success=False, status=PYATS_FAILED,
                                       error=f"pyATS connect() failed: {type(e).__name__}: {e}")

        parsed: Dict[str, Any] = {}
        commands_run: List[str] = []
        unsupported: List[str] = []
        try:
            for cmd in _commands():
                try:
                    parsed[cmd] = genie_device.parse(cmd)
                    commands_run.append(cmd)
                except Exception as e:  # noqa: BLE001 -- SchemaEmptyParserError / unsupported parser, etc.
                    unsupported.append(f"{cmd}: {type(e).__name__}: {e}")
        finally:
            try:
                genie_device.disconnect()
            except Exception:  # noqa: BLE001 -- best-effort cleanup only
                pass

        if not commands_run:
            return VerificationResult(
                success=False, status=PYATS_UNSUPPORTED,
                error=f"No supported Genie parser produced output for this device: {unsupported}",
            )

        return VerificationResult(
            success=True, status=PYATS_OK, commands_run=commands_run, parsed=parsed,
            error=("; ".join(unsupported) if unsupported else None),
        )