"""gNMI collector (ingestion side).

Complements services/gnmi.py (the gNMI *deployer*, which pushes Set RPCs
through the ChangeRequest approval pipeline). This module only issues a
read-only gNMI Get against OpenConfig paths to pull current device
state/config for the compliance pipeline -- it never calls Set.

Uses pygnmi when available (already a declared, optional dependency for
the config-injection layer -- see requirements.txt). Offline-safe fallback
mirrors every other collector in this package: no ImportError at module
import time, only a failed CollectionResult at call time.

Scope note: a gNMI Get against `/` or a small set of OpenConfig subtrees
returns structured JSON state, not vendor CLI text. That JSON is still
valid input to the normalization/AI pipeline (services/ai/normalize.py
already handles non-CLI structured input for SONiC), so `raw_config` here
is the pretty-printed JSON of the Get response.
"""
from __future__ import annotations

import json

from app.models.db import Device
from app.services.collectors.base import BaseCollector, CollectionResult, timed
from app.services.openbao_service import DeviceCredentials, redact_secret_values

try:
    from pygnmi.client import gNMIclient
    PYGNMI_AVAILABLE = True
except ImportError:  # pragma: no cover
    PYGNMI_AVAILABLE = False
    gNMIclient = None

# Vendors in this fleet that expose an OpenConfig gNMI target alongside
# their native CLI transport (Arista EOS and Cisco IOS-XE ship gNMI by
# default when configured; Juniper via a separate mgmd process).
_GNMI_VENDORS = {"arista", "arista_eos", "cisco_xe", "juniper"}

# Small, vendor-neutral set of OpenConfig subtrees good enough to establish
# reachability/identity and surface interface + system config for the
# compliance baseline. Deliberately not exhaustive -- unlike SSH/NETCONF/
# RESTCONF this is a supplementary ingestion path, not the primary one.
_DEFAULT_PATHS = ["/system/config", "/interfaces"]


class GNMICollector(BaseCollector):
    transport = "gnmi"

    @timed
    def collect_config(self, device: Device, credentials: DeviceCredentials) -> CollectionResult:
        if not PYGNMI_AVAILABLE:
            return CollectionResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error="pygnmi is not installed; gNMI collection unavailable in this environment",
            )

        vendor_key = (device.vendor or "").lower().replace(" ", "_")
        if vendor_key not in _GNMI_VENDORS:
            return CollectionResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error=f"gNMI collection not supported for vendor '{device.vendor}'",
            )

        management_address = getattr(device, "management_address", None) or device.hostname
        if not management_address:
            return CollectionResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error="Device has no management address/hostname to connect to",
            )

        secret = credentials.secret
        port = int(secret.get("port", 6030 if vendor_key.startswith("arista") else 9339))

        try:
            with gNMIclient(
                target=(management_address, port),
                username=secret.get("username"),
                password=secret.get("password"),
                insecure=bool(secret.get("insecure", True)),
                skip_verify=True,
                timeout=int(secret.get("timeout", 20)),
            ) as gc:
                response = gc.get(path=_DEFAULT_PATHS, encoding="json_ietf")
        except Exception as e:  # noqa: BLE001 -- pygnmi/grpc raise many transport-specific errors
            return CollectionResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error=redact_secret_values(f"{type(e).__name__}: {e}", secret),
            )

        raw_config = json.dumps(response, indent=2, default=str)
        return CollectionResult(
            success=True,
            vendor=device.vendor,
            hostname=device.hostname,
            raw_config=raw_config,
        )
