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
from app.services.collectors.base import (BaseCollector, CollectionResult,
                                           StructuredResult, timed, timed_structured)
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


def _extract_openconfig_val(get_response: dict, key_fragment: str) -> "dict | None":
    """pygnmi's gc.get() returns {"notification": [{"update": [{"path":...,
    "val": {...}}]}]}; pull out the first update value whose path contains
    `key_fragment` (e.g. "system" or "interfaces") without depending on the
    exact path-prefix formatting, which varies slightly by target."""
    for notif in (get_response or {}).get("notification", []):
        for upd in notif.get("update", []):
            path = upd.get("path", "")
            if key_fragment in path or not path:
                return upd.get("val")
    return None


def _oc_speed_to_bps(port_speed: "str | None") -> "int | None":
    """OpenConfig SPEED_* enum (e.g. "SPEED_10GB", "openconfig-if-ethernet:SPEED_1GB")
    -> bits per second, for consistency with the bps the SNMP/SSH collectors report."""
    if not port_speed:
        return None
    s = port_speed.split(":")[-1].upper()
    _MAP = {
        "SPEED_10MB": 10_000_000, "SPEED_100MB": 100_000_000, "SPEED_1GB": 1_000_000_000,
        "SPEED_10GB": 10_000_000_000, "SPEED_25GB": 25_000_000_000, "SPEED_40GB": 40_000_000_000,
        "SPEED_100GB": 100_000_000_000, "SPEED_400GB": 400_000_000_000,
    }
    return _MAP.get(s)


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

    def _client(self, device: Device, credentials: DeviceCredentials):
        management_address = getattr(device, "management_address", None) or device.hostname
        if not management_address:
            raise ValueError("Device has no management address/hostname to connect to")
        secret = credentials.secret
        vendor_key = (device.vendor or "").lower().replace(" ", "_")
        port = int(secret.get("port", 6030 if vendor_key.startswith("arista") else 9339))
        return gNMIclient(
            target=(management_address, port),
            username=secret.get("username"),
            password=secret.get("password"),
            insecure=bool(secret.get("insecure", True)),
            skip_verify=True,
            timeout=int(secret.get("timeout", 20)),
        )

    @timed_structured
    def get_facts(self, device: Device, credentials: DeviceCredentials) -> StructuredResult:
        """gNMI Get against openconfig-system:/system/state -- hostname,
        software version, and boot time, the gNMI-native equivalent of the
        SSH "show version" facts hook. Only meaningful for the OpenConfig-
        capable subset of the fleet (_GNMI_VENDORS)."""
        if not PYGNMI_AVAILABLE:
            return StructuredResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error="pygnmi is not installed; gNMI collection unavailable in this environment",
            )
        vendor_key = (device.vendor or "").lower().replace(" ", "_")
        if vendor_key not in _GNMI_VENDORS:
            return StructuredResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error=f"gNMI collection not supported for vendor '{device.vendor}'",
            )
        secret = credentials.secret
        try:
            with self._client(device, credentials) as gc:
                response = gc.get(path=["/system/state"], encoding="json_ietf")
        except Exception as e:  # noqa: BLE001
            return StructuredResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error=redact_secret_values(f"{type(e).__name__}: {e}", secret),
            )
        state = _extract_openconfig_val(response, "state") or {}
        return StructuredResult(
            success=True, vendor=device.vendor, hostname=device.hostname,
            data={
                "hostname": state.get("hostname") or device.hostname,
                "version": state.get("software-version") or state.get("openconfig-system:software-version"),
                "boot_time": state.get("boot-time") or state.get("openconfig-system:boot-time"),
                "source": "gnmi:/system/state",
            },
        )

    @timed_structured
    def get_interfaces(self, device: Device, credentials: DeviceCredentials) -> StructuredResult:
        """gNMI Get against openconfig-interfaces:/interfaces, parsed into
        the same {"interfaces": [...], "interface_count": N} shape the
        SSH/SNMP collectors already return, so the Device Detail UI and
        gateway/connectors.py degrade-path never need to know which
        transport actually answered."""
        if not PYGNMI_AVAILABLE:
            return StructuredResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error="pygnmi is not installed; gNMI collection unavailable in this environment",
            )
        vendor_key = (device.vendor or "").lower().replace(" ", "_")
        if vendor_key not in _GNMI_VENDORS:
            return StructuredResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error=f"gNMI collection not supported for vendor '{device.vendor}'",
            )
        secret = credentials.secret
        try:
            with self._client(device, credentials) as gc:
                response = gc.get(path=["/interfaces"], encoding="json_ietf")
        except Exception as e:  # noqa: BLE001
            return StructuredResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error=redact_secret_values(f"{type(e).__name__}: {e}", secret),
            )

        interfaces = []
        container = _extract_openconfig_val(response, "interfaces") or {}
        raw_list = container.get("interface") or container.get("openconfig-interfaces:interface") or []
        for entry in raw_list:
            state = entry.get("state", {})
            interfaces.append({
                "name": entry.get("name") or state.get("name"),
                "admin_status": (state.get("admin-status") or "").lower() or None,
                "oper_status": (state.get("oper-status") or "").lower() or None,
                "speed_bps": _oc_speed_to_bps(state.get("openconfig-if-ethernet:port-speed")),
                "mac_address": None,  # under .../ethernet/state/mac-address, a second Get; omitted to keep this one round-trip
            })
        return StructuredResult(
            success=True, vendor=device.vendor, hostname=device.hostname,
            data={"interfaces": interfaces, "interface_count": len(interfaces)},
        )