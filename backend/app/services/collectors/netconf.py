"""NETCONF collector (Phase 7).

Uses ncclient (open-source, MIT/Apache-licensed) when available. Offline-safe
fallback mirrors ssh.py: no ImportError at module import time if ncclient
isn't installed, only a failed CollectionResult at call time.
"""
from __future__ import annotations

from app.models.db import Device
from app.services.collectors.base import BaseCollector, CollectionResult, timed
from app.services.openbao_service import DeviceCredentials, redact_secret_values

try:
    from ncclient import manager as ncclient_manager
    NCCLIENT_AVAILABLE = True
except ImportError:  # pragma: no cover
    NCCLIENT_AVAILABLE = False
    ncclient_manager = None

_NETCONF_VENDORS = {"juniper", "cisco_xe", "cisco"}


class NetconfCollector(BaseCollector):
    transport = "netconf"

    @timed
    def collect_config(self, device: Device, credentials: DeviceCredentials) -> CollectionResult:
        if not NCCLIENT_AVAILABLE:
            return CollectionResult(
                success=False,
                vendor=device.vendor,
                hostname=device.hostname,
                error="ncclient is not installed; NETCONF collection unavailable in this environment",
            )

        vendor_key = (device.vendor or "").lower().replace(" ", "_")
        if vendor_key not in _NETCONF_VENDORS:
            return CollectionResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error=f"NETCONF collection not supported for vendor '{device.vendor}'",
            )

        management_address = getattr(device, "management_address", None) or device.hostname
        if not management_address:
            return CollectionResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
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
                timeout=int(secret.get("timeout", 20)),
            ) as m:
                reply = m.get_config(source="running")
                raw_config = reply.data_xml
        except Exception as e:  # noqa: BLE001 -- ncclient raises many transport-specific errors
            return CollectionResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error=redact_secret_values(f"{type(e).__name__}: {e}", secret),
            )

        return CollectionResult(
            success=True,
            vendor=device.vendor,
            hostname=device.hostname,
            raw_config=raw_config,
        )
