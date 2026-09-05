"""RESTCONF/REST collector (Phase 7).

Uses httpx (already a core dependency) -- no new optional import needed.
Covers vendors that expose configuration over a RESTCONF/REST JSON API:
Cisco IOS-XE RESTCONF and FortiGate's REST API.
"""
from __future__ import annotations

import json

import httpx

from app.models.db import Device
from app.services.collectors.base import BaseCollector, CollectionResult, timed
from app.services.openbao_service import DeviceCredentials, redact_secret_values

_RESTCONF_PATHS = {
    "cisco_xe": "/restconf/data/Cisco-IOS-XE-native:native",
    "fortigate": "/api/v2/cmdb",
    "fortinet": "/api/v2/cmdb",
}


class RestconfCollector(BaseCollector):
    transport = "restconf"

    @timed
    def collect_config(self, device: Device, credentials: DeviceCredentials) -> CollectionResult:
        vendor_key = (device.vendor or "").lower().replace(" ", "_")
        path = _RESTCONF_PATHS.get(vendor_key)
        if not path:
            return CollectionResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error=f"RESTCONF collection not supported for vendor '{device.vendor}'",
            )

        management_address = getattr(device, "management_address", None) or device.hostname
        if not management_address:
            return CollectionResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error="Device has no management address/hostname to connect to",
            )

        secret = credentials.secret
        url = f"https://{management_address}{path}"
        headers = {"Accept": "application/yang-data+json"} if vendor_key == "cisco_xe" else {"Accept": "application/json"}

        try:
            if credentials.credential_type == "restconf_token" and secret.get("token"):
                headers["Authorization"] = f"Bearer {secret['token']}"
                auth = None
            else:
                auth = (secret.get("username"), secret.get("password"))

            with httpx.Client(verify=bool(secret.get("verify_tls", False)), timeout=int(secret.get("timeout", 20))) as client:
                resp = client.get(url, headers=headers, auth=auth)
        except httpx.RequestError as e:
            return CollectionResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error=redact_secret_values(f"RESTCONF request failed: {e}", secret),
            )

        if resp.status_code == 401:
            return CollectionResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error="Authentication failed (401)",
            )
        if resp.status_code >= 300:
            return CollectionResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error=f"RESTCONF returned HTTP {resp.status_code}: {resp.text[:200]}",
            )

        try:
            raw_config = json.dumps(resp.json(), indent=2, sort_keys=True)
        except ValueError:
            raw_config = resp.text

        return CollectionResult(
            success=True,
            vendor=device.vendor,
            hostname=device.hostname,
            raw_config=raw_config,
        )
