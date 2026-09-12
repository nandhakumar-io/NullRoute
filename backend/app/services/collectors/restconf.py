"""RESTCONF/REST collector (Phase 7).

Uses httpx (already a core dependency) -- no new optional import needed.
Covers vendors that expose configuration over a RESTCONF/REST JSON API:
Cisco IOS-XE RESTCONF and FortiGate's REST API.
"""
from __future__ import annotations

import json
from typing import Optional

import httpx

from app.models.db import Device
from app.services.collectors.base import (BaseCollector, CollectionResult,
                                           StructuredResult, timed, timed_structured)
from app.services.openbao_service import DeviceCredentials, redact_secret_values

_RESTCONF_PATHS = {
    "cisco_xe": "/restconf/data/Cisco-IOS-XE-native:native",
    "fortigate": "/api/v2/cmdb",
    "fortinet": "/api/v2/cmdb",
}

# ietf-interfaces:interfaces-state is the RFC 7223 standard read-only
# operational-state container -- present on any RESTCONF-capable Cisco
# IOS-XE box regardless of native-model variant, so it's used for
# get_interfaces() instead of the vendor-native Cisco-IOS-XE-native path
# used by collect_config() (which is deliberately the full native config).
_IETF_INTERFACES_STATE_PATH = "/restconf/data/ietf-interfaces:interfaces-state"
_IETF_YANG_LIBRARY_PATH = "/restconf/data/ietf-yang-library:yang-library"
_FORTIGATE_STATUS_PATH = "/api/v2/monitor/system/status"
_FORTIGATE_INTERFACE_PATH = "/api/v2/cmdb/system/interface"

_ADMIN_STATUS_MAP = {"up": "up", "down": "down", "testing": "testing"}


def _client_kwargs(credentials: DeviceCredentials) -> dict:
    secret = credentials.secret
    headers = {"Accept": "application/json"}
    auth = None
    if credentials.credential_type == "restconf_token" and secret.get("token"):
        headers["Authorization"] = f"Bearer {secret['token']}"
    else:
        auth = (secret.get("username"), secret.get("password"))
    return {"headers": headers, "auth": auth, "verify": bool(secret.get("verify_tls", False)),
            "timeout": int(secret.get("timeout", 20))}


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

    def _target(self, device: Device) -> Optional[str]:
        return getattr(device, "management_address", None) or device.hostname

    @timed_structured
    def get_facts(self, device: Device, credentials: DeviceCredentials) -> StructuredResult:
        """Cisco IOS-XE: ietf-yang-library (module set + hostname is not
        exposed there, so we fall back to reporting what RESTCONF itself
        can confirm -- reachability/YANG support -- rather than fabricate a
        hostname). FortiGate: /api/v2/monitor/system/status, which
        natively returns hostname/version/serial."""
        vendor_key = (device.vendor or "").lower().replace(" ", "_")
        management_address = self._target(device)
        if not management_address:
            return StructuredResult(success=False, vendor=device.vendor, hostname=device.hostname,
                                     error="Device has no management address/hostname to connect to")
        secret = credentials.secret
        kwargs = _client_kwargs(credentials)

        if vendor_key == "cisco_xe":
            url = f"https://{management_address}{_IETF_YANG_LIBRARY_PATH}"
            try:
                with httpx.Client(**kwargs) as client:
                    resp = client.get(url)
            except httpx.RequestError as e:
                return StructuredResult(success=False, vendor=device.vendor, hostname=device.hostname,
                                         error=redact_secret_values(f"RESTCONF request failed: {e}", secret))
            if resp.status_code == 401:
                return StructuredResult(success=False, vendor=device.vendor, hostname=device.hostname, error="Authentication failed (401)")
            if resp.status_code >= 300:
                return StructuredResult(success=False, vendor=device.vendor, hostname=device.hostname,
                                         error=f"RESTCONF returned HTTP {resp.status_code}: {resp.text[:200]}")
            try:
                body = resp.json()
            except ValueError:
                body = {}
            lib = body.get("ietf-yang-library:yang-library", body)
            return StructuredResult(success=True, vendor=device.vendor, hostname=device.hostname, data={
                "hostname": device.hostname,
                "yang_content_id": lib.get("content-id"),
                "module_set_count": len(lib.get("module-set", [])) if isinstance(lib.get("module-set"), list) else None,
                "source": "restconf:ietf-yang-library",
            })

        if vendor_key in ("fortigate", "fortinet"):
            url = f"https://{management_address}{_FORTIGATE_STATUS_PATH}"
            try:
                with httpx.Client(**kwargs) as client:
                    resp = client.get(url)
            except httpx.RequestError as e:
                return StructuredResult(success=False, vendor=device.vendor, hostname=device.hostname,
                                         error=redact_secret_values(f"REST request failed: {e}", secret))
            if resp.status_code == 401:
                return StructuredResult(success=False, vendor=device.vendor, hostname=device.hostname, error="Authentication failed (401)")
            if resp.status_code >= 300:
                return StructuredResult(success=False, vendor=device.vendor, hostname=device.hostname,
                                         error=f"REST API returned HTTP {resp.status_code}: {resp.text[:200]}")
            try:
                body = resp.json().get("results", {})
            except ValueError:
                body = {}
            return StructuredResult(success=True, vendor=device.vendor, hostname=device.hostname, data={
                "hostname": body.get("hostname") or device.hostname,
                "version": body.get("version"),
                "serial_number": body.get("serial"),
                "model": body.get("model_name") or body.get("model"),
                "source": "restconf:/api/v2/monitor/system/status",
            })

        return StructuredResult(success=False, vendor=device.vendor, hostname=device.hostname,
                                 error=f"RESTCONF get_facts not supported for vendor '{device.vendor}'")

    @timed_structured
    def get_interfaces(self, device: Device, credentials: DeviceCredentials) -> StructuredResult:
        """Same {"interfaces": [...], "interface_count": N} shape as the
        SSH/SNMP/gNMI collectors. Cisco IOS-XE uses the RFC 7223
        ietf-interfaces:interfaces-state container; FortiGate uses its
        cmdb system/interface list (admin-only concept there, so
        oper_status reflects the configured `status` field, not live
        link state -- FortiGate's monitor API would be needed for that
        and is a reasonable follow-up if live link state matters more
        than config-time status)."""
        vendor_key = (device.vendor or "").lower().replace(" ", "_")
        management_address = self._target(device)
        if not management_address:
            return StructuredResult(success=False, vendor=device.vendor, hostname=device.hostname,
                                     error="Device has no management address/hostname to connect to")
        secret = credentials.secret
        kwargs = _client_kwargs(credentials)

        if vendor_key == "cisco_xe":
            url = f"https://{management_address}{_IETF_INTERFACES_STATE_PATH}"
            try:
                with httpx.Client(**kwargs) as client:
                    resp = client.get(url)
            except httpx.RequestError as e:
                return StructuredResult(success=False, vendor=device.vendor, hostname=device.hostname,
                                         error=redact_secret_values(f"RESTCONF request failed: {e}", secret))
            if resp.status_code == 401:
                return StructuredResult(success=False, vendor=device.vendor, hostname=device.hostname, error="Authentication failed (401)")
            if resp.status_code >= 300:
                return StructuredResult(success=False, vendor=device.vendor, hostname=device.hostname,
                                         error=f"RESTCONF returned HTTP {resp.status_code}: {resp.text[:200]}")
            try:
                body = resp.json()
            except ValueError:
                body = {}
            raw_list = body.get("ietf-interfaces:interfaces-state", {}).get("interface", [])
            interfaces = [{
                "name": row.get("name"),
                "admin_status": _ADMIN_STATUS_MAP.get(row.get("admin-status"), row.get("admin-status")),
                "oper_status": _ADMIN_STATUS_MAP.get(row.get("oper-status"), row.get("oper-status")),
                "speed_bps": int(row["speed"]) if str(row.get("speed", "")).isdigit() else None,
                "mac_address": row.get("phys-address"),
            } for row in raw_list]
            return StructuredResult(success=True, vendor=device.vendor, hostname=device.hostname,
                                     data={"interfaces": interfaces, "interface_count": len(interfaces)})

        if vendor_key in ("fortigate", "fortinet"):
            url = f"https://{management_address}{_FORTIGATE_INTERFACE_PATH}"
            try:
                with httpx.Client(**kwargs) as client:
                    resp = client.get(url)
            except httpx.RequestError as e:
                return StructuredResult(success=False, vendor=device.vendor, hostname=device.hostname,
                                         error=redact_secret_values(f"REST request failed: {e}", secret))
            if resp.status_code == 401:
                return StructuredResult(success=False, vendor=device.vendor, hostname=device.hostname, error="Authentication failed (401)")
            if resp.status_code >= 300:
                return StructuredResult(success=False, vendor=device.vendor, hostname=device.hostname,
                                         error=f"REST API returned HTTP {resp.status_code}: {resp.text[:200]}")
            try:
                rows = resp.json().get("results", [])
            except ValueError:
                rows = []
            interfaces = [{
                "name": row.get("name"),
                "admin_status": (row.get("status") or "").lower() or None,
                "oper_status": None,  # not available from cmdb; would need /api/v2/monitor/system/interface
                "speed_bps": None,
                "mac_address": None,
            } for row in rows]
            return StructuredResult(success=True, vendor=device.vendor, hostname=device.hostname,
                                     data={"interfaces": interfaces, "interface_count": len(interfaces)})

        return StructuredResult(success=False, vendor=device.vendor, hostname=device.hostname,
                                 error=f"RESTCONF get_interfaces not supported for vendor '{device.vendor}'")