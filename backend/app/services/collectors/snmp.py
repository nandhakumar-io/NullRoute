"""SNMP collector (Phase 7).

Important scope note: unlike SSH/NETCONF/RESTCONF, SNMP does not expose a
device's running configuration as text on any of the target vendors (Cisco,
Juniper, Arista, FortiGate, Palo Alto) -- `collect_config` here is an
identity/health probe only (sysDescr), used for
`GET /api/devices/{id}/collection-status`-style reachability checks.
`get_facts`/`get_interfaces` ARE real SNMP capabilities and are fully
supported.

Uses pysnmp (>=6.0.0, the maintained Python 3.12-compatible fork) when
available. The new API is async-first; we call it from plain synchronous
code using a thin `asyncio.run()` wrapper (_run_async) so the collector
stays a blocking function compatible with the gateway's ThreadPoolExecutor.
This is safe because gateway workers run in a ThreadPoolExecutor -- each
thread has no existing event loop, so asyncio.run() can create and tear
down its own loop per call.

Supports both SNMPv2c (community string) and SNMPv3 (username + optional
auth/priv). The active version is selected implicitly from the credential
payload: if `v3_username` is present, v3 is used; otherwise the `community`
string is used for v2c.
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from app.models.db import Device
from app.services.collectors.base import (BaseCollector, CollectionResult,
                                           StructuredResult, timed,
                                           timed_structured)
from app.services.openbao_service import DeviceCredentials, redact_secret_values

try:
    # pysnmp >=6.0.0 uses snake_case async functions under pysnmp.hlapi.asyncio
    from pysnmp.hlapi.asyncio import (  # type: ignore[import]
        CommunityData, ContextData, ObjectIdentity, ObjectType,
        SnmpEngine, UdpTransportTarget, UsmUserData,
        get_cmd, bulk_cmd,
        usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol,
        usmAesCfb128Protocol, usmDESPrivProtocol,
        usmNoAuthProtocol, usmNoPrivProtocol,
    )
    PYSNMP_AVAILABLE = True
except ImportError:  # pragma: no cover
    PYSNMP_AVAILABLE = False

SYS_DESCR_OID = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID_OID = "1.3.6.1.2.1.1.2.0"
SYS_UPTIME_OID = "1.3.6.1.2.1.1.3.0"
SYS_NAME_OID = "1.3.6.1.2.1.1.5.0"

# IF-MIB columns walked for get_interfaces()
_IF_MIB_COLUMNS: Dict[str, str] = {
    "index":        "1.3.6.1.2.1.2.2.1.1",
    "name":         "1.3.6.1.2.1.2.2.1.2",
    "admin_status": "1.3.6.1.2.1.2.2.1.7",
    "oper_status":  "1.3.6.1.2.1.2.2.1.8",
    "speed_bps":    "1.3.6.1.2.1.2.2.1.5",
    "mac_address":  "1.3.6.1.2.1.2.2.1.6",
}
_IF_STATUS_MAP = {
    1: "up", 2: "down", 3: "testing", 4: "unknown",
    5: "dormant", 6: "notPresent", 7: "lowerLayerDown",
}


def _run_async(coro):
    """Run an async coroutine from synchronous code.

    Safe to call from a ThreadPoolExecutor worker thread because each
    thread has no existing event loop -- asyncio.run() creates and tears
    down a dedicated loop for each SNMP operation.
    """
    return asyncio.run(coro)


def _auth_data(secret: Dict[str, Any]):
    v3_username = secret.get("v3_username")
    if v3_username:
        auth_protocol_name = (secret.get("v3_auth_protocol") or "sha").lower()
        priv_protocol_name = (secret.get("v3_priv_protocol") or "aes").lower()
        auth_protocol = {
            "md5": usmHMACMD5AuthProtocol, "sha": usmHMACSHAAuthProtocol,
            "none": usmNoAuthProtocol,
        }.get(auth_protocol_name, usmHMACSHAAuthProtocol)
        priv_protocol = {
            "aes": usmAesCfb128Protocol, "des": usmDESPrivProtocol,
            "none": usmNoPrivProtocol,
        }.get(priv_protocol_name, usmAesCfb128Protocol)
        kwargs: Dict[str, Any] = {}
        if secret.get("v3_auth_password"):
            kwargs["authKey"] = secret["v3_auth_password"]
            kwargs["authProtocol"] = auth_protocol
        if secret.get("v3_priv_password"):
            kwargs["privKey"] = secret["v3_priv_password"]
            kwargs["privProtocol"] = priv_protocol
        return UsmUserData(v3_username, **kwargs)
    return CommunityData(secret.get("community", "public"), mpModel=1)


def _transport(secret: Dict[str, Any], management_address: str):
    return UdpTransportTarget(
        (management_address, int(secret.get("port", 161))),
        timeout=int(secret.get("timeout", 5)),
    )


def _validate_target(device: Device) -> str:
    management_address = getattr(device, "management_address", None) or device.hostname
    if not management_address:
        raise ValueError("Device has no management address/hostname to connect to")
    return management_address


class SNMPCollector(BaseCollector):
    """SNMP collector. See module docstring for scope notes."""

    transport = "snmp"

    @timed
    def collect_config(self, device: Device, credentials: DeviceCredentials) -> CollectionResult:
        if not PYSNMP_AVAILABLE:
            return CollectionResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error="pysnmp is not installed; SNMP probing unavailable in this environment",
            )
        secret = credentials.secret
        try:
            management_address = _validate_target(device)
        except ValueError as e:
            return CollectionResult(success=False, vendor=device.vendor, hostname=device.hostname, error=str(e))

        async def _get():
            error_indication, error_status, error_index, var_binds = await get_cmd(
                SnmpEngine(),
                _auth_data(secret),
                _transport(secret, management_address),
                ContextData(),
                ObjectType(ObjectIdentity(SYS_DESCR_OID)),
            )
            return error_indication, error_status, error_index, var_binds

        try:
            error_indication, error_status, error_index, var_binds = _run_async(_get())
        except Exception as e:
            return CollectionResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error=redact_secret_values(f"SNMP error: {e}", secret),
            )

        if error_indication:
            return CollectionResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error=redact_secret_values(f"SNMP error: {error_indication}", secret),
            )
        if error_status:
            return CollectionResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error=redact_secret_values(f"SNMP error status: {error_status.prettyPrint()}", secret),
            )

        sys_descr = str(var_binds[0][1]) if var_binds else ""
        return CollectionResult(success=True, vendor=device.vendor, hostname=device.hostname, raw_config=sys_descr)

    @timed_structured
    def get_facts(self, device: Device, credentials: DeviceCredentials) -> StructuredResult:
        """Single multi-OID GET for sysDescr/sysObjectID/sysUpTime/sysName."""
        if not PYSNMP_AVAILABLE:
            return StructuredResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error="pysnmp is not installed; SNMP probing unavailable in this environment",
            )
        secret = credentials.secret
        try:
            management_address = _validate_target(device)
        except ValueError as e:
            return StructuredResult(success=False, vendor=device.vendor, hostname=device.hostname, error=str(e))

        oids = [SYS_DESCR_OID, SYS_OBJECT_ID_OID, SYS_UPTIME_OID, SYS_NAME_OID]

        async def _get():
            return await get_cmd(
                SnmpEngine(),
                _auth_data(secret),
                _transport(secret, management_address),
                ContextData(),
                *(ObjectType(ObjectIdentity(oid)) for oid in oids),
            )

        try:
            error_indication, error_status, error_index, var_binds = _run_async(_get())
        except Exception as e:
            return StructuredResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error=redact_secret_values(f"SNMP error: {e}", secret),
            )

        if error_indication:
            return StructuredResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error=redact_secret_values(f"SNMP error: {error_indication}", secret),
            )
        if error_status:
            return StructuredResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error=redact_secret_values(f"SNMP error status: {error_status.prettyPrint()}", secret),
            )

        values = [str(vb[1]) for vb in var_binds]
        sys_descr, sys_object_id, sys_uptime, sys_name = values
        return StructuredResult(
            success=True,
            vendor=device.vendor,
            hostname=sys_name or device.hostname,
            data={
                "sys_descr": sys_descr,
                "sys_object_id": sys_object_id,
                "sys_uptime_ticks": sys_uptime,
                "sys_name": sys_name,
            },
        )

    @timed_structured
    def get_interfaces(self, device: Device, credentials: DeviceCredentials) -> StructuredResult:
        """IF-MIB walk (ifIndex/ifDescr/ifAdminStatus/ifOperStatus/ifSpeed/ifPhysAddress)."""
        if not PYSNMP_AVAILABLE:
            return StructuredResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error="pysnmp is not installed; SNMP probing unavailable in this environment",
            )
        secret = credentials.secret
        try:
            management_address = _validate_target(device)
        except ValueError as e:
            return StructuredResult(success=False, vendor=device.vendor, hostname=device.hostname, error=str(e))

        by_index: Dict[str, Dict[str, Any]] = {}

        for field_name, base_oid in _IF_MIB_COLUMNS.items():
            async def _walk(base=base_oid):
                results = []
                async for (error_indication, error_status, error_index, var_binds) in bulk_cmd(
                    SnmpEngine(),
                    _auth_data(secret),
                    _transport(secret, management_address),
                    ContextData(),
                    0, 25,
                    ObjectType(ObjectIdentity(base)),
                    lexicographicMode=False,
                ):
                    results.append((error_indication, error_status, error_index, var_binds))
                return results

            try:
                rows = _run_async(_walk())
            except Exception as e:
                return StructuredResult(
                    success=False, vendor=device.vendor, hostname=device.hostname,
                    error=redact_secret_values(f"SNMP error walking {field_name}: {e}", secret),
                )

            for error_indication, error_status, error_index, var_binds in rows:
                if error_indication:
                    return StructuredResult(
                        success=False, vendor=device.vendor, hostname=device.hostname,
                        error=redact_secret_values(f"SNMP error walking {field_name}: {error_indication}", secret),
                    )
                if error_status:
                    return StructuredResult(
                        success=False, vendor=device.vendor, hostname=device.hostname,
                        error=redact_secret_values(f"SNMP error status walking {field_name}: {error_status.prettyPrint()}", secret),
                    )
                for oid, value in var_binds:
                    oid_str = str(oid)
                    if not oid_str.startswith(base_oid + "."):
                        continue
                    if_index = oid_str[len(base_oid) + 1:]
                    row = by_index.setdefault(if_index, {"if_index": if_index})
                    if field_name in ("admin_status", "oper_status"):
                        try:
                            row[field_name] = _IF_STATUS_MAP.get(int(value), str(value))
                        except (ValueError, TypeError):
                            row[field_name] = str(value)
                    elif field_name == "mac_address":
                        row[field_name] = value.prettyPrint() if hasattr(value, "prettyPrint") else str(value)
                    else:
                        row[field_name] = str(value)

        interfaces: List[Dict[str, Any]] = sorted(
            by_index.values(),
            key=lambda r: int(r["if_index"]) if r.get("if_index", "").isdigit() else 0,
        )
        return StructuredResult(
            success=True,
            vendor=device.vendor,
            hostname=device.hostname,
            data={"interfaces": interfaces, "interface_count": len(interfaces)},
        )