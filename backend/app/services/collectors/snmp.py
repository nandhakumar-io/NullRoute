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
        get_cmd, bulk_walk_cmd,
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

# HOST-RESOURCES-MIB (RFC 2790) -- vendor-agnostic CPU/memory, supported by
# every one of this app's five target vendors' SNMP agents (Cisco, Juniper,
# Arista, FortiGate, Palo Alto all implement HOST-RESOURCES-MIB alongside
# their proprietary CPU/memory MIBs). Deliberately NOT using e.g. Cisco's
# CISCO-PROCESS-MIB (cpmCPUTotal5min) here to keep one code path working
# across vendors instead of a per-vendor OID table (RULE 11).
HR_PROCESSOR_LOAD_TABLE = "1.3.6.1.2.1.25.3.3.1.2"     # hrProcessorLoad, walked per-CPU
HR_STORAGE_DESCR_TABLE = "1.3.6.1.2.1.25.2.3.1.3"      # hrStorageDescr
HR_STORAGE_ALLOC_UNITS_TABLE = "1.3.6.1.2.1.25.2.3.1.4"  # hrStorageAllocationUnits
HR_STORAGE_SIZE_TABLE = "1.3.6.1.2.1.25.2.3.1.5"       # hrStorageSize
HR_STORAGE_USED_TABLE = "1.3.6.1.2.1.25.2.3.1.6"       # hrStorageUsed
# hrStorageType values that represent RAM (vs. disk/swap/removable media) --
# we only want "Memory" and "Virtual Memory" for a health-panel summary.
HR_STORAGE_RAM_TYPES = ("1.3.6.1.2.1.25.2.1.2", "1.3.6.1.2.1.25.2.1.3")

# IF-MIB high-capacity (64-bit) counters (RFC 2863) -- ifHC* rather than the
# 32-bit ifIn/OutOctets used nowhere else in this file, since a busy uplink
# wraps a 32-bit octet counter in well under a minute and produces nonsense
# deltas. Error/discard counters are still 32-bit only (no HC variant exists
# in the standard) but wrap far less often at realistic error rates.
_IF_HEALTH_COLUMNS: Dict[str, str] = {
    "name":         "1.3.6.1.2.1.2.2.1.2",       # ifDescr (kept for correlation with get_interfaces' "name")
    "in_octets_hc":  "1.3.6.1.2.1.31.1.1.1.6",   # ifHCInOctets
    "out_octets_hc": "1.3.6.1.2.1.31.1.1.1.10",  # ifHCOutOctets
    "in_errors":    "1.3.6.1.2.1.2.2.1.14",      # ifInErrors
    "out_errors":   "1.3.6.1.2.1.2.2.1.20",      # ifOutErrors
    "in_discards":  "1.3.6.1.2.1.2.2.1.13",      # ifInDiscards
    "out_discards": "1.3.6.1.2.1.2.2.1.19",      # ifOutDiscards
}

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


async def _transport(secret: Dict[str, Any], management_address: str):
    return await UdpTransportTarget.create(
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
            target = await _transport(secret, management_address)
            error_indication, error_status, error_index, var_binds = await get_cmd(
                SnmpEngine(),
                _auth_data(secret),
                target,
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
            target = await _transport(secret, management_address)
            return await get_cmd(
                SnmpEngine(),
                _auth_data(secret),
                target,
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
                target = await _transport(secret, management_address)
                async for (error_indication, error_status, error_index, var_binds) in bulk_walk_cmd(
                    SnmpEngine(),
                    _auth_data(secret),
                    target,
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

    @timed_structured
    def get_routes(self, device: Device, credentials: DeviceCredentials) -> StructuredResult:
        """IP-MIB (RFC1213) ipRouteTable walk for basic IPv4 route inventory."""
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

        def _walk_column(base_oid: str) -> Dict[str, str]:
            async def _walk():
                results = []
                target = await _transport(secret, management_address)
                async for (error_indication, error_status, error_index, var_binds) in bulk_walk_cmd(
                    SnmpEngine(),
                    _auth_data(secret),
                    target,
                    ContextData(),
                    0, 25,
                    ObjectType(ObjectIdentity(base_oid)),
                    lexicographicMode=False,
                ):
                    results.append((error_indication, error_status, error_index, var_binds))
                return results

            rows = _run_async(_walk())
            out: Dict[str, str] = {}
            for error_indication, error_status, error_index, var_binds in rows:
                if error_indication or error_status:
                    return {}
                for oid, value in var_binds:
                    oid_str = str(oid)
                    if not oid_str.startswith(base_oid + "."):
                        continue
                    out[oid_str[len(base_oid) + 1:]] = value.prettyPrint() if hasattr(value, "prettyPrint") else str(value)
            return out

        try:
            # 1.3.6.1.2.1.4.21.1 (ipRouteEntry)
            dest_dict = _walk_column("1.3.6.1.2.1.4.21.1.1")
            ifindex_dict = _walk_column("1.3.6.1.2.1.4.21.1.2")
            metric_dict = _walk_column("1.3.6.1.2.1.4.21.1.3")
            nexthop_dict = _walk_column("1.3.6.1.2.1.4.21.1.7")
            proto_dict = _walk_column("1.3.6.1.2.1.4.21.1.9")
            mask_dict = _walk_column("1.3.6.1.2.1.4.21.1.11")
        except Exception as e:
            return StructuredResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error=redact_secret_values(f"SNMP error walking ipRouteTable: {e}", secret),
            )

        routes: List[Dict[str, Any]] = []
        _PROTO_MAP = {
            1: "other", 2: "local", 3: "netmgmt", 4: "icmp", 8: "rip", 9: "is-is", 13: "ospf", 14: "bgp",
        }
        for idx, dest in dest_dict.items():
            proto_raw = proto_dict.get(idx)
            proto_name = str(proto_raw)
            if proto_raw and proto_raw.isdigit():
                proto_name = _PROTO_MAP.get(int(proto_raw), proto_raw)

            routes.append({
                "destination": dest,
                "mask": mask_dict.get(idx, ""),
                "next_hop": nexthop_dict.get(idx, ""),
                "interface_index": ifindex_dict.get(idx, ""),
                "metric": metric_dict.get(idx, ""),
                "protocol": proto_name,
            })

        return StructuredResult(
            success=True,
            vendor=device.vendor,
            hostname=device.hostname,
            data={"routes": routes, "route_count": len(routes)},
        )

    @timed_structured
    def get_neighbors(self, device: Device, credentials: DeviceCredentials) -> StructuredResult:
        """LLDP-MIB walk (IEEE 802.1AB) -- vendor-agnostic Layer-2 neighbor
        discovery, same rationale as get_health_metrics() using
        HOST-RESOURCES-MIB instead of a per-vendor CDP/proprietary MIB: one
        code path across Cisco/Juniper/Arista/FortiGate/Palo Alto rather
        than a per-vendor OID table (RULE 11). Walks lldpRemTable (remote
        system/port identity, keyed by local port number) and lldpLocPortTable
        (local port number -> local port name) so results can be reported
        against the same interface names get_interfaces()/topology_extractor
        already use. Devices with LLDP disabled/unsupported simply return an
        empty neighbor list, never a guess (RULE 10)."""
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

        def _walk_column(base_oid: str) -> Dict[str, str]:
            async def _walk():
                results = []
                target = await _transport(secret, management_address)
                async for (error_indication, error_status, error_index, var_binds) in bulk_walk_cmd(
                    SnmpEngine(),
                    _auth_data(secret),
                    target,
                    ContextData(),
                    0, 25,
                    ObjectType(ObjectIdentity(base_oid)),
                    lexicographicMode=False,
                ):
                    results.append((error_indication, error_status, error_index, var_binds))
                return results

            rows = _run_async(_walk())
            out: Dict[str, str] = {}
            for error_indication, error_status, error_index, var_binds in rows:
                if error_indication or error_status:
                    # LLDP-MIB unsupported/disabled on this agent -- treat as
                    # "no neighbors observed", not a hard failure, since
                    # sysDescr/IF-MIB already proved the device is reachable.
                    return {}
                for oid, value in var_binds:
                    oid_str = str(oid)
                    if not oid_str.startswith(base_oid + "."):
                        continue
                    out[oid_str[len(base_oid) + 1:]] = value.prettyPrint() if hasattr(value, "prettyPrint") else str(value)
            return out

        try:
            # lldpLocPortTable: local port index -> local interface name, so
            # neighbors can be reported against the same port names as
            # get_interfaces()/show-cmd interface extraction.
            loc_port_names = _walk_column("1.0.8802.1.1.2.1.3.7.1.3")   # lldpLocPortId

            # lldpRemTable is indexed by (timeMark, localPortNum, remIndex);
            # the local port number is the *second* sub-identifier.
            rem_sys_name = _walk_column("1.0.8802.1.1.2.1.4.1.1.9")    # lldpRemSysName
            rem_port_id = _walk_column("1.0.8802.1.1.2.1.4.1.1.7")     # lldpRemPortId
            rem_port_desc = _walk_column("1.0.8802.1.1.2.1.4.1.1.8")   # lldpRemPortDesc
            rem_chassis_id = _walk_column("1.0.8802.1.1.2.1.4.1.1.5")  # lldpRemChassisId
        except Exception as e:
            return StructuredResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error=redact_secret_values(f"SNMP error walking LLDP-MIB: {e}", secret),
            )

        neighbors: List[Dict[str, Any]] = []
        for suffix, sys_name in rem_sys_name.items():
            parts = suffix.split(".")
            local_port_num = parts[1] if len(parts) >= 2 else suffix
            local_port_name = loc_port_names.get(local_port_num, f"port-{local_port_num}")
            neighbors.append({
                "local_port": local_port_name,
                "remote_system_name": sys_name or None,
                "remote_port_id": rem_port_id.get(suffix) or None,
                "remote_port_description": rem_port_desc.get(suffix) or None,
                "remote_chassis_id": rem_chassis_id.get(suffix) or None,
                "protocol": "lldp",
            })

        return StructuredResult(
            success=True,
            vendor=device.vendor,
            hostname=device.hostname,
            data={"neighbors": neighbors, "neighbor_count": len(neighbors)},
        )

    @timed_structured
    def get_health_metrics(self, device: Device, credentials: DeviceCredentials) -> StructuredResult:
        """Live health/performance snapshot: per-CPU load (HOST-RESOURCES-MIB
        hrProcessorLoad), RAM utilization (hrStorage, RAM-typed rows only),
        and per-interface traffic/error/discard counters (IF-MIB high-
        capacity counters). This is deliberately separate from get_facts()
        (static identity) and get_interfaces() (admin/oper status) -- it's
        the "is this device under load / dropping traffic right now" view
        for the Device Detail health panel."""
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

        def _walk_column(base_oid: str):
            async def _walk():
                rows = []
                target = await _transport(secret, management_address)
                async for (error_indication, error_status, error_index, var_binds) in bulk_walk_cmd(
                    SnmpEngine(),
                    _auth_data(secret),
                    target,
                    ContextData(),
                    0, 25,
                    ObjectType(ObjectIdentity(base_oid)),
                    lexicographicMode=False,
                ):
                    rows.append((error_indication, error_status, error_index, var_binds))
                return rows
            return _run_async(_walk())

        def _column_values(base_oid: str, label: str) -> Dict[str, str]:
            """Returns {table_index: value} for one MIB column, or raises a
            plain Exception on any SNMP-level error (caller wraps it)."""
            values: Dict[str, str] = {}
            for error_indication, error_status, error_index, var_binds in _walk_column(base_oid):
                if error_indication:
                    raise RuntimeError(f"walking {label}: {error_indication}")
                if error_status:
                    raise RuntimeError(f"walking {label}: {error_status.prettyPrint()}")
                for oid, value in var_binds:
                    oid_str = str(oid)
                    if not oid_str.startswith(base_oid + "."):
                        continue
                    idx = oid_str[len(base_oid) + 1:]
                    values[idx] = value.prettyPrint() if hasattr(value, "prettyPrint") else str(value)
            return values

        try:
            # --- CPU: hrProcessorLoad is a % (0-100) per logical processor ---
            cpu_by_index = _column_values(HR_PROCESSOR_LOAD_TABLE, "hrProcessorLoad")
            cpu_loads = []
            for v in cpu_by_index.values():
                try:
                    cpu_loads.append(int(v))
                except (TypeError, ValueError):
                    continue
            cpu_average_pct = round(sum(cpu_loads) / len(cpu_loads), 1) if cpu_loads else None

            # --- Memory: hrStorage, filtered to RAM-typed rows only ---
            storage_type = _column_values("1.3.6.1.2.1.25.2.3.1.2", "hrStorageType")  # hrStorageType
            storage_descr = _column_values(HR_STORAGE_DESCR_TABLE, "hrStorageDescr")
            storage_units = _column_values(HR_STORAGE_ALLOC_UNITS_TABLE, "hrStorageAllocationUnits")
            storage_size = _column_values(HR_STORAGE_SIZE_TABLE, "hrStorageSize")
            storage_used = _column_values(HR_STORAGE_USED_TABLE, "hrStorageUsed")

            memory_total_bytes = 0
            memory_used_bytes = 0
            memory_rows = []
            for idx, type_oid in storage_type.items():
                if not any(type_oid == t or type_oid.endswith(t.split(".")[-1]) for t in HR_STORAGE_RAM_TYPES):
                    continue
                try:
                    units = int(storage_units.get(idx, "1"))
                    size = int(storage_size.get(idx, "0")) * units
                    used = int(storage_used.get(idx, "0")) * units
                except (TypeError, ValueError):
                    continue
                memory_total_bytes += size
                memory_used_bytes += used
                memory_rows.append({
                    "description": storage_descr.get(idx, f"storage[{idx}]"),
                    "total_bytes": size,
                    "used_bytes": used,
                })
            memory_used_pct = (
                round(100.0 * memory_used_bytes / memory_total_bytes, 1) if memory_total_bytes else None
            )

            # --- Interface traffic/errors: IF-MIB high-capacity counters ---
            if_columns: Dict[str, Dict[str, str]] = {name: _column_values(oid, name) for name, oid in _IF_HEALTH_COLUMNS.items()}
            by_if_index: Dict[str, Dict[str, Any]] = {}
            for name, values in if_columns.items():
                for idx, v in values.items():
                    row = by_if_index.setdefault(idx, {"if_index": idx})
                    row[name] = v
            interface_health = sorted(
                by_if_index.values(),
                key=lambda r: int(r["if_index"]) if r.get("if_index", "").isdigit() else 0,
            )
        except Exception as e:  # noqa: BLE001 -- any SNMP-level failure degrades to a failed result, never a raise
            return StructuredResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error=redact_secret_values(f"SNMP error collecting health metrics: {e}", secret),
            )

        return StructuredResult(
            success=True,
            vendor=device.vendor,
            hostname=device.hostname,
            data={
                "cpu_average_pct": cpu_average_pct,
                "cpu_per_processor_pct": {k: (int(v) if v.isdigit() else v) for k, v in cpu_by_index.items()},
                "memory_used_pct": memory_used_pct,
                "memory_total_bytes": memory_total_bytes or None,
                "memory_used_bytes": memory_used_bytes or None,
                "memory_pools": memory_rows,
                "interface_health": interface_health,
            },
        )