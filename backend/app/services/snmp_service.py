"""
SNMP Telemetry Service — Phase 7 extension.

Polls connected network devices via SNMP v2c/v3 for live CPU, memory,
and interface throughput metrics. Community strings / auth credentials are
ALWAYS retrieved from OpenBao (never hardcoded or stored in Postgres).

Design:
    - Only called on-demand by GET /api/devices/{id}/telemetry (no persistent
      polling loop that runs uncontrolled in the background).
    - Credentials are held only for the duration of a single SNMP session;
      never returned in API responses, logs, or evidence records (RULE 6).
    - If SNMP is unavailable or the device is unreachable, returns a structured
      SNMP_UNAVAILABLE result rather than raising, to keep the API stable.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("snmp_service")

SNMP_TIMEOUT = int(os.getenv("SNMP_TIMEOUT", "5"))
SNMP_RETRIES = int(os.getenv("SNMP_RETRIES", "1"))

# Standard MIB OIDs for common metrics
OID_SYSNAME    = "1.3.6.1.2.1.1.5.0"
OID_SYSDESCR   = "1.3.6.1.2.1.1.1.0"
OID_CPU_5SEC   = "1.3.6.1.4.1.9.2.1.56.0"   # Cisco: cpmCPUTotal5sec
OID_CPU_1MIN   = "1.3.6.1.4.1.9.2.1.57.0"   # Cisco: cpmCPUTotal1min
OID_MEM_USED   = "1.3.6.1.4.1.9.9.48.1.1.1.5.1"  # Cisco: ciscoMemoryPoolUsed
OID_MEM_FREE   = "1.3.6.1.4.1.9.9.48.1.1.1.6.1"  # Cisco: ciscoMemoryPoolFree
OID_IF_IN_OCTS = "1.3.6.1.2.1.2.2.1.10"     # ifInOctets table
OID_IF_OUT_OCTS= "1.3.6.1.2.1.2.2.1.16"     # ifOutOctets table
OID_IF_DESCR   = "1.3.6.1.2.1.2.2.1.2"      # ifDescr table


@dataclass
class InterfaceMetric:
    index: str
    description: str
    in_octets: Optional[int] = None
    out_octets: Optional[int] = None


@dataclass
class SnmpTelemetry:
    status: str                              # "ok" | "unavailable" | "auth_error" | "timeout"
    device_id: str
    management_address: Optional[str] = None
    sys_name: Optional[str] = None
    sys_descr: Optional[str] = None
    cpu_5sec_pct: Optional[int] = None
    cpu_1min_pct: Optional[int] = None
    mem_used_bytes: Optional[int] = None
    mem_free_bytes: Optional[int] = None
    mem_total_bytes: Optional[int] = None
    mem_utilization_pct: Optional[float] = None
    interfaces: List[InterfaceMetric] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "device_id": self.device_id,
            "management_address": self.management_address,
            "sys_name": self.sys_name,
            "sys_descr": self.sys_descr,
            "cpu_5sec_pct": self.cpu_5sec_pct,
            "cpu_1min_pct": self.cpu_1min_pct,
            "mem_used_bytes": self.mem_used_bytes,
            "mem_free_bytes": self.mem_free_bytes,
            "mem_total_bytes": self.mem_total_bytes,
            "mem_utilization_pct": self.mem_utilization_pct,
            "interfaces": [
                {
                    "index": i.index,
                    "description": i.description,
                    "in_octets": i.in_octets,
                    "out_octets": i.out_octets,
                }
                for i in self.interfaces
            ],
            "error": self.error,
        }


def _try_import_snmp():
    """Lazy import easysnmp / pysnmp so startup does not fail if not installed."""
    try:
        from pysnmp.hlapi import (
            getCmd, nextCmd, SnmpEngine, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity,
        )
        return "pysnmp"
    except ImportError:
        pass
    try:
        import easysnmp  # noqa: F401
        return "easysnmp"
    except ImportError:
        pass
    return None


def collect_telemetry(
    device_id: str,
    management_address: str,
    community: str = "public",
    port: int = 161,
    version: str = "2c",
) -> SnmpTelemetry:
    """Poll a device using SNMP v2c and return structured telemetry.
    `community` must have been retrieved from OpenBao by the caller — this
    function never calls OpenBao itself (see /api/devices/{id}/telemetry)."""

    snmp_lib = _try_import_snmp()
    if not snmp_lib:
        return SnmpTelemetry(
            status="unavailable",
            device_id=device_id,
            management_address=management_address,
            error="No SNMP library available. Install pysnmp: pip install pysnmp",
        )

    try:
        if snmp_lib == "pysnmp":
            return _collect_pysnmp(device_id, management_address, community, port)
        else:
            return _collect_easysnmp(device_id, management_address, community, port)
    except Exception as exc:  # noqa: BLE001
        logger.warning("SNMP collection failed for %s: %s", management_address, exc)
        return SnmpTelemetry(
            status="unavailable",
            device_id=device_id,
            management_address=management_address,
            error=str(exc),
        )


def _collect_pysnmp(device_id: str, host: str, community: str, port: int) -> SnmpTelemetry:
    from pysnmp.hlapi import (
        getCmd, nextCmd, SnmpEngine, CommunityData, UdpTransportTarget,
        ContextData, ObjectType, ObjectIdentity,
    )

    result = SnmpTelemetry(status="ok", device_id=device_id, management_address=host)
    engine = SnmpEngine()
    transport = UdpTransportTarget((host, port), timeout=SNMP_TIMEOUT, retries=SNMP_RETRIES)
    auth = CommunityData(community, mpModel=1)  # mpModel=1 → SNMPv2c
    ctx = ContextData()

    def _get(*oids):
        result_list = []
        for oid in oids:
            error_indication, error_status, error_index, var_binds = next(
                getCmd(engine, auth, transport, ctx, ObjectType(ObjectIdentity(oid)))
            )
            if error_indication or error_status:
                result_list.append(None)
            else:
                result_list.append(str(var_binds[0][1]) if var_binds else None)
        return result_list

    sys_name, sys_descr = _get(OID_SYSNAME, OID_SYSDESCR)
    result.sys_name = sys_name
    result.sys_descr = (sys_descr or "")[:200]

    cpu_5s, cpu_1m = _get(OID_CPU_5SEC, OID_CPU_1MIN)
    try:
        result.cpu_5sec_pct = int(cpu_5s) if cpu_5s else None
        result.cpu_1min_pct = int(cpu_1m) if cpu_1m else None
    except (TypeError, ValueError):
        pass

    mem_used_s, mem_free_s = _get(OID_MEM_USED, OID_MEM_FREE)
    try:
        mem_used = int(mem_used_s) if mem_used_s else None
        mem_free = int(mem_free_s) if mem_free_s else None
        result.mem_used_bytes = mem_used
        result.mem_free_bytes = mem_free
        if mem_used is not None and mem_free is not None:
            total = mem_used + mem_free
            result.mem_total_bytes = total
            result.mem_utilization_pct = round(mem_used / total * 100, 1) if total else None
    except (TypeError, ValueError):
        pass

    # Walk ifDescr / ifInOctets / ifOutOctets
    iface_map: Dict[str, InterfaceMetric] = {}
    try:
        for (err_ind, err_stat, err_idx, var_binds) in nextCmd(
            engine, auth, transport, ctx,
            ObjectType(ObjectIdentity(OID_IF_DESCR)),
            lexicographicMode=False,
        ):
            if err_ind or err_stat:
                break
            for var_bind in var_binds:
                oid_str = str(var_bind[0])
                idx = oid_str.split(".")[-1]
                iface_map.setdefault(idx, InterfaceMetric(index=idx, description=""))
                iface_map[idx].description = str(var_bind[1])[:64]
        for (err_ind, err_stat, err_idx, var_binds) in nextCmd(
            engine, auth, transport, ctx,
            ObjectType(ObjectIdentity(OID_IF_IN_OCTS)),
            lexicographicMode=False,
        ):
            if err_ind or err_stat:
                break
            for var_bind in var_binds:
                oid_str = str(var_bind[0])
                idx = oid_str.split(".")[-1]
                iface_map.setdefault(idx, InterfaceMetric(index=idx, description=""))
                try:
                    iface_map[idx].in_octets = int(var_bind[1])
                except (TypeError, ValueError):
                    pass
        for (err_ind, err_stat, err_idx, var_binds) in nextCmd(
            engine, auth, transport, ctx,
            ObjectType(ObjectIdentity(OID_IF_OUT_OCTS)),
            lexicographicMode=False,
        ):
            if err_ind or err_stat:
                break
            for var_bind in var_binds:
                oid_str = str(var_bind[0])
                idx = oid_str.split(".")[-1]
                iface_map.setdefault(idx, InterfaceMetric(index=idx, description=""))
                try:
                    iface_map[idx].out_octets = int(var_bind[1])
                except (TypeError, ValueError):
                    pass
    except Exception:  # noqa: BLE001
        pass

    result.interfaces = list(iface_map.values())[:24]  # cap at 24 interfaces for API size
    return result


def _collect_easysnmp(device_id: str, host: str, community: str, port: int) -> SnmpTelemetry:
    """Fallback using easysnmp if pysnmp is not available."""
    import easysnmp
    session = easysnmp.Session(hostname=host, community=community, version=2,
                                timeout=SNMP_TIMEOUT, retries=SNMP_RETRIES, remote_port=port)
    result = SnmpTelemetry(status="ok", device_id=device_id, management_address=host)

    def _get_val(oid: str) -> Optional[str]:
        try:
            item = session.get(oid)
            return item.value if item.snmp_type not in ("NOSUCHOBJECT", "NOSUCHINSTANCE", "ENDOFMIBVIEW") else None
        except Exception:  # noqa: BLE001
            return None

    result.sys_name = _get_val(OID_SYSNAME)
    result.sys_descr = (_get_val(OID_SYSDESCR) or "")[:200]
    try:
        result.cpu_5sec_pct = int(_get_val(OID_CPU_5SEC) or 0) or None
        result.cpu_1min_pct = int(_get_val(OID_CPU_1MIN) or 0) or None
    except (TypeError, ValueError):
        pass
    try:
        mu = int(_get_val(OID_MEM_USED) or 0)
        mf = int(_get_val(OID_MEM_FREE) or 0)
        result.mem_used_bytes = mu or None
        result.mem_free_bytes = mf or None
        if mu and mf:
            total = mu + mf
            result.mem_total_bytes = total
            result.mem_utilization_pct = round(mu / total * 100, 1)
    except (TypeError, ValueError):
        pass

    return result
