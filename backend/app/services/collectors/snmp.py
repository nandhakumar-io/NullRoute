"""SNMP collector (Phase 7).

Important scope note: unlike SSH/NETCONF/RESTCONF, SNMP does not expose a
device's running configuration as text on any of the target vendors (Cisco,
Juniper, Arista, FortiGate, Palo Alto) -- it's included in the registry for
inventory/health signals (sysDescr, sysUpTime, sysName) via
`GET /api/devices/{id}/collection-status`-style checks, and as a future
extension point. It must never be used to satisfy a compliance scan, and
callers should prefer ssh/netconf/restconf for `collect_config`.

Uses pysnmp when available; offline-safe fallback otherwise (same pattern
as the other collectors).
"""
from __future__ import annotations

from app.models.db import Device
from app.services.collectors.base import BaseCollector, CollectionResult, timed
from app.services.openbao_service import DeviceCredentials, redact_secret_values

try:
    from pysnmp.hlapi import (CommunityData, ContextData, ObjectIdentity,
                               ObjectType, SnmpEngine, UdpTransportTarget,
                               getCmd)
    PYSNMP_AVAILABLE = True
except ImportError:  # pragma: no cover
    PYSNMP_AVAILABLE = False

SYS_DESCR_OID = "1.3.6.1.2.1.1.1.0"


class SNMPCollector(BaseCollector):
    """Identity/health probe only -- see module docstring. `raw_config` on
    a successful result contains sysDescr text, NOT a running
    configuration, and must not be fed into the compliance pipeline."""

    transport = "snmp"

    @timed
    def collect_config(self, device: Device, credentials: DeviceCredentials) -> CollectionResult:
        if not PYSNMP_AVAILABLE:
            return CollectionResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error="pysnmp is not installed; SNMP probing unavailable in this environment",
            )

        management_address = getattr(device, "management_address", None) or device.hostname
        if not management_address:
            return CollectionResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error="Device has no management address/hostname to connect to",
            )

        secret = credentials.secret
        community = secret.get("community", "public")

        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),
            UdpTransportTarget((management_address, int(secret.get("port", 161))), timeout=int(secret.get("timeout", 5))),
            ContextData(),
            ObjectType(ObjectIdentity(SYS_DESCR_OID)),
        )
        error_indication, error_status, error_index, var_binds = next(iterator)

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
        return CollectionResult(
            success=True,
            vendor=device.vendor,
            hostname=device.hostname,
            raw_config=sys_descr,
        )
