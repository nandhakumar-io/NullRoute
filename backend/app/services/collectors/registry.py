"""Collector registry (Phase 7).

Picks the best available transport for a given vendor. SSH is preferred
for the vendors that expose their config that way (all five target
vendors), NETCONF is preferred for Juniper when the caller explicitly asks
for it, RESTCONF is offered for Cisco IOS-XE/FortiGate as an alternative.
SNMP is registered but excluded from `get_collector`'s default config-
collection resolution (see snmp.py docstring) -- it must be requested
explicitly via `get_collector(vendor, transport="snmp")` for identity
probing only.
"""
from __future__ import annotations

from typing import Dict, Optional

from app.services.collectors.base import BaseCollector
from app.services.collectors.gnmi import GNMICollector
from app.services.collectors.netconf import NetconfCollector
from app.services.collectors.restconf import RestconfCollector
from app.services.collectors.snmp import SNMPCollector
from app.services.collectors.ssh import SSHCollector

SUPPORTED_VENDORS = {"cisco", "cisco_ios", "cisco_xe", "juniper", "arista", "arista_eos", "fortigate", "fortinet", "paloalto", "palo_alto"}

# vendor_key -> ordered list of transports to try when no explicit transport is requested
_DEFAULT_TRANSPORT_PRIORITY: Dict[str, list] = {
    "cisco": ["ssh", "restconf"],
    "cisco_ios": ["ssh"],
    "cisco_xe": ["ssh", "restconf", "netconf"],
    "juniper": ["netconf", "ssh"],
    "arista": ["ssh"],
    "arista_eos": ["ssh"],
    "fortigate": ["ssh", "restconf"],
    "fortinet": ["ssh", "restconf"],
    "paloalto": ["ssh"],
    "palo_alto": ["ssh"],
}

_COLLECTORS: Dict[str, BaseCollector] = {
    "ssh": SSHCollector(),
    "netconf": NetconfCollector(),
    "restconf": RestconfCollector(),
    "snmp": SNMPCollector(),
    # gNMI is never in a vendor's default priority list above (its Get
    # response is structured OpenConfig JSON, not CLI-equivalent running
    # config -- see collectors/gnmi.py docstring), so it's only reachable
    # via an explicit transport="gnmi" request, same opt-in pattern as SNMP.
    "gnmi": GNMICollector(),
}

# DeviceCredentialRef.credential_type prefixes that are valid for each
# transport (e.g. "ssh_password"/"ssh_key" for ssh, "snmp_community"/
# "snmp_v3" for snmp). Used by credential-resolution code (routers/devices.py,
# gateway/worker.py) so a device with BOTH SSH and SNMP credentials on file
# doesn't accidentally hand the SNMP community string to the SSH collector
# (or vice versa) just because it happens to be the most-recently-created
# credential ref -- that mismatch previously surfaced as a confusing
# "paramiko: No authentication methods available" error when SNMP was
# selected but SSH crendentials didn't exist / weren't picked.
TRANSPORT_CREDENTIAL_PREFIXES: Dict[str, tuple] = {
    "ssh": ("ssh_", "ssh"),
    "netconf": ("netconf", "ssh_"),  # NETCONF devices are commonly onboarded with ssh_password creds too
    "restconf": ("restconf", "restconf_token"),
    "snmp": ("snmp_", "snmp"),
    "gnmi": ("gnmi",),
}


def credential_type_matches_transport(credential_type: Optional[str], transport: Optional[str]) -> bool:
    """True if `credential_type` (e.g. "snmp_community") is an accepted
    credential kind for `transport` (e.g. "snmp")."""
    if not credential_type or not transport:
        return False
    prefixes = TRANSPORT_CREDENTIAL_PREFIXES.get(transport.lower())
    if not prefixes:
        return False
    ct = credential_type.lower()
    return any(ct.startswith(p) for p in prefixes)


def preferred_transport(vendor: Optional[str]) -> str:
    vendor_key = (vendor or "").lower().replace(" ", "_")
    priority = _DEFAULT_TRANSPORT_PRIORITY.get(vendor_key, ["ssh"])
    return priority[0]


def get_collector(vendor: Optional[str], transport: Optional[str] = None) -> BaseCollector:
    """Resolve a collector instance. `transport`, if given, is used
    verbatim (must be one of ssh/netconf/restconf/snmp). Otherwise the
    vendor's preferred transport is used."""
    key = transport or preferred_transport(vendor)
    if key not in _COLLECTORS:
        raise ValueError(f"Unknown transport '{key}'; must be one of {sorted(_COLLECTORS)}")
    return _COLLECTORS[key]