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
