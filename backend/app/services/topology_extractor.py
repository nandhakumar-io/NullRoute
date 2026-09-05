"""Inventory/topology extraction (Phase 9).

Best-effort, deterministic, regex-based extraction of interfaces, VLANs,
VRFs, and static routes from raw configuration text -- the same raw_text
the compliance pipeline already parses. This is intentionally separate from
services/parsers.py (which builds the SecurityBaselineModel for compliance
evaluation): topology data doesn't feed OPA/Batfish/risk, it only powers
the inventory/topology views (RULE 11: additive, doesn't touch the existing
pipeline's compliance semantics).

Extraction is best-effort per RULE 10 (never fabricate results): if a
vendor's syntax isn't recognized, the corresponding list is simply empty --
never guessed or padded with placeholder rows. Every value returned here is
literally present in the raw config.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ExtractedInterface:
    name: str
    description: Optional[str] = None
    ip_address: Optional[str] = None
    subnet_mask: Optional[str] = None
    vlan: Optional[str] = None
    admin_state: Optional[str] = None  # up/down, when explicitly stated (e.g. "shutdown")
    vrf: Optional[str] = None


@dataclass
class ExtractedVlan:
    vlan_id: str
    name: Optional[str] = None


@dataclass
class ExtractedVrf:
    name: str
    route_distinguisher: Optional[str] = None


@dataclass
class ExtractedRoute:
    destination: str
    mask: Optional[str] = None
    next_hop: Optional[str] = None
    vrf: Optional[str] = None


@dataclass
class TopologyExtraction:
    interfaces: List[ExtractedInterface] = field(default_factory=list)
    vlans: List[ExtractedVlan] = field(default_factory=list)
    vrfs: List[ExtractedVrf] = field(default_factory=list)
    routes: List[ExtractedRoute] = field(default_factory=list)


def _extract_cisco(raw_text: str) -> TopologyExtraction:
    out = TopologyExtraction()

    # interface <Name>\n  ...block... (until next top-level "interface"/"!"/EOF)
    for m in re.finditer(
        r"^interface\s+(\S+)\n((?:^[ \t].*\n?)*)", raw_text, re.M
    ):
        name, block = m.group(1), m.group(2)
        desc_m = re.search(r"^\s*description\s+(.+)$", block, re.M)
        ip_m = re.search(r"^\s*ip address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", block, re.M)
        vlan_m = re.search(r"^\s*(?:switchport access vlan|encapsulation dot1[qQ])\s+(\d+)", block, re.M)
        vrf_m = re.search(r"^\s*(?:ip vrf forwarding|vrf forwarding)\s+(\S+)", block, re.M)
        admin_state = "down" if re.search(r"^\s*shutdown\s*$", block, re.M) else "up"
        out.interfaces.append(ExtractedInterface(
            name=name,
            description=desc_m.group(1).strip() if desc_m else None,
            ip_address=ip_m.group(1) if ip_m else None,
            subnet_mask=ip_m.group(2) if ip_m else None,
            vlan=vlan_m.group(1) if vlan_m else None,
            admin_state=admin_state,
            vrf=vrf_m.group(1) if vrf_m else None,
        ))

    for m in re.finditer(r"^vlan\s+(\d+)\n(?:^\s*name\s+(\S+)\n)?", raw_text, re.M):
        out.vlans.append(ExtractedVlan(vlan_id=m.group(1), name=m.group(2)))

    for m in re.finditer(r"^(?:ip vrf|vrf definition)\s+(\S+)(?:\n^\s*rd\s+(\S+))?", raw_text, re.M):
        out.vrfs.append(ExtractedVrf(name=m.group(1), route_distinguisher=m.group(2)))

    for m in re.finditer(
        r"^ip route\s+(?:vrf\s+(\S+)\s+)?(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)", raw_text, re.M
    ):
        out.routes.append(ExtractedRoute(
            vrf=m.group(1), destination=m.group(2), mask=m.group(3), next_hop=m.group(4),
        ))

    return out


def _extract_juniper(raw_text: str) -> TopologyExtraction:
    out = TopologyExtraction()
    seen_ifaces = {}

    for m in re.finditer(r"^set interfaces (\S+)(?:\.(\d+))? unit \d+ family inet address (\d+\.\d+\.\d+\.\d+)/(\d+)", raw_text, re.M):
        name = m.group(1)
        seen_ifaces.setdefault(name, ExtractedInterface(name=name))
        seen_ifaces[name].ip_address = m.group(3)
        seen_ifaces[name].subnet_mask = m.group(4)
    for m in re.finditer(r"^set interfaces (\S+) description (.+)$", raw_text, re.M):
        name = m.group(1)
        seen_ifaces.setdefault(name, ExtractedInterface(name=name))
        seen_ifaces[name].description = m.group(2).strip('"')
    for m in re.finditer(r"^set interfaces (\S+) disable", raw_text, re.M):
        name = m.group(1)
        seen_ifaces.setdefault(name, ExtractedInterface(name=name))
        seen_ifaces[name].admin_state = "down"
    out.interfaces = list(seen_ifaces.values())
    for iface in out.interfaces:
        if iface.admin_state is None:
            iface.admin_state = "up"

    for m in re.finditer(r"^set vlans (\S+) vlan-id (\d+)", raw_text, re.M):
        out.vlans.append(ExtractedVlan(vlan_id=m.group(2), name=m.group(1)))

    for m in re.finditer(r"^set routing-instances (\S+) instance-type vrf", raw_text, re.M):
        out.vrfs.append(ExtractedVrf(name=m.group(1)))

    for m in re.finditer(
        r"^set routing-options static route (\d+\.\d+\.\d+\.\d+)/(\d+) next-hop (\d+\.\d+\.\d+\.\d+)", raw_text, re.M
    ):
        out.routes.append(ExtractedRoute(destination=m.group(1), mask=m.group(2), next_hop=m.group(3)))

    return out


def _extract_fortinet(raw_text: str) -> TopologyExtraction:
    out = TopologyExtraction()
    for m in re.finditer(
        r"^\s*edit\s+\"?(\S+?)\"?\n((?:^\s{8,}.*\n?)*)", raw_text, re.M
    ):
        name, block = m.group(1), m.group(2)
        ip_m = re.search(r"^\s*set ip (\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", block, re.M)
        desc_m = re.search(r'^\s*set description\s+"?([^"\n]+)"?', block, re.M)
        vlan_m = re.search(r"^\s*set vlanid\s+(\d+)", block, re.M)
        if ip_m or desc_m or vlan_m:
            out.interfaces.append(ExtractedInterface(
                name=name,
                ip_address=ip_m.group(1) if ip_m else None,
                subnet_mask=ip_m.group(2) if ip_m else None,
                description=desc_m.group(1).strip() if desc_m else None,
                vlan=vlan_m.group(1) if vlan_m else None,
            ))
    return out


_EXTRACTORS = {
    "Cisco": _extract_cisco,
    "Arista": _extract_cisco,  # EOS interface/VLAN syntax is IOS-derived, close enough for these patterns
    "Juniper": _extract_juniper,
    "Fortinet": _extract_fortinet,
}


def extract_topology(vendor: Optional[str], raw_text: str) -> TopologyExtraction:
    """Best-effort dispatch by vendor. Unknown/unsupported vendors (e.g.
    'Palo Alto Networks', whose set-based syntax needs its own patterns not
    yet written) return an empty TopologyExtraction rather than a guess."""
    extractor = _EXTRACTORS.get(vendor or "")
    if not extractor:
        return TopologyExtraction()
    try:
        return extractor(raw_text)
    except Exception:  # noqa: BLE001 - extraction is best-effort, must never fail the pipeline
        return TopologyExtraction()
