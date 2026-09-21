"""Deterministic *structural* parsing of network device configuration.

services/parsers.py extracts security parameters (SSH version, syslog, AAA,
...). It has never understood the *structure* of a config -- interface
blocks, VLAN definitions, VRFs, static routes, ACL bodies -- so every one of
those lines fell through to the "unknown" bucket and was sent to the LLM, and
the Topology page had to fall back on a second, narrower regex extractor.

This module is the single deterministic implementation of that structure for
every vendor family the platform ingests:

    ios       Cisco IOS / IOS-XE / NX-OS, Arista EOS, Aruba AOS-CX
    vrp       Huawei VRP
    junos     Juniper Junos (``set`` format, and ``{ }`` hierarchy converted)
    fortios   Fortinet FortiOS
    panos     Palo Alto PAN-OS (``set`` format)
    routeros  MikroTik RouterOS export
    sonic     SONiC config_db.json
    gaia      Check Point Gaia clish

Contract (RULE 10 -- never fabricate):
  * every value returned is literally present in the config text;
  * ``consumed`` holds the 0-based indices (into ``raw_text.splitlines()``) of
    lines whose meaning is fully captured by a returned fact;
  * ``recognized`` holds indices of lines that are known, deliberately
    unmodelled commands (e.g. ``speed 1000``) -- deterministic, so they are
    never sent to the LLM, but they carry no fact either;
  * ``noise`` holds comments / block delimiters;
  * every other line is the caller's "unknown" set and must go to the
    AI/RAG normalizer -- this module never guesses at them.

Parsing never raises: malformed input degrades to fewer facts.
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Result types (re-exported by services/topology_extractor.py)
# ---------------------------------------------------------------------------


@dataclass
class ExtractedInterface:
    name: str
    description: Optional[str] = None
    ip_address: Optional[str] = None
    subnet_mask: Optional[str] = None
    vlan: Optional[str] = None
    admin_state: Optional[str] = None  # up/down, when explicitly stated (e.g. "shutdown")
    vrf: Optional[str] = None
    switchport_mode: Optional[str] = None  # ACCESS / TRUNK / ROUTED
    allowed_vlans: Optional[str] = None
    acl_in: Optional[str] = None
    acl_out: Optional[str] = None
    line: Optional[int] = None  # 1-based line of the declaration


@dataclass
class ExtractedVlan:
    vlan_id: str
    name: Optional[str] = None
    interfaces: List[str] = field(default_factory=list)
    declared: bool = True  # False: only referenced by an interface, never defined
    line: Optional[int] = None


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
    protocol: str = "static"
    line: Optional[int] = None


@dataclass
class ExtractedAcl:
    name: str
    kind: Optional[str] = None  # standard / extended / ...
    entries: List[Dict[str, str]] = field(default_factory=list)
    line: Optional[int] = None


@dataclass
class ExtractedProtocol:
    protocol: str  # ospf / bgp / eigrp
    process: Optional[str] = None
    router_id: Optional[str] = None
    networks: List[str] = field(default_factory=list)
    neighbors: List[str] = field(default_factory=list)
    line: Optional[int] = None


@dataclass
class StructureResult:
    family: Optional[str] = None
    hostname: Optional[str] = None
    interfaces: List[ExtractedInterface] = field(default_factory=list)
    vlans: List[ExtractedVlan] = field(default_factory=list)
    vrfs: List[ExtractedVrf] = field(default_factory=list)
    routes: List[ExtractedRoute] = field(default_factory=list)
    acls: List[ExtractedAcl] = field(default_factory=list)
    protocols: List[ExtractedProtocol] = field(default_factory=list)
    consumed: Set[int] = field(default_factory=set)
    recognized: Set[int] = field(default_factory=set)
    noise: Set[int] = field(default_factory=set)

    @property
    def explained(self) -> Set[int]:
        return self.consumed | self.recognized | self.noise


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

_IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"


def _prefix_to_mask(prefix: int) -> Optional[str]:
    if 0 <= prefix <= 32:
        return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
    return None


def _split_addr(token: str, mask: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
    """``10.0.0.1/24`` | (``10.0.0.1``, ``255.255.255.0``) | (``10.0.0.1``, ``24``)
    -> (ip, dotted mask). IPv6 is returned as (address, None)."""
    try:
        if "/" in token:
            iface = ipaddress.ip_interface(token)
            return str(iface.ip), (str(iface.netmask) if iface.version == 4 else None)
        if mask:
            if mask.isdigit():
                return token, _prefix_to_mask(int(mask))
            ipaddress.IPv4Address(mask)
            return token, mask
        ipaddress.ip_address(token)
        return token, None
    except ValueError:
        return None, None


def _wildcard_ok(text: str) -> bool:
    try:
        ipaddress.IPv4Address(text)
        return True
    except ValueError:
        return False


def expand_vlans(text: str) -> List[int]:
    """``10,20,30-32`` / ``10 20 to 25`` / ``add 40`` -> sorted unique ids.
    ``all`` / ``none`` / ``except`` are not expandable and yield []."""
    out: Set[int] = set()
    cleaned = re.sub(r"\b(add|remove|except|none|all)\b", " ", text or "", flags=re.I)
    cleaned = re.sub(r"\s+to\s+", "-", cleaned, flags=re.I).replace(",", " ")
    for tok in cleaned.split():
        m = re.fullmatch(r"(\d+)(?:-(\d+))?", tok)
        if not m:
            continue
        lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
        if 1 <= lo <= hi <= 4094 and hi - lo <= 4094:
            out.update(range(lo, hi + 1))
    return sorted(out)


def _compress(ids: Iterable[int]) -> str:
    ids = sorted(set(ids))
    parts, i = [], 0
    while i < len(ids):
        j = i
        while j + 1 < len(ids) and ids[j + 1] == ids[j] + 1:
            j += 1
        parts.append(str(ids[i]) if i == j else f"{ids[i]}-{ids[j]}")
        i = j + 1
    return ",".join(parts)


def _is_comment(stripped: str, prefixes: Tuple[str, ...]) -> bool:
    return any(stripped.startswith(p) for p in prefixes)


@dataclass
class _Block:
    start: int  # index of header line
    header: str
    children: List[Tuple[int, str]]  # (index, stripped text)


def _iter_indented_blocks(lines: List[str], comment_prefixes: Tuple[str, ...]) -> Iterable[_Block]:
    """Top-level line + the indented lines that follow it. A column-0 line
    (including a comment) ends the block."""
    i, n = 0, len(lines)
    while i < n:
        raw = lines[i]
        if not raw.strip() or raw[0] in " \t" or _is_comment(raw.strip(), comment_prefixes):
            i += 1
            continue
        block = _Block(i, raw.strip(), [])
        j = i + 1
        while j < n and (not lines[j].strip() or lines[j][0] in " \t"):
            if lines[j].strip():
                block.children.append((j, lines[j].strip()))
            j += 1
        yield block
        i = j


# ---------------------------------------------------------------------------
# Family: ios  (Cisco IOS/IOS-XE/NX-OS, Arista EOS, Aruba AOS-CX)
# ---------------------------------------------------------------------------

_IOS_IFACE_BENIGN = re.compile(
    r"^(?:no\s+)?(?:speed|duplex|mtu|negotiation|negotiate|flowcontrol|load-interval|carrier-delay|bandwidth|"
    r"keepalive|logging event|storm-control|lldp|cdp|mls|service-policy|standby|vrrp|glbp|power inline|"
    r"spanning-tree|channel-group|channel-protocol|ip ospf|ipv6 ospf|ip pim|ip igmp|ip flow|ip helper-address|"
    r"ip proxy-arp|ip redirects|ip unreachables|ip mtu|ip tcp|ip verify|ip arp|arp timeout|ip directed-broadcast|"
    r"ip route-cache|ip mroute-cache|ipv6|ip nat|ip policy|switchport nonegotiate|switchport voice|"
    r"switchport protected|switchport block|switchport port-security|switchport backup|switchport host|"
    r"switchport trunk pruning|mac address-table|mac-address|dot1x|mab|ip dhcp|qos|trust|"
    r"priority-flow-control|ip source-guard|isis)\b",
    re.I,
)

_IOS_TOP_BENIGN = re.compile(
    r"^(?:version\b|building configuration|current configuration|boot-(?:start|end)-marker|boot system|"
    r"service (?:timestamps|call-home|tcp-keepalives|sequence-numbers|dhcp|counters|unsupported)|"
    r"spanning-tree\b|ip cef|no ip cef|ip routing|no ip routing|ipv6 unicast-routing|"
    r"ip domain[- ]lookup|no ip domain[- ]lookup|ip name-server|clock timezone|clock summer-time|"
    r"lldp run|no lldp run|license\b|memory\b|platform\b|terminal\b|hardware\b|transceiver\b|"
    r"errdisable|vtp\b|udld\b|mls\b|cluster\b|redundancy\b|"
    r"logging (?:buffered|console|monitor|facility|source-interface|synchronous|rate-limit|count|origin-id|on)\b|"
    r"archive\b|ip dhcp\b|no ip dhcp|ip tftp|no ip finger|no ip bootp|no ip gratuitous|ip subnet-zero|"
    r"no ip subnet-zero|ip classless|ip forward-protocol|no ip forward-protocol|call-home\b|diagnostic\b|"
    r"switch \d|ip multicast-routing|mac address-table|exit-address-family\b|address-family\b|"
    r"class-map\b|policy-map\b|route-map\b|ip prefix-list\b|ip as-path\b|ip community-list\b|prefix-list\b|"
    r"event-handler\b|daemon\b|trace\b|queue-monitor\b|tap aggregation\b|feature\b|copp\b|system\b|"
    r"no feature\b)",
    re.I,
)


def _ios_dialect(vendor: Optional[str], raw: str) -> str:
    v = (vendor or "").lower()
    if "aruba" in v or "aos" in v:
        return "aoscx"
    if "arista" in v or "eos" in v:
        return "eos"
    if re.search(r"^interface\s+\d+/\d+/\d+\s*$", raw, re.M):
        return "aoscx"
    return "ios"


def _parse_ios(raw: str, vendor: Optional[str]) -> StructureResult:
    dialect = _ios_dialect(vendor, raw)
    res = StructureResult(family="ios")
    lines = raw.splitlines()
    ifaces: Dict[str, ExtractedInterface] = {}
    vlans: Dict[str, ExtractedVlan] = {}
    vrfs: Dict[str, ExtractedVrf] = {}
    pending_acl_bind: List[Tuple[str, str, str]] = []

    def eat(idx: int) -> None:
        res.consumed.add(idx)

    def see(idx: int) -> None:
        res.recognized.add(idx)

    for i, ln in enumerate(lines):
        s = ln.strip()
        if s and _is_comment(s, ("!",)):
            res.noise.add(i)

    for blk in _iter_indented_blocks(lines, ("!",)):
        h, low, idx = blk.header, blk.header.lower(), blk.start
        if idx in res.consumed:  # body line of a multi-line banner
            continue

        if m := re.match(r"hostname\s+(\S+)", h, re.I):
            res.hostname = m.group(1)
            eat(idx)
        elif m := re.match(r"interface\s+(.+)$", h, re.I):
            name = re.sub(r"^(vlan|lag|loopback)\s+(\d+)$", r"\1\2", m.group(1).strip(), flags=re.I)
            iface = ifaces.setdefault(name, ExtractedInterface(name=name, line=idx + 1))
            eat(idx)
            if re.fullmatch(r"(?:vlan|vlanif)\s*(\d+)", name, re.I):
                iface.vlan = re.sub(r"\D", "", name)
            _ios_interface(blk, iface, dialect, res, vrfs)
        elif m := re.match(r"vlan\s+([\d,\- ]+)$", h, re.I):
            ids = expand_vlans(m.group(1))
            eat(idx)
            names: Optional[str] = None
            for cidx, c in blk.children:
                if mm := re.match(r"name\s+(.+)$", c, re.I):
                    names = mm.group(1).strip().strip('"')
                    eat(cidx)
                elif re.match(r"(?:state\s+\w+|no\s+shutdown|shutdown|description\s+.+|spanning-tree.*|"
                              r"remote-span|private-vlan.*|media\s+\w+|mtu\s+\d+|voice)$", c, re.I):
                    see(cidx)
            for vid in ids:
                v = vlans.setdefault(str(vid), ExtractedVlan(vlan_id=str(vid), line=idx + 1))
                v.declared = True
                if names and len(ids) == 1:
                    v.name = names
        elif m := re.match(r"(?:ip vrf|vrf definition|vrf context)\s+(\S+)$", h, re.I) or (
                dialect == "aoscx" and (m := re.match(r"vrf\s+(\S+)$", h, re.I))):
            vrf = vrfs.setdefault(m.group(1), ExtractedVrf(name=m.group(1)))
            eat(idx)
            for cidx, c in blk.children:
                if mm := re.match(r"rd\s+(\S+)$", c, re.I):
                    vrf.route_distinguisher = mm.group(1)
                    eat(cidx)
                elif re.match(r"(?:route-target|address-family|exit-address-family|description|"
                              r"import|export|maplist|rd|no\s+shutdown)\b", c, re.I):
                    see(cidx)
        elif m := re.match(r"ip route\s+(.+)$", h, re.I):
            route = _ios_route(m.group(1), idx)
            if route:
                res.routes.append(route)
                eat(idx)
        elif m := re.match(r"ip access-list\s+(?:(standard|extended|resequence)\s+)?(\S+)$", h, re.I):
            acl = ExtractedAcl(name=m.group(2), kind=(m.group(1) or "extended").lower(), line=idx + 1)
            eat(idx)
            for cidx, c in blk.children:
                entry = _acl_entry(c)
                if entry:
                    acl.entries.append(entry)
                    eat(cidx)
                elif re.match(r"(?:remark|\d+\s+remark)\b", c, re.I):
                    see(cidx)
            res.acls.append(acl)
        elif m := re.match(r"access-list\s+(\S+)\s+((?:permit|deny|remark).*)$", h, re.I):
            name = m.group(1)
            acl = next((a for a in res.acls if a.name == name), None)
            if acl is None:
                acl = ExtractedAcl(name=name, kind="numbered", line=idx + 1)
                res.acls.append(acl)
            entry = _acl_entry(m.group(2))
            if entry:
                acl.entries.append(entry)
                eat(idx)
            else:
                see(idx)
        elif m := re.match(r"router\s+(ospf|bgp|eigrp|rip|isis)\s*(\S*)$", h, re.I):
            _ios_router(blk, m.group(1).lower(), m.group(2), res)
        elif m := re.match(r"banner\s+(\w+)\s+(\^C|\S)(.*)$", h, re.I):
            delim, rest = m.group(2), m.group(3)
            eat(idx)
            if delim not in rest:
                j = idx + 1
                while j < len(lines):
                    eat(j)
                    if delim in lines[j]:
                        break
                    j += 1
        elif _IOS_TOP_BENIGN.match(h):
            see(idx)
            for cidx, _c in blk.children:
                see(cidx)
    # Multi-line banners are not indented, so the block iterator visits their
    # body lines as new top-level headers; they were consumed above by index.
    # Nothing further to do.

    # Fold VLAN membership from interfaces (declared VLANs + VLANs a port uses).
    for iface in ifaces.values():
        members: List[int] = []
        if iface.vlan and (iface.switchport_mode in ("ACCESS", None) or re.match(r"(?i)vlan\d+", iface.name)):
            members.append(int(iface.vlan))
        if iface.switchport_mode == "TRUNK" and iface.allowed_vlans and iface.allowed_vlans.lower() != "all":
            members.extend(expand_vlans(iface.allowed_vlans))
        for vid in members:
            v = vlans.setdefault(str(vid), ExtractedVlan(vlan_id=str(vid), declared=False, line=None))
            if iface.name not in v.interfaces:
                v.interfaces.append(iface.name)

    res.interfaces = list(ifaces.values())
    res.vlans = sorted(vlans.values(), key=lambda v: int(v.vlan_id))
    res.vrfs = list(vrfs.values())
    return res


def _ios_interface(blk: _Block, iface: ExtractedInterface, dialect: str, res: StructureResult,
                   vrfs: Dict[str, ExtractedVrf]) -> None:
    for cidx, c in blk.children:
        low = c.lower()
        if m := re.match(r"description\s+(.+)$", c, re.I):
            iface.description = m.group(1).strip().strip('"')
        elif m := re.match(r"(?:ip|ipv4) address\s+(.+)$", c, re.I):
            toks = m.group(1).split()
            if toks and toks[-1].lower() == "secondary":
                res.recognized.add(cidx)  # secondary address: real, but not the primary
                continue
            if toks and toks[0].lower() in ("dhcp", "negotiated"):
                res.recognized.add(cidx)
                continue
            ip, mask = _split_addr(toks[0], toks[1] if len(toks) > 1 else None)
            if ip is None:
                continue
            iface.ip_address, iface.subnet_mask = ip, mask
        elif re.match(r"no (?:ip|ipv4) address$", low):
            pass
        elif low == "shutdown":
            iface.admin_state = "down"
        elif low == "no shutdown":
            iface.admin_state = "up"
        elif m := re.match(r"switchport mode\s+(access|trunk|dynamic\s+\w+)", c, re.I):
            mode = m.group(1).upper()
            iface.switchport_mode = mode if mode in ("ACCESS", "TRUNK") else "DYNAMIC"
        elif m := re.match(r"(?:switchport access vlan|vlan access)\s+(\d+)$", c, re.I):
            iface.vlan = m.group(1)
            iface.switchport_mode = iface.switchport_mode or "ACCESS"
        elif m := re.match(r"(?:switchport trunk allowed vlan|vlan trunk allowed)\s+(.+)$", c, re.I):
            text = m.group(1).strip()
            if re.match(r"(?:add|remove|except)\b", text, re.I) and iface.allowed_vlans:
                current = set(expand_vlans(iface.allowed_vlans))
                delta = set(expand_vlans(text))
                current = current - delta if text.lower().startswith(("remove", "except")) else current | delta
                iface.allowed_vlans = _compress(current)
            elif text.lower() in ("all", "none"):
                iface.allowed_vlans = text.lower()
            else:
                iface.allowed_vlans = _compress(expand_vlans(text))
            iface.switchport_mode = iface.switchport_mode or "TRUNK"
        elif re.match(r"(?:switchport trunk native vlan|vlan trunk native)\s+\d+$", c, re.I):
            iface.switchport_mode = iface.switchport_mode or "TRUNK"
        elif re.match(r"(?:no switchport|no routing)$", low):
            iface.switchport_mode = "ROUTED"
        elif m := re.match(r"(?:ip vrf forwarding|vrf forwarding|vrf member|vrf attach)\s+(\S+)$", c, re.I):
            iface.vrf = m.group(1)
            vrfs.setdefault(iface.vrf, ExtractedVrf(name=iface.vrf))
        elif m := re.match(r"encapsulation dot1q\s+(\d+)", c, re.I):
            iface.vlan = m.group(1)
        elif m := re.match(r"(?:ip access-group|ip access-list)\s+(\S+)\s+(in|out)$", c, re.I):
            if m.group(2).lower() == "in":
                iface.acl_in = m.group(1)
            else:
                iface.acl_out = m.group(1)
        elif _IOS_IFACE_BENIGN.match(c):
            res.recognized.add(cidx)
            continue
        else:
            continue  # unmodelled + unrecognised -> stays "unknown" for the LLM
        res.consumed.add(cidx)


def _ios_route(text: str, idx: int) -> Optional[ExtractedRoute]:
    vrf = None
    if m := re.match(r"vrf\s+(\S+)\s+(.+)$", text, re.I):
        vrf, text = m.group(1), m.group(2)
    if m := re.search(r"\s+vrf\s+(\S+)\s*$", text, re.I):  # AOS-CX trailing form
        vrf, text = m.group(1), text[:m.start()]
    toks = text.split()
    if not toks:
        return None
    if "/" in toks[0]:
        try:
            net = ipaddress.ip_network(toks[0], strict=False)
        except ValueError:
            return None
        dest, mask, rest = str(net.network_address), (str(net.netmask) if net.version == 4 else str(net.prefixlen)), toks[1:]
    elif len(toks) >= 2 and _wildcard_ok(toks[0]) and _wildcard_ok(toks[1]):
        dest, mask, rest = toks[0], toks[1], toks[2:]
    else:
        return None
    if not rest:
        return None
    return ExtractedRoute(destination=dest, mask=mask, next_hop=rest[0], vrf=vrf, line=idx + 1)


_ACL_ENTRY = re.compile(
    r"^(?:(?P<seq>\d+)\s+)?(?P<action>permit|deny)\s+(?P<proto>\S+)\s+(?P<rest>.+)$", re.I)


def _acl_entry(text: str) -> Optional[Dict[str, str]]:
    m = _ACL_ENTRY.match(text.strip())
    if not m:
        return None
    entry = {"action": m.group("action").lower(), "protocol": m.group("proto").lower(), "match": m.group("rest").strip()}
    if m.group("seq"):
        entry["sequence"] = m.group("seq")
    return entry


def _ios_router(blk: _Block, proto: str, process: str, res: StructureResult) -> None:
    p = ExtractedProtocol(protocol=proto, process=process or None, line=blk.start + 1)
    res.consumed.add(blk.start)
    for cidx, c in blk.children:
        if m := re.match(r"(?:bgp )?router-id\s+(\S+)$", c, re.I):
            p.router_id = m.group(1)
        elif m := re.match(r"network\s+(\S+)(?:\s+(?:mask\s+)?(?!area\b)(\S+))?(?:\s+area\s+(\S+))?", c, re.I):
            p.networks.append(" ".join(x for x in (m.group(1), m.group(2), f"area {m.group(3)}" if m.group(3) else None) if x))
        elif m := re.match(r"neighbor\s+(\S+)\s+remote-as\s+(\S+)", c, re.I):
            p.neighbors.append(f"{m.group(1)} AS{m.group(2)}")
        elif re.match(r"(?:passive-interface|no passive-interface|default-information|redistribute|"
                      r"maximum-paths|auto-summary|no auto-summary|log-adjacency-changes|distance|timers|"
                      r"neighbor|address-family|exit-address-family|bgp |synchronization|no synchronization|"
                      r"area|summary-address|default-metric|metric|passive|exit|network|maximum-|ip |"
                      r"graceful-restart|nsf|vrf)\b", c, re.I):
            res.recognized.add(cidx)
            continue
        else:
            continue
        res.consumed.add(cidx)
    res.protocols.append(p)


# ---------------------------------------------------------------------------
# Family: vrp  (Huawei)
# ---------------------------------------------------------------------------

_VRP_IFACE_BENIGN = re.compile(
    r"^(?:undo\s+)?(?:speed|duplex|mtu|negotiation|stp|loopback-detect|port-security|storm-control|traffic-(?:policy|limit)|"
    r"lldp|ntdp|ndp|trust|qos|flow-|mac-address|dhcp|arp|ip\s+(?:urpf|forward-mode)|ospf|isis|"
    r"port\s+(?:hybrid|trunk pvid)|port-isolate|jumboframe|statistic|combo-port|set flow-stat)\b", re.I)


def _parse_vrp(raw: str) -> StructureResult:
    res = StructureResult(family="vrp")
    lines = raw.splitlines()
    ifaces: Dict[str, ExtractedInterface] = {}
    vlans: Dict[str, ExtractedVlan] = {}
    vrfs: Dict[str, ExtractedVrf] = {}
    for i, ln in enumerate(lines):
        s = ln.strip()
        if s and (s.startswith("#") or s.startswith("!") or s in ("return", "quit")):
            res.noise.add(i)

    for blk in _iter_indented_blocks(lines, ("#", "!")):
        h = blk.header
        if m := re.match(r"sysname\s+(\S+)", h, re.I):
            res.hostname = m.group(1)
            res.consumed.add(blk.start)
        elif m := re.match(r"vlan batch\s+(.+)$", h, re.I):
            for vid in expand_vlans(m.group(1)):
                vlans.setdefault(str(vid), ExtractedVlan(vlan_id=str(vid), line=blk.start + 1))
            res.consumed.add(blk.start)
        elif m := re.match(r"vlan\s+(\d+)$", h, re.I):
            v = vlans.setdefault(m.group(1), ExtractedVlan(vlan_id=m.group(1), line=blk.start + 1))
            res.consumed.add(blk.start)
            for cidx, c in blk.children:
                if mm := re.match(r"(?:name|description)\s+(.+)$", c, re.I):
                    if c.lower().startswith("name"):
                        v.name = mm.group(1).strip()
                    res.consumed.add(cidx)
        elif m := re.match(r"interface\s+(\S+)$", h, re.I):
            name = m.group(1)
            iface = ifaces.setdefault(name, ExtractedInterface(name=name, line=blk.start + 1))
            res.consumed.add(blk.start)
            if mm := re.fullmatch(r"(?i)vlanif(\d+)", name):
                iface.vlan = mm.group(1)
            trunk_vlans: List[int] = []
            for cidx, c in blk.children:
                if mm := re.match(r"description\s+(.+)$", c, re.I):
                    iface.description = mm.group(1).strip()
                elif mm := re.match(r"ip address\s+(\S+)\s+(\S+)(\s+sub)?$", c, re.I):
                    if mm.group(3):
                        res.recognized.add(cidx)
                        continue
                    ip, mask = _split_addr(mm.group(1), mm.group(2))
                    if ip is None:
                        continue
                    iface.ip_address, iface.subnet_mask = ip, mask
                elif re.match(r"undo shutdown$", c, re.I):
                    iface.admin_state = "up"
                elif re.match(r"shutdown$", c, re.I):
                    iface.admin_state = "down"
                elif mm := re.match(r"port link-type\s+(\S+)", c, re.I):
                    t = mm.group(1).upper()
                    iface.switchport_mode = t if t in ("ACCESS", "TRUNK") else "HYBRID"
                elif mm := re.match(r"port default vlan\s+(\d+)$", c, re.I):
                    iface.vlan = mm.group(1)
                    iface.switchport_mode = iface.switchport_mode or "ACCESS"
                elif mm := re.match(r"port trunk allow-pass vlan\s+(.+)$", c, re.I):
                    trunk_vlans.extend(expand_vlans(mm.group(1)))
                    iface.switchport_mode = iface.switchport_mode or "TRUNK"
                elif mm := re.match(r"ip binding vpn-instance\s+(\S+)$", c, re.I):
                    iface.vrf = mm.group(1)
                elif mm := re.match(r"traffic-filter\s+(inbound|outbound)\s+acl\s+(\S+)", c, re.I):
                    if mm.group(1).lower() == "inbound":
                        iface.acl_in = mm.group(2)
                    else:
                        iface.acl_out = mm.group(2)
                elif _VRP_IFACE_BENIGN.match(c):
                    res.recognized.add(cidx)
                    continue
                else:
                    continue
                res.consumed.add(cidx)
            if trunk_vlans:
                iface.allowed_vlans = _compress(trunk_vlans)
        elif m := re.match(r"ip vpn-instance\s+(\S+)$", h, re.I):
            vrf = vrfs.setdefault(m.group(1), ExtractedVrf(name=m.group(1)))
            res.consumed.add(blk.start)
            for cidx, c in blk.children:
                if mm := re.match(r"route-distinguisher\s+(\S+)$", c, re.I):
                    vrf.route_distinguisher = mm.group(1)
                    res.consumed.add(cidx)
                elif re.match(r"(?:vpn-target|ipv4-family|ipv6-family|description)\b", c, re.I):
                    res.recognized.add(cidx)
        elif m := re.match(r"ip route-static\s+(?:vpn-instance\s+(\S+)\s+)?(\S+)\s+(\S+)\s+(\S+)", h, re.I):
            dest, mask = m.group(2), m.group(3)
            if mask.isdigit():
                mask = _prefix_to_mask(int(mask)) or mask
            if _wildcard_ok(dest):
                res.routes.append(ExtractedRoute(destination=dest, mask=mask, next_hop=m.group(4),
                                                 vrf=m.group(1), line=blk.start + 1))
                res.consumed.add(blk.start)
        elif re.match(r"(?:stp|lldp|dhcp|dns|clock|diffserv|traffic |arp |lacp|cluster|drop-profile|qos|vrrp|"
                      r"undo (?:stp|lldp|dhcp|dns|arp|lacp|cluster|vrrp)|sysname)\b", h, re.I):
            res.recognized.add(blk.start)
            for cidx, _c in blk.children:
                res.recognized.add(cidx)

    # VLAN membership from interfaces
    for iface in ifaces.values():
        members: List[int] = []
        if iface.vlan and iface.switchport_mode in ("ACCESS", None):
            members.append(int(iface.vlan))
        if iface.switchport_mode == "TRUNK" and iface.allowed_vlans:
            members.extend(expand_vlans(iface.allowed_vlans))
        for vid in members:
            v = vlans.setdefault(str(vid), ExtractedVlan(vlan_id=str(vid), declared=False))
            if iface.name not in v.interfaces:
                v.interfaces.append(iface.name)
    res.interfaces = list(ifaces.values())
    res.vlans = sorted(vlans.values(), key=lambda v: int(v.vlan_id))
    res.vrfs = list(vrfs.values())
    return res


# ---------------------------------------------------------------------------
# Family: junos
# ---------------------------------------------------------------------------


def junos_hierarchy_to_set(raw: str) -> List[Tuple[int, str]]:
    """Convert Junos ``{ }`` hierarchy to ``set`` lines. Returns
    (source line index, "set a b c") pairs. Deterministic; unbalanced input
    simply yields fewer lines."""
    out: List[Tuple[int, str]] = []
    path: List[List[str]] = []
    for i, ln in enumerate(raw.splitlines()):
        s = ln.strip()
        if not s or s.startswith(("#", "/*", "*", "//")):
            continue
        s = re.sub(r"^(?:inactive|protect):\s*", "", s)
        if s.endswith("{"):
            path.append(s[:-1].strip().split())
        elif s == "}":
            if path:
                path.pop()
        elif s.endswith(";"):
            flat = [t for seg in path for t in seg] + s[:-1].strip().split()
            out.append((i, "set " + " ".join(flat)))
    return out


def _parse_junos(raw: str) -> StructureResult:
    res = StructureResult(family="junos")
    lines = raw.splitlines()
    has_set = any(l.strip().startswith("set ") for l in lines)
    if has_set:
        stmts = [(i, l.strip()) for i, l in enumerate(lines) if l.strip().startswith("set ")]
        for i, l in enumerate(lines):
            if l.strip().startswith(("#", "/*", "*", "//")):
                res.noise.add(i)
    else:
        stmts = junos_hierarchy_to_set(raw)
        for i, l in enumerate(lines):
            s = l.strip()
            if s in ("{", "}") or s.endswith("{") or s.startswith(("#", "/*", "*", "//")):
                res.noise.add(i)

    ifaces: Dict[str, ExtractedInterface] = {}
    vlans: Dict[str, ExtractedVlan] = {}
    vlan_by_name: Dict[str, str] = {}
    vrfs: Dict[str, ExtractedVrf] = {}
    unit_vlan: Dict[str, str] = {}

    def iface(name: str, idx: int) -> ExtractedInterface:
        return ifaces.setdefault(name, ExtractedInterface(name=name, line=idx + 1))

    for i, s in stmts:
        m = re.match(r"set system host-name\s+\"?([^\s\";]+)", s)
        if m:
            res.hostname = m.group(1)
            res.consumed.add(i)
            continue
        if m := re.match(r"set vlans\s+(\S+)\s+vlan-id\s+(\d+)", s):
            v = vlans.setdefault(m.group(2), ExtractedVlan(vlan_id=m.group(2), line=i + 1))
            v.name = m.group(1)
            vlan_by_name[m.group(1)] = m.group(2)
            res.consumed.add(i)
            continue
        if m := re.match(r"set vlans\s+(\S+)\s+(?:description\s+.+|l3-interface\s+(\S+))$", s):
            res.consumed.add(i)
            if m.group(2):
                pass  # resolved after names are known
            continue
        if m := re.match(r"set interfaces\s+(\S+)\s+unit\s+(\d+)\s+family inet address\s+(\S+)", s):
            base, unit, addr = m.groups()
            name = base if unit == "0" else f"{base}.{unit}"
            ip, mask = _split_addr(addr)
            it = iface(name if base != "irb" else f"irb.{unit}", i)
            if ip:
                it.ip_address, it.subnet_mask = ip, mask
                res.consumed.add(i)
            if base == "irb" and it.vlan is None:
                it.vlan = None  # resolved below via l3-interface
            continue
        if m := re.match(r"set interfaces\s+(\S+)\s+description\s+\"?(.+?)\"?$", s):
            iface(m.group(1), i).description = m.group(2)
            res.consumed.add(i)
            continue
        if m := re.match(r"set interfaces\s+(\S+)\s+disable$", s):
            iface(m.group(1), i).admin_state = "down"
            res.consumed.add(i)
            continue
        if m := re.match(r"set interfaces\s+(\S+)\s+unit\s+(\d+)\s+vlan-id\s+(\d+)", s):
            it = iface(f"{m.group(1)}.{m.group(2)}", i)
            it.vlan = m.group(3)
            res.consumed.add(i)
            continue
        if m := re.match(r"set interfaces\s+(\S+)\s+unit\s+\d+\s+family ethernet-switching\s+interface-mode\s+(\S+)", s):
            iface(m.group(1), i).switchport_mode = m.group(2).upper()
            res.consumed.add(i)
            continue
        if m := re.match(r"set interfaces\s+(\S+)\s+unit\s+\d+\s+family ethernet-switching\s+vlan members\s+(.+)$", s):
            it = iface(m.group(1), i)
            members = re.sub(r"[\[\]]", " ", m.group(2)).split()
            ids: List[int] = []
            for tok in members:
                if tok.isdigit():
                    ids.append(int(tok))
                elif tok in vlan_by_name:
                    ids.append(int(vlan_by_name[tok]))
                elif "-" in tok:
                    ids.extend(expand_vlans(tok))
            if ids:
                if it.switchport_mode == "TRUNK" or len(ids) > 1:
                    it.allowed_vlans = _compress(set(expand_vlans(it.allowed_vlans or "")) | set(ids))
                    it.switchport_mode = it.switchport_mode or "TRUNK"
                else:
                    it.vlan = str(ids[0])
                    it.switchport_mode = it.switchport_mode or "ACCESS"
                res.consumed.add(i)
            continue
        if m := re.match(r"set routing-options static route\s+(\S+)\s+next-hop\s+(\S+)", s):
            try:
                net = ipaddress.ip_network(m.group(1), strict=False)
                res.routes.append(ExtractedRoute(
                    destination=str(net.network_address),
                    mask=str(net.netmask) if net.version == 4 else str(net.prefixlen),
                    next_hop=m.group(2), line=i + 1))
                res.consumed.add(i)
            except ValueError:
                pass
            continue
        if m := re.match(r"set routing-instances\s+(\S+)\s+instance-type\s+(\S+)", s):
            if m.group(2) == "vrf":
                vrfs.setdefault(m.group(1), ExtractedVrf(name=m.group(1)))
            res.consumed.add(i)
            continue
        if m := re.match(r"set routing-instances\s+(\S+)\s+route-distinguisher\s+(\S+)", s):
            vrfs.setdefault(m.group(1), ExtractedVrf(name=m.group(1))).route_distinguisher = m.group(2)
            res.consumed.add(i)
            continue
        if m := re.match(r"set routing-instances\s+(\S+)\s+interface\s+(\S+)", s):
            target = ifaces.get(m.group(2)) or ifaces.get(re.sub(r"\.0$", "", m.group(2)))
            vrfs.setdefault(m.group(1), ExtractedVrf(name=m.group(1)))
            if target:
                target.vrf = m.group(1)
            res.consumed.add(i)
            continue

    # l3-interface (irb.N -> vlan) resolution + membership
    for i, s in stmts:
        if m := re.match(r"set vlans\s+(\S+)\s+l3-interface\s+(\S+)$", s):
            vid = vlan_by_name.get(m.group(1))
            if vid:
                it = ifaces.get(m.group(2))
                if it:
                    it.vlan = vid
    for it in ifaces.values():
        members: List[int] = []
        if it.vlan:
            members.append(int(it.vlan))
        if it.allowed_vlans:
            members.extend(expand_vlans(it.allowed_vlans))
        for vid in members:
            v = vlans.setdefault(str(vid), ExtractedVlan(vlan_id=str(vid), declared=False))
            if it.name not in v.interfaces:
                v.interfaces.append(it.name)
    res.interfaces = list(ifaces.values())
    res.vlans = sorted(vlans.values(), key=lambda v: int(v.vlan_id))
    res.vrfs = list(vrfs.values())
    return res


# ---------------------------------------------------------------------------
# Family: fortios
# ---------------------------------------------------------------------------


def _parse_fortios(raw: str) -> StructureResult:
    res = StructureResult(family="fortios")
    lines = raw.splitlines()
    ifaces: Dict[str, ExtractedInterface] = {}
    vlans: Dict[str, ExtractedVlan] = {}
    vrfs: Dict[str, ExtractedVrf] = {}
    stack: List[str] = []
    edit: Optional[str] = None
    edit_idx = 0
    cur: Dict[str, Tuple[str, int]] = {}  # key -> (value, line index) inside the current edit

    def flush() -> None:
        nonlocal cur, edit
        path = stack[-1] if stack else ""
        if edit is None:
            cur = {}
            return
        g = lambda k: cur.get(k, (None, -1))[0]  # noqa: E731
        if path == "system interface":
            it = ifaces.setdefault(edit, ExtractedInterface(name=edit, line=edit_idx + 1))
            if v := g("ip"):
                parts = v.split()
                if len(parts) == 2 and parts[0] != "0.0.0.0":
                    it.ip_address, it.subnet_mask = parts[0], parts[1]
                    res.consumed.add(cur["ip"][1])
                elif len(parts) == 2:
                    res.recognized.add(cur["ip"][1])  # explicit "unassigned"
            for key, attr in (("description", "description"), ("alias", None), ("vlanid", "vlan"), ("vrf", "vrf")):
                val = g(key)
                if val is None:
                    continue
                val = val.strip('"')
                if attr:
                    setattr(it, attr, val)
                    res.consumed.add(cur[key][1])
                else:
                    res.recognized.add(cur[key][1])
            if (val := g("status")) is not None:
                it.admin_state = "down" if val.strip('"') == "down" else "up"
                res.consumed.add(cur["status"][1])
            if it.vlan:
                it.switchport_mode = "ACCESS"
                v = vlans.setdefault(it.vlan, ExtractedVlan(vlan_id=it.vlan, name=it.name, line=edit_idx + 1))
                if it.name not in v.interfaces:
                    v.interfaces.append(it.name)
            for key in ("type", "interface", "role", "allowaccess", "vdom", "mode", "mtu", "mtu-override",
                        "speed", "device-identification", "lldp-reception", "lldp-transmission", "snmp-index",
                        "estimated-upstream-bandwidth", "estimated-downstream-bandwidth", "ip-managed-by-fortiipam",
                        "secondary-IP", "monitor-bandwidth", "netbios-forward", "broadcast-forward", "arp-reply",
                        "proxy-captive-portal", "fortiheartbeat", "bfd", "detectserver", "detectprotocol",
                        "gwdetect", "ping-serv-status", "dhcp-relay-service", "dhcp-relay-ip", "trust-ip-1",
                        "management-ip", "tcp-mss", "explicit-web-proxy", "security-mode", "l2forward"):
                if key in cur:
                    res.recognized.add(cur[key][1])
        elif path == "router static":
            dst = g("dst")
            gw = g("gateway")
            if gw:
                ip, mask = ("0.0.0.0", "0.0.0.0")
                if dst:
                    p = dst.split()
                    if len(p) == 2:
                        ip, mask = p
                    else:
                        try:
                            net = ipaddress.ip_network(dst, strict=False)
                            ip, mask = str(net.network_address), str(net.netmask)
                        except ValueError:
                            ip = None
                if ip:
                    res.routes.append(ExtractedRoute(destination=ip, mask=mask, next_hop=gw, line=edit_idx + 1))
                    for key in ("dst", "gateway"):
                        if key in cur:
                            res.consumed.add(cur[key][1])
            for key in ("device", "distance", "priority", "comment", "status", "blackhole", "weight", "vrf"):
                if key in cur:
                    res.recognized.add(cur[key][1])
        elif path == "system zone":
            for key in ("interface", "intrazone", "description"):
                if key in cur:
                    res.recognized.add(cur[key][1])
        cur = {}

    for i, ln in enumerate(lines):
        s = ln.strip()
        if not s:
            continue
        if s.startswith("#"):
            res.noise.add(i)
            continue
        if m := re.match(r"config\s+(.+)$", s):
            flush()
            edit = None
            stack.append(m.group(1).strip())
            res.noise.add(i)
        elif s == "end":
            flush()
            edit = None
            if stack:
                stack.pop()
            res.noise.add(i)
        elif m := re.match(r"edit\s+(.+)$", s):
            flush()
            edit = m.group(1).strip().strip('"')
            edit_idx = i
            if stack and stack[-1] in ("system interface", "router static"):
                res.consumed.add(i)
            else:
                res.noise.add(i)
        elif s == "next":
            flush()
            edit = None
            res.noise.add(i)
        elif m := re.match(r"set\s+(\S+)\s*(.*)$", s):
            if stack and stack[-1] == "system global" and m.group(1) == "hostname":
                res.hostname = m.group(2).strip().strip('"')
                res.consumed.add(i)
            elif edit is not None:
                cur[m.group(1)] = (m.group(2).strip(), i)
    flush()
    res.interfaces = list(ifaces.values())
    res.vlans = sorted(vlans.values(), key=lambda v: int(v.vlan_id))
    res.vrfs = list(vrfs.values())
    return res


# ---------------------------------------------------------------------------
# Family: panos
# ---------------------------------------------------------------------------


def _parse_panos(raw: str) -> StructureResult:
    res = StructureResult(family="panos")
    ifaces: Dict[str, ExtractedInterface] = {}
    vlans: Dict[str, ExtractedVlan] = {}
    vrfs: Dict[str, ExtractedVrf] = {}
    lines = raw.splitlines()
    for i, ln in enumerate(lines):
        s = ln.strip()
        if not s:
            continue
        if s.startswith("#"):
            res.noise.add(i)
            continue
        if m := re.match(r"set deviceconfig system hostname\s+(\S+)", s):
            res.hostname = m.group(1)
            res.consumed.add(i)
        elif m := re.match(r"set network interface (?:ethernet|aggregate-ethernet|loopback|vlan)\s+(\S+)\s+layer3\s+ip\s+(\S+)$", s):
            ip, mask = _split_addr(m.group(2))
            it = ifaces.setdefault(m.group(1), ExtractedInterface(name=m.group(1), line=i + 1))
            if ip:
                it.ip_address, it.subnet_mask, it.switchport_mode = ip, mask, "ROUTED"
                res.consumed.add(i)
        elif m := re.match(r"set network interface (?:ethernet|aggregate-ethernet)\s+(\S+)\s+layer3\s+units\s+(\S+)\s+ip\s+(\S+)$", s):
            ip, mask = _split_addr(m.group(3))
            it = ifaces.setdefault(m.group(2), ExtractedInterface(name=m.group(2), line=i + 1))
            if ip:
                it.ip_address, it.subnet_mask, it.switchport_mode = ip, mask, "ROUTED"
                res.consumed.add(i)
        elif m := re.match(r"set network interface (?:ethernet|aggregate-ethernet)\s+(\S+)\s+layer3\s+units\s+(\S+)\s+tag\s+(\d+)$", s):
            it = ifaces.setdefault(m.group(2), ExtractedInterface(name=m.group(2), line=i + 1))
            it.vlan = m.group(3)
            v = vlans.setdefault(m.group(3), ExtractedVlan(vlan_id=m.group(3), declared=False))
            if it.name not in v.interfaces:
                v.interfaces.append(it.name)
            res.consumed.add(i)
        elif m := re.match(r"set network interface (?:ethernet|aggregate-ethernet)\s+(\S+)\s+layer3\s+(?:units\s+\S+\s+)?comment\s+(.+)$", s):
            ifaces.setdefault(m.group(1), ExtractedInterface(name=m.group(1), line=i + 1)).description = m.group(2).strip('"')
            res.consumed.add(i)
        elif m := re.match(r"set network virtual-router\s+(\S+)\s+routing-table ip static-route\s+\S+\s+destination\s+(\S+)$", s):
            res.recognized.add(i)  # paired with nexthop below
        elif m := re.match(r"set network virtual-router\s+(\S+)\s+interface\s+\[?\s*([^\]]+?)\s*\]?$", s):
            vrfs.setdefault(m.group(1), ExtractedVrf(name=m.group(1)))
            for name in m.group(2).split():
                if name in ifaces:
                    ifaces[name].vrf = m.group(1)
            res.consumed.add(i)

    # static routes need destination + nexthop from separate lines
    dests: Dict[Tuple[str, str], Tuple[str, int]] = {}
    for i, ln in enumerate(lines):
        s = ln.strip()
        if m := re.match(r"set network virtual-router\s+(\S+)\s+routing-table ip static-route\s+(\S+)\s+destination\s+(\S+)$", s):
            dests[(m.group(1), m.group(2))] = (m.group(3), i)
    for i, ln in enumerate(lines):
        s = ln.strip()
        if m := re.match(r"set network virtual-router\s+(\S+)\s+routing-table ip static-route\s+(\S+)\s+nexthop ip-address\s+(\S+)$", s):
            key = (m.group(1), m.group(2))
            if key in dests:
                try:
                    net = ipaddress.ip_network(dests[key][0], strict=False)
                except ValueError:
                    continue
                res.routes.append(ExtractedRoute(
                    destination=str(net.network_address), mask=str(net.netmask), next_hop=m.group(3),
                    vrf=None if m.group(1) == "default" else m.group(1), line=i + 1))
                res.consumed.update({i, dests[key][1]})
                vrfs.setdefault(m.group(1), ExtractedVrf(name=m.group(1)))
    res.interfaces = list(ifaces.values())
    res.vlans = sorted(vlans.values(), key=lambda v: int(v.vlan_id))
    res.vrfs = list(vrfs.values())
    return res


# ---------------------------------------------------------------------------
# Family: routeros
# ---------------------------------------------------------------------------


def _routeros_kv(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for m in re.finditer(r'([\w-]+)=("[^"]*"|\S+)', text):
        out[m.group(1)] = m.group(2).strip('"')
    return out


def _parse_routeros(raw: str) -> StructureResult:
    res = StructureResult(family="routeros")
    ifaces: Dict[str, ExtractedInterface] = {}
    vlans: Dict[str, ExtractedVlan] = {}
    lines = raw.splitlines()
    # RouterOS exports wrap long commands with a trailing backslash
    logical: List[Tuple[int, List[int], str]] = []
    buf, idxs = "", []
    for i, ln in enumerate(lines):
        s = ln.strip()
        if buf or s:
            if s.endswith("\\"):
                buf += " " + s[:-1].strip()
                idxs.append(i)
                continue
            buf += (" " if buf else "") + s
            idxs.append(i)
            logical.append((idxs[0], idxs, buf.strip()))
            buf, idxs = "", []
    section = ""
    for start, idxs, text in logical:
        if not text:
            continue
        if text.startswith("#"):
            res.noise.update(idxs)
            continue
        if text.startswith("/"):
            hm = re.match(r"^(/[^=]*?)(?:\s+((?:add|set)\b.*))?$", text)
            section = re.sub(r"\s+", " ", hm.group(1).strip()) if hm else text
            if not (hm and hm.group(2)):
                res.consumed.update(idxs)  # bare section header
                continue
            text = hm.group(2)
        kv = _routeros_kv(text)
        if section == "/system identity" and text.startswith("set") and "name" in kv:
            res.hostname = kv["name"]
            res.consumed.update(idxs)
        elif section == "/ip address" and text.startswith("add") and "address" in kv:
            ip, mask = _split_addr(kv["address"])
            iface_name = kv.get("interface")
            if ip and iface_name:
                it = ifaces.setdefault(iface_name, ExtractedInterface(name=iface_name, line=start + 1))
                it.ip_address, it.subnet_mask = ip, mask
                it.description = it.description or kv.get("comment")
                if kv.get("disabled") == "yes":
                    it.admin_state = "down"
                res.consumed.update(idxs)
        elif section == "/interface vlan" and text.startswith("add") and "vlan-id" in kv:
            name = kv.get("name") or f"vlan{kv['vlan-id']}"
            it = ifaces.setdefault(name, ExtractedInterface(name=name, line=start + 1))
            it.vlan, it.switchport_mode = kv["vlan-id"], "ACCESS"
            v = vlans.setdefault(kv["vlan-id"], ExtractedVlan(vlan_id=kv["vlan-id"], name=kv.get("name"), line=start + 1))
            if name not in v.interfaces:
                v.interfaces.append(name)
            res.consumed.update(idxs)
        elif section == "/ip route" and text.startswith("add") and "gateway" in kv:
            dst = kv.get("dst-address", "0.0.0.0/0")
            try:
                net = ipaddress.ip_network(dst, strict=False)
            except ValueError:
                continue
            res.routes.append(ExtractedRoute(destination=str(net.network_address), mask=str(net.netmask),
                                             next_hop=kv["gateway"], vrf=kv.get("routing-table") if kv.get("routing-table") not in (None, "main") else None,
                                             line=start + 1))
            res.consumed.update(idxs)
        elif section == "/interface bridge vlan" and text.startswith("add") and "vlan-ids" in kv:
            for vid in expand_vlans(kv["vlan-ids"]):
                v = vlans.setdefault(str(vid), ExtractedVlan(vlan_id=str(vid), line=start + 1))
                for member in (kv.get("tagged", "") + "," + kv.get("untagged", "")).split(","):
                    if member and member not in v.interfaces:
                        v.interfaces.append(member)
            res.consumed.update(idxs)
        elif section.startswith(("/ip firewall", "/ip service", "/user", "/snmp", "/system", "/ip dns", "/ip dhcp",
                                 "/interface ethernet", "/interface bridge", "/ip pool", "/tool", "/routing",
                                 "/ip neighbor", "/certificate", "/ip ssh", "/ip settings")):
            res.recognized.update(idxs)
    res.interfaces = list(ifaces.values())
    res.vlans = sorted(vlans.values(), key=lambda v: int(v.vlan_id))
    return res


# ---------------------------------------------------------------------------
# Family: sonic
# ---------------------------------------------------------------------------


def _parse_sonic(raw: str) -> StructureResult:
    res = StructureResult(family="sonic")
    lines = raw.splitlines()
    for i, ln in enumerate(lines):
        if re.fullmatch(r"[\s{}\[\],]*", ln):
            res.noise.add(i)
    try:
        data = json.loads(raw)
    except ValueError:
        return res
    if not isinstance(data, dict):
        return res

    def line_of(*needles: str) -> Optional[int]:
        for i, ln in enumerate(lines):
            if all(n in ln for n in needles):
                return i
        return None

    meta = (data.get("DEVICE_METADATA") or {}).get("localhost") or {}
    if isinstance(meta, dict) and meta.get("hostname"):
        res.hostname = str(meta["hostname"])
        if (li := line_of('"hostname"')) is not None:
            res.consumed.add(li)
    ifaces: Dict[str, ExtractedInterface] = {}
    vlans: Dict[str, ExtractedVlan] = {}
    vrfs: Dict[str, ExtractedVrf] = {}

    def iface(name: str) -> ExtractedInterface:
        return ifaces.setdefault(name, ExtractedInterface(name=name, switchport_mode=None))

    for table in ("PORT", "PORTCHANNEL", "LOOPBACK_INTERFACE"):
        for name, attrs in (data.get(table) or {}).items():
            it = iface(name)
            if isinstance(attrs, dict):
                it.description = attrs.get("description") or it.description
                if attrs.get("admin_status"):
                    it.admin_state = "down" if str(attrs["admin_status"]).lower() == "down" else "up"
    for table in ("INTERFACE", "PORTCHANNEL_INTERFACE", "VLAN_INTERFACE", "LOOPBACK_INTERFACE"):
        for key, attrs in (data.get(table) or {}).items():
            if "|" in str(key):
                name, addr = str(key).split("|", 1)
                ip, mask = _split_addr(addr)
                it = iface(name)
                if ip and it.ip_address is None:
                    it.ip_address, it.subnet_mask = ip, mask
                    it.switchport_mode = "ROUTED"
            else:
                it = iface(str(key))
                if isinstance(attrs, dict) and attrs.get("vrf_name"):
                    it.vrf = attrs["vrf_name"]
                    vrfs.setdefault(it.vrf, ExtractedVrf(name=it.vrf))
    for name, attrs in (data.get("VLAN") or {}).items():
        vid = str((attrs or {}).get("vlanid") or re.sub(r"\D", "", name))
        if vid.isdigit():
            v = vlans.setdefault(vid, ExtractedVlan(vlan_id=vid, name=name, line=(line_of(f'"{name}"') or -1) + 1 or None))
            v.name = name
            iface(name).vlan = vid
    for key, attrs in (data.get("VLAN_MEMBER") or {}).items():
        if "|" not in str(key):
            continue
        vname, port = str(key).split("|", 1)
        vid = re.sub(r"\D", "", vname)
        if not vid:
            continue
        it = iface(port)
        tagged = str((attrs or {}).get("tagging_mode", "")).lower() == "tagged"
        if tagged:
            it.switchport_mode = "TRUNK"
            it.allowed_vlans = _compress(set(expand_vlans(it.allowed_vlans or "")) | {int(vid)})
        else:
            it.switchport_mode, it.vlan = "ACCESS", vid
        v = vlans.setdefault(vid, ExtractedVlan(vlan_id=vid, name=vname, declared=False))
        if port not in v.interfaces:
            v.interfaces.append(port)
    for name, attrs in (data.get("VRF") or {}).items():
        vrfs.setdefault(name, ExtractedVrf(name=name))
    for key, attrs in (data.get("STATIC_ROUTE") or {}).items():
        vrf, _, prefix = str(key).rpartition("|")
        if "|" not in str(key):
            vrf, prefix = "", str(key)
        nh = (attrs or {}).get("nexthop")
        try:
            net = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            continue
        if nh:
            res.routes.append(ExtractedRoute(
                destination=str(net.network_address), mask=str(net.netmask) if net.version == 4 else str(net.prefixlen),
                next_hop=str(nh).split(",")[0], vrf=vrf if vrf and vrf != "default" else None))
    res.interfaces = [i for i in ifaces.values() if i.ip_address or i.vlan or i.switchport_mode or i.description]
    res.vlans = sorted(vlans.values(), key=lambda v: int(v.vlan_id))
    res.vrfs = list(vrfs.values())
    # Mark the JSON lines that carry modelled tables as consumed
    for i, ln in enumerate(lines):
        if re.search(r'"(?:VLAN|VLAN_MEMBER|VLAN_INTERFACE|INTERFACE|PORTCHANNEL|PORT|STATIC_ROUTE|VRF|LOOPBACK_INTERFACE)"', ln):
            res.consumed.add(i)
    return res


# ---------------------------------------------------------------------------
# Family: gaia (Check Point clish)
# ---------------------------------------------------------------------------


def _parse_gaia(raw: str) -> StructureResult:
    res = StructureResult(family="gaia")
    ifaces: Dict[str, ExtractedInterface] = {}
    vlans: Dict[str, ExtractedVlan] = {}
    for i, ln in enumerate(raw.splitlines()):
        s = ln.strip()
        if not s:
            continue
        if s.startswith("#"):
            res.noise.add(i)
            continue
        if m := re.match(r"set hostname\s+(\S+)$", s):
            res.hostname = m.group(1)
            res.consumed.add(i)
        elif m := re.match(r"set interface\s+(\S+)\s+ipv4-address\s+(\S+)\s+mask-length\s+(\d+)", s):
            it = ifaces.setdefault(m.group(1), ExtractedInterface(name=m.group(1), line=i + 1))
            it.ip_address, it.subnet_mask, it.switchport_mode = m.group(2), _prefix_to_mask(int(m.group(3))), "ROUTED"
            res.consumed.add(i)
        elif m := re.match(r"set interface\s+(\S+)\s+state\s+(on|off)$", s):
            ifaces.setdefault(m.group(1), ExtractedInterface(name=m.group(1), line=i + 1)).admin_state = (
                "up" if m.group(2) == "on" else "down")
            res.consumed.add(i)
        elif m := re.match(r"set interface\s+(\S+)\s+comments\s+(.+)$", s):
            ifaces.setdefault(m.group(1), ExtractedInterface(name=m.group(1), line=i + 1)).description = m.group(2).strip('"')
            res.consumed.add(i)
        elif m := re.match(r"add interface\s+(\S+)\s+vlan\s+(\d+)$", s):
            name = f"{m.group(1)}.{m.group(2)}"
            it = ifaces.setdefault(name, ExtractedInterface(name=name, line=i + 1))
            it.vlan = m.group(2)
            v = vlans.setdefault(m.group(2), ExtractedVlan(vlan_id=m.group(2), declared=True, line=i + 1))
            v.interfaces.append(name)
            res.consumed.add(i)
        elif m := re.match(r"set static-route\s+(\S+)\s+nexthop gateway address\s+(\S+)\s+on$", s):
            dest = "0.0.0.0/0" if m.group(1) == "default" else m.group(1)
            try:
                net = ipaddress.ip_network(dest, strict=False)
            except ValueError:
                continue
            res.routes.append(ExtractedRoute(destination=str(net.network_address), mask=str(net.netmask),
                                             next_hop=m.group(2), line=i + 1))
            res.consumed.add(i)
        elif re.match(r"set (?:domainname|dns|clienv|timezone|date|time|core-dump)\b", s):
            res.recognized.add(i)
    res.interfaces = list(ifaces.values())
    res.vlans = sorted(vlans.values(), key=lambda v: int(v.vlan_id))
    return res


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_FAMILY_BY_VENDOR = (
    (("cisco", "arista", "aruba", "hpe", "nxos", "nx-os"), "ios"),
    (("huawei", "vrp"), "vrp"),
    (("juniper", "junos"), "junos"),
    (("fortinet", "fortigate", "fortios"), "fortios"),
    (("palo", "pan-os", "panos"), "panos"),
    (("mikrotik", "routeros"), "routeros"),
    (("sonic",), "sonic"),
    (("checkpoint", "check point", "gaia"), "gaia"),
)


def detect_family(vendor: Optional[str], raw_text: str) -> Optional[str]:
    """Structural family for a vendor name, else sniffed from the content
    (used when the vendor is unknown/ad-hoc -- structure is still parseable)."""
    v = (vendor or "").strip().lower()
    for keys, fam in _FAMILY_BY_VENDOR:
        if any(k in v for k in keys):
            return fam
    text = raw_text or ""
    stripped = text.lstrip()
    if stripped.startswith("{") and re.search(r'"(?:VLAN|PORT|DEVICE_METADATA|INTERFACE)"', text):
        return "sonic"
    if re.search(r"^config\s+system\s+(?:global|interface)", text, re.M):
        return "fortios"
    if re.search(r"^set\s+deviceconfig\s+system|^set\s+network\s+interface\s+ethernet", text, re.M):
        return "panos"
    if re.search(r"^/(?:ip|interface|system)\s+\w+", text, re.M):
        return "routeros"
    if re.search(r"^sysname\s+\S+|^interface\s+Vlanif\d+|^vlan batch\s", text, re.M):
        return "vrp"
    if re.search(r"^set\s+(?:system|interfaces|vlans|routing-options)\s", text, re.M) or re.search(
            r"^\s*(?:interfaces|system)\s*\{", text, re.M):
        return "junos"
    if re.search(r"^set\s+interface\s+\S+\s+ipv4-address\s", text, re.M):
        return "gaia"
    if re.search(r"^(?:interface\s+\S+|hostname\s+\S+|vlan\s+\d+)\s*$", text, re.M):
        return "ios"
    return None


_PARSERS = {
    "vrp": lambda raw, vendor: _parse_vrp(raw),
    "junos": lambda raw, vendor: _parse_junos(raw),
    "fortios": lambda raw, vendor: _parse_fortios(raw),
    "panos": lambda raw, vendor: _parse_panos(raw),
    "routeros": lambda raw, vendor: _parse_routeros(raw),
    "sonic": lambda raw, vendor: _parse_sonic(raw),
    "gaia": lambda raw, vendor: _parse_gaia(raw),
    "ios": _parse_ios,
}


def parse_structure(vendor: Optional[str], raw_text: str) -> StructureResult:
    """Parse the structure of ``raw_text``. Never raises; an unrecognised
    family returns an empty result (everything stays "unknown")."""
    family = detect_family(vendor, raw_text or "")
    if not family:
        return StructureResult()
    try:
        return _PARSERS[family](raw_text or "", vendor)
    except Exception:  # noqa: BLE001 -- best-effort, must never fail ingestion
        return StructureResult(family=family)
    