"""Nmap-based network device discovery (ingestion, pre-device-creation).

This is a *discovery* aid only: it tells an operator which hosts on a
subnet look like network/security devices and which management
transports they appear to expose, so the operator can turn a subset of
them into `Device` rows (with a real credential reference) that then flow
through the existing SSH/NETCONF/RESTCONF/SNMP/gNMI collectors in
collectors/registry.py. It never collects a configuration itself, never
stores credentials, and never creates a Device without an explicit
import step (RULE 6 / RULE 11 -- no parallel ingestion path, no implicit
trust of an unauthenticated scan result).

Uses python-nmap (a thin wrapper around the `nmap` binary) when both the
library and the binary are available. Offline-safe: if either is
missing, `scan_network` raises `NmapUnavailableError` so the router can
turn it into a clean 503 instead of a crash.

OS detection (`-O`) is opt-in via `os_detection=True` because it requires
the `nmap` process to have CAP_NET_RAW / root privileges (raw-socket SYN
probes). When the flag is set but nmap reports insufficient privileges the
error is wrapped in NmapUnavailableError with a clear message, rather than
silently returning empty os_guess fields. Operators running the API without
elevated nmap access should leave os_detection=False (default).
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:
    import nmap  # python-nmap
    NMAP_AVAILABLE = True
except ImportError:  # pragma: no cover
    NMAP_AVAILABLE = False
    nmap = None

# Well-known management ports -> the transport(s) they hint at. A host
# with 830 open is very likely NETCONF-speaking; 6030/9339 hint at gNMI
# (Arista's default gNMI port vs. the IANA-registered one); 443 is
# ambiguous (RESTCONF *or* plain HTTPS admin UI) so it's surfaced as
# "restconf_or_https" rather than asserted.
_PORT_HINTS: Dict[int, str] = {
    22: "ssh",
    23: "telnet",  # surfaced so operators can flag/remediate it, not to use it
    161: "snmp",
    179: "bgp",
    443: "restconf_or_https",
    830: "netconf",
    3306: "mysql",
    6030: "gnmi",
    8443: "restconf_or_https",
    9339: "gnmi",
}

# Nmap service-detection banner substrings -> a vendor guess. Best-effort
# only; always surfaced as `vendor_guess` with the raw banner alongside
# it, never written into a Device row without human confirmation.
_BANNER_VENDOR_HINTS = [
    ("cisco", "Cisco"),
    ("ios-xe", "Cisco"),
    ("junos", "Juniper"),
    ("juniper", "Juniper"),
    ("arista", "Arista"),
    ("eos", "Arista"),
    ("fortios", "Fortinet"),
    ("fortigate", "Fortinet"),
    ("pan-os", "Palo Alto Networks"),
    ("sonic", "SONiC"),
]

DEFAULT_PORTS = ",".join(str(p) for p in sorted(_PORT_HINTS))

# How many addresses go into a single nmap invocation when a discovery job
# runs chunked (see discovery_job_service.py). Small enough that a
# pause/cancel request takes effect within a few seconds even on a large
# /24, without so many nmap process spawns that overhead dominates.
CHUNK_SIZE = 8


def expand_targets(cidr: str) -> List[str]:
    """Turns `cidr` into an explicit list of addresses to scan one chunk at
    a time. A single host or hostname (not a network) is returned as a
    one-item list unchanged -- ipaddress only understands literal
    IPs/networks, so anything it can't parse (e.g. a DNS name) is treated
    as one opaque target, same as nmap would.
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return [cidr]

    if network.num_addresses <= 2:
        # /31, /32 (or the v6 equivalents) have no distinct network/broadcast
        # to exclude -- every address in them is a usable target.
        return [str(ip) for ip in network]
    return [str(ip) for ip in network.hosts()]


def chunk_targets(targets: List[str], chunk_size: int = CHUNK_SIZE) -> List[List[str]]:
    return [targets[i:i + chunk_size] for i in range(0, len(targets), chunk_size)]


class NmapUnavailableError(RuntimeError):
    """Raised when neither the nmap binary nor python-nmap is usable."""


@dataclass
class DiscoveredHost:
    ip: str
    hostname: Optional[str]
    state: str  # up/down
    open_ports: List[int] = field(default_factory=list)
    transport_hints: List[str] = field(default_factory=list)
    vendor_guess: Optional[str] = None
    banner: Optional[str] = None
    # OS fingerprint guess from nmap -O (None when os_detection=False or
    # nmap could not classify the host).
    os_guess: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "state": self.state,
            "open_ports": self.open_ports,
            "transport_hints": self.transport_hints,
            "vendor_guess": self.vendor_guess,
            "banner": self.banner,
            "os_guess": self.os_guess,
        }


def _guess_vendor(banners: List[str]) -> Optional[str]:
    joined = " ".join(b.lower() for b in banners if b)
    for needle, vendor in _BANNER_VENDOR_HINTS:
        if needle in joined:
            return vendor
    return None


def _best_os_match(osmatch_list: list) -> Optional[str]:
    """Return the highest-accuracy OS match name from nmap's osmatch list,
    or None if the list is empty / below 50% confidence."""
    if not osmatch_list:
        return None
    # nmap returns matches sorted best-first; accuracy is a string "0"-"100".
    best = osmatch_list[0]
    accuracy = int(best.get("accuracy", "0"))
    if accuracy < 50:
        return None
    name = best.get("name", "").strip()
    return name or None


def scan_network(
    cidr: str,
    ports: str = DEFAULT_PORTS,
    service_detection: bool = True,
    os_detection: bool = False,
    snmp_probe: bool = False,
    timeout_sec: int = 300,
    include_silent_hosts: bool = False,
) -> List[DiscoveredHost]:
    """Runs an nmap TCP-connect scan (`-sT -Pn`, `-sV` if `service_detection`,
    `-O --osscan-limit` if `os_detection`, `-sU -p U:161` if `snmp_probe`)
    of `cidr` against `ports` and returns one DiscoveredHost per address
    that actually looks like a live device.

    `-sT`/`-Pn` are used deliberately instead of a raw-socket SYN scan
    (`-sS`) so this runs without requiring the API process to hold
    CAP_NET_RAW/root -- a slower but privilege-safe default for a backend
    service. IMPORTANT: `-Pn` skips host-discovery (ICMP/ARP) entirely and
    tells nmap to *assume* every address in `cidr` is up, so every single
    IP -- not just the ones actually hosting something -- appears in
    `scanner.all_hosts()`. This used to be returned verbatim (256 "hosts"
    for a /24 with 2 real devices on it); we now only keep a host if it
    actually showed a live TCP/UDP signal (an open port, a banner, or an
    SNMP reply), which is the only real evidence -Pn's forced "up" state
    doesn't give us on its own. Pass `include_silent_hosts=True` to opt
    back into the old "list every address" behavior if that's ever useful
    for debugging.

    `os_detection=True` DOES require CAP_NET_RAW because `-O` uses raw
    sockets. `snmp_probe=True` also requires CAP_NET_RAW: `-sU` needs to
    read raw ICMP port-unreachable replies to tell closed vs. open|filtered
    UDP ports apart, which is exactly how SNMP (UDP/161) gets discovered --
    SNMP has no TCP presence on any of the target vendors, so a TCP-only
    scan (the previous behavior) could never surface it as a transport
    hint no matter how the device was configured. When the nmap binary
    reports a privilege error for either flag it's wrapped in
    NmapUnavailableError so the router can return a clean 503 with a
    descriptive message instead of silently coming back with no SNMP hint
    and no explanation.

    `timeout_sec` bounds the whole scan via nmap's own
    `--host-timeout`/args rather than an external kill, since python-nmap's
    scan() call is otherwise blocking with no built-in deadline.

    Never raises for "no hosts up" (returns an empty list) -- only for
    nmap/python-nmap being unavailable or the CIDR/argument being
    malformed, both of which are configuration errors the caller should
    surface distinctly from "scanned, found nothing".
    """
    if not NMAP_AVAILABLE:
        raise NmapUnavailableError(
            "python-nmap is not installed; network discovery unavailable in this environment"
        )

    scanner = nmap.PortScanner()
    args = f"-sT -Pn --host-timeout {timeout_sec}s"
    scan_ports = f"T:{ports}"
    if service_detection:
        args += " -sV --version-light"
    if os_detection:
        # --osscan-limit skips hosts with no open ports to avoid wasting time.
        args += " -O --osscan-limit"
    if snmp_probe:
        args += " -sU"
        scan_ports += ",U:161"

    try:
        scanner.scan(hosts=cidr, ports=scan_ports, arguments=args)
    except nmap.PortScannerError as e:
        err_str = str(e).lower()
        if "permission" in err_str or "operation not permitted" in err_str or "root" in err_str:
            raise NmapUnavailableError(
                "OS detection (-O) and/or the SNMP UDP probe (-sU) require elevated "
                "privileges (CAP_NET_RAW/root). Disable os_detection/snmp_probe or run "
                "nmap with the necessary capabilities."
            ) from e
        raise NmapUnavailableError(f"nmap binary not usable: {e}") from e

    hosts: List[DiscoveredHost] = []
    for ip in scanner.all_hosts():
        host_data = scanner[ip]
        state = host_data.state()
        open_ports: List[int] = []
        transport_hints: List[str] = []
        banners: List[str] = []

        tcp_ports = host_data.get("tcp", {}) or {}
        for port_str, port_info in tcp_ports.items():
            port = int(port_str)
            if port_info.get("state") != "open":
                continue
            open_ports.append(port)
            hint = _PORT_HINTS.get(port)
            if hint and hint not in transport_hints:
                transport_hints.append(hint)
            product = port_info.get("product", "")
            version = port_info.get("version", "")
            extrainfo = port_info.get("extrainfo", "")
            banner = " ".join(p for p in (product, version, extrainfo) if p)
            if banner:
                banners.append(banner)

        # UDP results (currently only 161/SNMP is probed). nmap reports
        # a responsive-but-unconfirmed UDP port as "open|filtered" rather
        # than "open" (no ICMP unreachable came back, but no SNMP-layer
        # ack either without actually speaking the protocol) -- treat
        # both as a live signal, since a *closed* UDP port would have come
        # back "closed" via an ICMP port-unreachable.
        udp_ports = host_data.get("udp", {}) or {}
        for port_str, port_info in udp_ports.items():
            port = int(port_str)
            udp_state = port_info.get("state")
            if udp_state not in ("open", "open|filtered"):
                continue
            open_ports.append(port)
            hint = _PORT_HINTS.get(port)
            if hint and hint not in transport_hints:
                transport_hints.append(hint)

        hostnames = host_data.get("hostnames", []) or []
        hostname = next((h.get("name") for h in hostnames if h.get("name")), None)

        # OS fingerprint (only populated when os_detection=True and nmap succeeded).
        osmatch_list = host_data.get("osmatch", []) or []
        os_guess = _best_os_match(osmatch_list)

        # -Pn forces nmap to report every address as "up" even though host
        # discovery (ICMP/ARP) was skipped entirely -- that's WHY every
        # address in the CIDR used to show up as a "discovered host". The
        # only real evidence of something actually being there is a port
        # response (TCP or UDP) or a resolvable hostname. Drop anything
        # without that evidence unless the caller explicitly wants the
        # raw "-Pn says up" list.
        has_signal = bool(open_ports) or bool(hostname)
        if not has_signal and not include_silent_hosts:
            continue

        hosts.append(DiscoveredHost(
            ip=ip,
            hostname=hostname,
            state=state if has_signal else "unconfirmed",
            open_ports=sorted(open_ports),
            transport_hints=transport_hints,
            vendor_guess=_guess_vendor(banners),
            banner="; ".join(banners) or None,
            os_guess=os_guess,
        ))

    return hosts