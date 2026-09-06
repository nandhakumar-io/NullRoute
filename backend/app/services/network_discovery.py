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
"""
from __future__ import annotations

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

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "state": self.state,
            "open_ports": self.open_ports,
            "transport_hints": self.transport_hints,
            "vendor_guess": self.vendor_guess,
            "banner": self.banner,
        }


def _guess_vendor(banners: List[str]) -> Optional[str]:
    joined = " ".join(b.lower() for b in banners if b)
    for needle, vendor in _BANNER_VENDOR_HINTS:
        if needle in joined:
            return vendor
    return None


def scan_network(cidr: str, ports: str = DEFAULT_PORTS, service_detection: bool = True,
                  timeout_sec: int = 300) -> List[DiscoveredHost]:
    """Runs an nmap TCP-connect scan (`-sT -Pn`, `-sV` if `service_detection`)
    of `cidr` against `ports` and returns one DiscoveredHost per responding
    address.

    `-sT`/`-Pn` are used deliberately instead of a raw-socket SYN scan
    (`-sS`) so this runs without requiring the API process to hold
    CAP_NET_RAW/root -- a slower but privilege-safe default for a backend
    service. `timeout_sec` bounds the whole scan via nmap's own
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
    if service_detection:
        args += " -sV --version-light"

    try:
        scanner.scan(hosts=cidr, ports=ports, arguments=args)
    except nmap.PortScannerError as e:
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

        hostnames = host_data.get("hostnames", []) or []
        hostname = next((h.get("name") for h in hostnames if h.get("name")), None)

        hosts.append(DiscoveredHost(
            ip=ip,
            hostname=hostname,
            state=state,
            open_ports=sorted(open_ports),
            transport_hints=transport_hints,
            vendor_guess=_guess_vendor(banners),
            banner="; ".join(banners) or None,
        ))

    return hosts
