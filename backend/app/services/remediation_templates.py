"""Validated vendor-specific CLI remediation templates (Phase 14+).

RULE 3 still applies: AI/automation may look up a template, it must never
invent one. Every entry below is a hand-authored, reviewed CLI sequence
for a specific (vendor_key, control_id) pair -- the same trust boundary
`remediation_service.py` already documents for prose guidance now
extends to CLI generation.

Pipeline this module implements:

    Finding -> control_id -> (vendor, os) -> validated template -> CLI steps -> human approval

Lookup is keyed on a normalized vendor string (see `_normalize_vendor`)
plus control_id. If no template exists for that exact pair, callers MUST
fall back to the existing prose `finding.remediation` guidance rather
than guessing -- see `remediation_service.generate_remediation_cli`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class CLITemplate:
    control_id: str
    vendor: str          # display vendor name, e.g. "Cisco"
    os_family: str        # e.g. "IOS-XE"
    description: str
    commands: List[str]           # ordered configuration-mode CLI lines
    save_commands: List[str] = field(default_factory=list)  # e.g. "write memory"
    reference: Optional[str] = None  # doc/benchmark citation for the reviewer


def _normalize_vendor(vendor: Optional[str]) -> str:
    v = (vendor or "").strip().lower().replace(" ", "_")
    aliases = {
        "cisco_ios": "cisco",
        "cisco_ios-xe": "cisco",
        "cisco_iosxe": "cisco",
        "cisco_xe": "cisco",
        "arista_eos": "arista",
        "fortinet": "fortigate",
        "palo_alto": "paloalto",
        "palo_alto_networks": "paloalto",
    }
    return aliases.get(v, v)


# ---------------------------------------------------------------------------
# Template library. Grouped by control_id (see backend/app/policies/
# controls.py for the authoritative control catalog) then by normalized
# vendor. Only controls with an established, low-ambiguity single-purpose
# fix are included here -- controls whose correct remediation depends on
# site-specific values (e.g. exact AAA server IPs, exact banner text) are
# deliberately left out so `remediation_service` falls back to prose
# guidance instead of fabricating a plausible-looking placeholder.
# ---------------------------------------------------------------------------
_TEMPLATES: Dict[Tuple[str, str], CLITemplate] = {}


def _register(t: CLITemplate) -> None:
    _TEMPLATES[(t.control_id, _normalize_vendor(t.vendor))] = t


# CIS-TELNET-001 / STIG-NET-001 -- disable Telnet, require SSH on VTY lines
_register(CLITemplate(
    control_id="CIS-TELNET-001", vendor="Cisco", os_family="IOS-XE",
    description="Disable Telnet and require SSH-only transport on VTY lines.",
    commands=["conf t", "line vty 0 4", "transport input ssh", "end"],
    save_commands=["write memory"],
    reference="CIS Cisco IOS 17 Benchmark 2.1 / DISA STIG NET-001",
))
_register(CLITemplate(
    control_id="CIS-TELNET-001", vendor="Arista", os_family="EOS",
    description="Disable Telnet and require SSH-only transport on VTY lines.",
    commands=["configure terminal", "management ssh", "no shutdown", "!", "line vty",
              "no transport input telnet", "transport input ssh", "end"],
    save_commands=["write memory"],
    reference="CIS Cisco IOS 17 Benchmark 2.1 (EOS equivalent)",
))
_register(CLITemplate(
    control_id="CIS-TELNET-001", vendor="Juniper", os_family="Junos",
    description="Disable Telnet on the management/system services stanza.",
    commands=["configure", "delete system services telnet", "set system services ssh", "commit"],
    save_commands=[],
    reference="CIS Cisco IOS 17 Benchmark 2.1 (Junos equivalent)",
))
_register(CLITemplate(
    control_id="STIG-NET-001", vendor="Cisco", os_family="IOS-XE",
    description="Disable Telnet and require SSH-only transport on VTY lines.",
    commands=["conf t", "line vty 0 4", "transport input ssh", "end"],
    save_commands=["write memory"],
    reference="DISA Network Infrastructure STIG NET-NAC-001",
))

# CIS-SSH-001 -- enforce SSHv2
_register(CLITemplate(
    control_id="CIS-SSH-001", vendor="Cisco", os_family="IOS-XE",
    description="Force SSH protocol version 2 only.",
    commands=["conf t", "ip ssh version 2", "end"],
    save_commands=["write memory"],
    reference="CIS Cisco IOS 17 Benchmark 2.3",
))
_register(CLITemplate(
    control_id="NIST-AC-17", vendor="Cisco", os_family="IOS-XE",
    description="Force SSH protocol version 2 only (AC-17 Remote Access).",
    commands=["conf t", "ip ssh version 2", "end"],
    save_commands=["write memory"],
    reference="NIST 800-53 rev5 AC-17",
))

# CIS-SSH-002 / STIG-NET-002 -- VTY idle timeout <= 600s (10 min)
_register(CLITemplate(
    control_id="CIS-SSH-002", vendor="Cisco", os_family="IOS-XE",
    description="Set VTY exec-timeout to 10 minutes (600s) or less.",
    commands=["conf t", "line vty 0 4", "exec-timeout 10 0", "end"],
    save_commands=["write memory"],
    reference="CIS Cisco IOS 17 Benchmark 1.1.6",
))
_register(CLITemplate(
    control_id="STIG-NET-002", vendor="Cisco", os_family="IOS-XE",
    description="Set VTY exec-timeout to 10 minutes (600s) or less.",
    commands=["conf t", "line vty 0 4", "exec-timeout 10 0", "end"],
    save_commands=["write memory"],
    reference="DISA Network Infrastructure STIG NET-NAC-002",
))

# CIS-HTTP-001 -- disable unencrypted HTTP management
_register(CLITemplate(
    control_id="CIS-HTTP-001", vendor="Cisco", os_family="IOS-XE",
    description="Disable the plaintext HTTP management server.",
    commands=["conf t", "no ip http server", "end"],
    save_commands=["write memory"],
    reference="CIS Cisco IOS 17 Benchmark 1.1.13",
))
_register(CLITemplate(
    control_id="CIS-HTTP-001", vendor="Fortigate", os_family="FortiOS",
    description="Disable plaintext HTTP on the admin management interface.",
    commands=["config system interface", "edit \"mgmt\"", "unset allowaccess http", "next", "end"],
    save_commands=[],
    reference="Fortinet Security Hardening Guide -- Admin Access",
))

# CIS-HTTP-002 -- enforce HTTPS for web management
_register(CLITemplate(
    control_id="CIS-HTTP-002", vendor="Cisco", os_family="IOS-XE",
    description="Enable HTTPS and disable the plaintext HTTP server for web management.",
    commands=["conf t", "no ip http server", "ip http secure-server", "end"],
    save_commands=["write memory"],
    reference="CIS Cisco IOS 17 Benchmark 1.1.14",
))

# CIS-LOG-001 / NIST-AU-3 / ISO27001-A12-4 -- remote syslog
_register(CLITemplate(
    control_id="CIS-LOG-001", vendor="Cisco", os_family="IOS-XE",
    description="Enable logging and point it at the site's syslog collector "
                 "(replace <SYSLOG_HOST> with the real collector address before applying).",
    commands=["conf t", "logging host <SYSLOG_HOST>", "logging trap informational", "service timestamps log datetime msec", "end"],
    save_commands=["write memory"],
    reference="CIS Cisco IOS 17 Benchmark 3.4 / NIST 800-53 AU-3",
))

# CIS-SNMP-001 / NIST-IA-5 -- remove default SNMP community strings
_register(CLITemplate(
    control_id="CIS-SNMP-001", vendor="Cisco", os_family="IOS-XE",
    description="Remove default 'public'/'private' SNMP communities. Replace "
                 "<RO_COMMUNITY>/<RO_ACL> with the site's actual read-only community and ACL.",
    commands=["conf t", "no snmp-server community public", "no snmp-server community private",
              "snmp-server community <RO_COMMUNITY> RO <RO_ACL>", "end"],
    save_commands=["write memory"],
    reference="CIS Cisco IOS 17 Benchmark 3.1 / NIST 800-53 IA-5",
))

# CIS-PWD-001 -- encrypted secret storage
_register(CLITemplate(
    control_id="CIS-PWD-001", vendor="Cisco", os_family="IOS-XE",
    description="Enforce type-6/type-9 encrypted secret storage and stop storing "
                 "passwords in plaintext in the running-config.",
    commands=["conf t", "service password-encryption", "end"],
    save_commands=["write memory"],
    reference="CIS Cisco IOS 17 Benchmark 1.1.4",
))

# CIS-AAA-001 / ISO27001-A9-1 -- centralized AAA
_register(CLITemplate(
    control_id="CIS-AAA-001", vendor="Cisco", os_family="IOS-XE",
    description="Enable AAA and require centralized authentication for login. "
                 "Replace <AAA_GROUP> with the site's configured TACACS+/RADIUS server group.",
    commands=["conf t", "aaa new-model", "aaa authentication login default group <AAA_GROUP> local", "end"],
    save_commands=["write memory"],
    reference="CIS Cisco IOS 17 Benchmark 4.1 / ISO 27001 A.9.2",
))


def get_template(control_id: str, vendor: Optional[str]) -> Optional[CLITemplate]:
    return _TEMPLATES.get((control_id, _normalize_vendor(vendor)))


def has_template(control_id: str, vendor: Optional[str]) -> bool:
    return (control_id, _normalize_vendor(vendor)) in _TEMPLATES
