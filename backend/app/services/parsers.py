"""
Deterministic, rule-based parsers that turn known vendor syntax into
NormalizedParameter entries on the Security Baseline Model.

Design: each vendor module is a list of (regex, normalized_parameter, value_fn)
tuples. Any config line that matches NONE of the known patterns is collected
into `unknown_lines` and handed to the AI/RAG normalization pipeline
(ai/normalize.py) instead — the parser never guesses.

Error handling: a malformed configuration must never fail the whole scan
(a single bad line, truncated section, or a value_fn that can't coerce a
captured group is not grounds to abandon everything else that DID parse
cleanly). Each line is bucketed into exactly one outcome:
  - successful  : matched a known rule and the value_fn ran without error
  - malformed   : looks like a config directive but is structurally broken
                   (unbalanced quotes, dangling continuation, truncated
                   token) so we don't even try to normalize it
  - unsupported : well-formed but not covered by any rule for this vendor
                   (routed to the AI/RAG pipeline, same as before)
A rule whose value_fn raises for a specific match does not propagate — that
match's line is downgraded to unsupported/malformed and parsing continues.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

from pydantic import ValidationError

from app.models.baseline import NormalizedParameter, SecurityBaselineModel

Rule = Tuple[re.Pattern, str, Callable[[re.Match], object]]


@dataclass
class ParseStats:
    """Per-scan parse coverage, surfaced to the UI/API as e.g.
    Parsed: 91% / Unsupported: 6% / Malformed: 3%."""

    total_lines: int = 0
    successful: int = 0
    unsupported: int = 0
    malformed: int = 0
    malformed_lines: List[str] = field(default_factory=list)
    rule_errors: List[str] = field(default_factory=list)

    def _pct(self, n: int) -> float:
        return round(100.0 * n / self.total_lines, 1) if self.total_lines else 0.0

    def to_dict(self) -> dict:
        return {
            "total_lines": self.total_lines,
            "parsed_pct": self._pct(self.successful),
            "unsupported_pct": self._pct(self.unsupported),
            "malformed_pct": self._pct(self.malformed),
            "malformed_lines": self.malformed_lines[:50],
            "rule_errors": self.rule_errors[:50],
        }


# Heuristic, vendor-agnostic "this line is structurally broken" check — not
# "this line means something we don't understand" (that's unsupported).
_MALFORMED_CHECKS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'^[^"]*"[^"]*$'), "unbalanced quote"),
    (re.compile(r'\\\s*$'), "dangling line continuation"),
    (re.compile(r'^[\{\[][^\}\]]*$'), "unterminated brace/bracket"),
    (re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f]'), "embedded control characters"),
]


def _looks_malformed(line: str) -> bool:
    return any(pattern.search(line) for pattern, _ in _MALFORMED_CHECKS)


def _rules_cisco() -> List[Rule]:
    return [
        (re.compile(r"^hostname\s+(\S+)", re.M), "device.hostname", lambda m: m.group(1)),
        (re.compile(r"^ip ssh version\s+v?(\d+)", re.M | re.I), "management.ssh.version", lambda m: int(m.group(1))),
        (re.compile(r"^ip ssh time-out\s+(\d+)", re.M), "management.ssh.idle_timeout", lambda m: int(m.group(1)) * 60),
        (re.compile(r"^line vty.*\n(?:.*\n)*?\s*transport input (\S+)", re.M), "management.ssh.enabled",
         lambda m: "ssh" in m.group(1) and "telnet" not in m.group(1)),
        (re.compile(r"^line vty.*\n(?:.*\n)*?\s*transport input.*telnet", re.M), "management.telnet.enabled", lambda m: True),
        (re.compile(r"^no ip http server", re.M), "management.http.enabled", lambda m: False),
        (re.compile(r"^ip http server\b(?!.*secure)", re.M), "management.http.enabled", lambda m: True),
        (re.compile(r"^ip http secure-server", re.M), "management.http.https_only", lambda m: True),
        (re.compile(r"^logging (?:host|server) (\S+)", re.M), "logging.remote_syslog", lambda m: True),
        (re.compile(r"^logging trap (\S+)", re.M), "logging.log_level", lambda m: m.group(1)),
        (re.compile(r"^aaa new-model", re.M), "aaa.enabled", lambda m: True),
        (re.compile(r"^aaa authentication login default (\S+)", re.M), "aaa.authentication_method", lambda m: m.group(1)),
        (re.compile(r"^snmp-server community (\S+)", re.M), "snmp.community_strings_default",
         lambda m: m.group(1).lower() in ("public", "private")),
        (re.compile(r"^service password-encryption", re.M), "password_policy.encrypted_storage", lambda m: True),
        (re.compile(r"^banner (?:motd|login)", re.M), "management.banner_configured", lambda m: True),
        (re.compile(r"^ntp server\s+(\S+)", re.M), "logging.ntp_synced", lambda m: True),
    ]


def _rules_juniper() -> List[Rule]:
    return [
        (re.compile(r"^set system host-name\s+(\S+)", re.M), "device.hostname", lambda m: m.group(1)),
        (re.compile(r"^set system services ssh\b", re.M), "management.ssh.enabled", lambda m: True),
        (re.compile(r"^set system services ssh protocol-version v?(\d+)", re.M | re.I), "management.ssh.version", lambda m: int(m.group(1))),
        (re.compile(r"^set system login idle-time (\d+)", re.M), "management.ssh.idle_timeout", lambda m: int(m.group(1)) * 60),
        (re.compile(r"^set system services telnet", re.M), "management.telnet.enabled", lambda m: True),
        (re.compile(r"^set system services web-management http\b(?!s)", re.M), "management.http.enabled", lambda m: True),
        (re.compile(r"^set system services web-management https", re.M), "management.http.https_only", lambda m: True),
        (re.compile(r"^set system syslog host (\S+)", re.M), "logging.remote_syslog", lambda m: True),
        (re.compile(r"^set system login user .* authentication", re.M), "aaa.local_fallback", lambda m: True),
        (re.compile(r"^set snmp community (\S+)", re.M), "snmp.community_strings_default",
         lambda m: m.group(1).strip('"').lower() in ("public", "private")),
        (re.compile(r"^set system ntp server\s+(\S+)", re.M), "logging.ntp_synced", lambda m: True),
        (re.compile(r"^set system login message", re.M), "management.banner_configured", lambda m: True),
    ]


def _rules_fortios() -> List[Rule]:
    return [
        (re.compile(r"set hostname\s+\"?([\w-]+)\"?", re.M), "device.hostname", lambda m: m.group(1)),
        (re.compile(r"set admin-ssh-port\s+(\d+)", re.M), "management.ssh.port", lambda m: int(m.group(1))),
        (re.compile(r"set admin-ssh-v1\s+disable", re.M), "management.ssh.version", lambda m: 2),
        (re.compile(r"set admintimeout\s+(\d+)", re.M), "management.ssh.idle_timeout", lambda m: int(m.group(1)) * 60),
        (re.compile(r"set admin-telnet\s+(enable|disable)", re.M), "management.telnet.enabled", lambda m: m.group(1) == "enable"),
        (re.compile(r"set admin-https\s+enable", re.M), "management.http.https_only", lambda m: True),
        (re.compile(r"set admin-http\s+disable", re.M), "management.http.enabled", lambda m: False),
        (re.compile(r"set server\s+\"?([\d.]+)\"?\s*\n\s*set status enable", re.M), "logging.remote_syslog", lambda m: True),
        (re.compile(r"set password-policy\s+enable", re.M), "password_policy.complexity_required", lambda m: True),
        (re.compile(r"set minimum-length\s+(\d+)", re.M), "password_policy.min_length", lambda m: int(m.group(1))),
    ]


def _rules_panos() -> List[Rule]:
    return [
        (re.compile(r"set deviceconfig system hostname\s+(\S+)", re.M), "device.hostname", lambda m: m.group(1)),
        (re.compile(r"set deviceconfig system.*service.*disable-telnet\s+yes", re.M), "management.telnet.enabled", lambda m: False),
        (re.compile(r"set deviceconfig system.*service.*disable-http\s+yes", re.M), "management.http.enabled", lambda m: False),
        (re.compile(r"set deviceconfig system.*service.*disable-https\s+no", re.M), "management.http.https_only", lambda m: True),
        (re.compile(r"set deviceconfig system.*idle-timeout\s+(\d+)", re.M), "management.ssh.idle_timeout", lambda m: int(m.group(1)) * 60),
        (re.compile(r"set shared log-settings syslog", re.M), "logging.remote_syslog", lambda m: True),
        (re.compile(r"set mgt-config password-complexity enabled\s+yes", re.M), "password_policy.complexity_required", lambda m: True),
    ]


def _rules_arista() -> List[Rule]:
    return [
        (re.compile(r"^hostname\s+(\S+)", re.M), "device.hostname", lambda m: m.group(1)),
        (re.compile(r"^management ssh\n(?:.*\n)*?\s*idle-timeout\s+(\d+)", re.M), "management.ssh.idle_timeout", lambda m: int(m.group(1)) * 60),
        (re.compile(r"^no management telnet|^management telnet\n\s*no shutdown", re.M), "management.telnet.enabled", lambda m: "no management telnet" not in m.group(0)),
        (re.compile(r"^management api http-commands\n(?:.*\n)*?\s*no shutdown", re.M), "management.http.enabled", lambda m: True),
        (re.compile(r"^management api http-commands\n(?:.*\n)*?\s*protocol https", re.M), "management.http.https_only", lambda m: True),
        (re.compile(r"^logging host\s+(\S+)", re.M), "logging.remote_syslog", lambda m: True),
        (re.compile(r"^aaa authentication login default", re.M), "aaa.enabled", lambda m: True),
    ]


def _rules_sonic() -> List[Rule]:
    # SONiC ships JSON-ish config_db — treated as line-oriented key hints for the MVP demo.
    return [
        (re.compile(r'"hostname"\s*:\s*"([\w-]+)"', re.M), "device.hostname", lambda m: m.group(1)),
        (re.compile(r'"authentication"\s*:\s*{\s*"login"\s*:\s*"(\w+)"', re.M), "aaa.authentication_method", lambda m: m.group(1)),
        (re.compile(r'"SYSLOG_SERVER"', re.M), "logging.remote_syslog", lambda m: True),
        (re.compile(r'"ssh"\s*:\s*{\s*"enabled"\s*:\s*"(true|false)"', re.M), "management.ssh.enabled", lambda m: m.group(1) == "true"),
    ]


VENDOR_RULES = {
    "Cisco": _rules_cisco(),
    "Juniper": _rules_juniper(),
    "Fortinet": _rules_fortios(),
    "Palo Alto Networks": _rules_panos(),
    "Arista": _rules_arista(),
    "SONiC": _rules_sonic(),
}


@dataclass
class StructuredFact:
    """One deterministically-extracted fact that targets a List[...] or a
    nested-object field on the baseline (radius/tacacs servers, VLANs,
    ACLs, interfaces, routing, ...), as opposed to the flat scalar `Rule`
    tuples above. Carries its own line span so it participates in the same
    parsed/unsupported/malformed line accounting as flat rules."""

    start_line: int
    end_line: int
    parameter: str
    value: object
    append: bool
    raw: str


def _line_span(raw_text: str, start: int, end: int) -> Tuple[int, int]:
    return raw_text.count("\n", 0, start), raw_text.count("\n", 0, end)


def _structured_extract_cisco(raw_text: str) -> List[StructuredFact]:
    """Multi-field / nested-block facts a single flat regex->one-value Rule
    can't express: RADIUS/TACACS+ server definitions, VLAN/ACL/route/OSPF/
    BGP facts, and per-interface attributes -- the exact relationships lost
    by pure line-at-a-time normalization (problem statement item 5)."""
    facts: List[StructuredFact] = []

    for m in re.finditer(
        r"^radius server (\S+)\n(?:.*\n)*?\s*address ipv4 (\S+)"
        r"(?: auth-port (\d+))?(?: acct-port (\d+))?",
        raw_text, re.M,
    ):
        entry = {"address": m.group(2)}
        if m.group(3):
            entry["auth_port"] = int(m.group(3))
        if m.group(4):
            entry["acct_port"] = int(m.group(4))
        s, e = _line_span(raw_text, m.start(), m.end())
        facts.append(StructuredFact(s, e, "aaa.radius_servers", entry, True, m.group(0).strip()[:300]))

    for m in re.finditer(
        r"^tacacs server (\S+)\n(?:.*\n)*?\s*address ipv4 (\S+)(?: port (\d+))?",
        raw_text, re.M,
    ):
        entry = {"address": m.group(2)}
        if m.group(3):
            entry["port"] = int(m.group(3))
        s, e = _line_span(raw_text, m.start(), m.end())
        facts.append(StructuredFact(s, e, "aaa.tacacs_servers", entry, True, m.group(0).strip()[:300]))

    for m in re.finditer(r"^router ospf (\d+)", raw_text, re.M):
        s, e = _line_span(raw_text, m.start(), m.end())
        facts.append(StructuredFact(s, e, "routing.ospf", {"enabled": True, "process_id": int(m.group(1))},
                                     False, m.group(0).strip()[:300]))

    for m in re.finditer(r"^router bgp (\d+)", raw_text, re.M):
        s, e = _line_span(raw_text, m.start(), m.end())
        facts.append(StructuredFact(s, e, "routing.bgp", {"enabled": True, "as_number": int(m.group(1))},
                                     False, m.group(0).strip()[:300]))

    for m in re.finditer(r"^ip route (\S+) (\S+) (\S+)", raw_text, re.M):
        s, e = _line_span(raw_text, m.start(), m.end())
        facts.append(StructuredFact(s, e, "routing.static_routes",
                                     {"destination": f"{m.group(1)} {m.group(2)}", "next_hop": m.group(3)},
                                     True, m.group(0).strip()[:300]))

    for m in re.finditer(r"^logging (?:host|server) (\S+)", raw_text, re.M):
        s, e = _line_span(raw_text, m.start(), m.end())
        facts.append(StructuredFact(s, e, "logging.syslog_servers", m.group(1), True, m.group(0).strip()[:300]))
        facts.append(StructuredFact(s, e, "logging.syslog_servers_detail",
                                     {"address": m.group(1), "severity": None}, True, m.group(0).strip()[:300]))

    for m in re.finditer(r"^ntp server\s+(\S+)", raw_text, re.M):
        s, e = _line_span(raw_text, m.start(), m.end())
        facts.append(StructuredFact(s, e, "logging.ntp.servers", m.group(1), True, m.group(0).strip()[:300]))

    for m in re.finditer(r"^snmp-server community (\S+)", raw_text, re.M):
        s, e = _line_span(raw_text, m.start(), m.end())
        facts.append(StructuredFact(s, e, "snmp.community_strings", m.group(1), True, m.group(0).strip()[:300]))

    for m in re.finditer(r"^snmp-server host (\S+)", raw_text, re.M):
        s, e = _line_span(raw_text, m.start(), m.end())
        facts.append(StructuredFact(s, e, "snmp.trap_servers", m.group(1), True, m.group(0).strip()[:300]))

    # Per-interface attributes: ACL bindings, IP address, description,
    # admin state, VLAN membership. Tracked by nearest preceding
    # `interface <name>` line, same convention as batfish_service.infer_zones.
    lines = raw_text.splitlines()
    current_iface: Optional[str] = None
    for i, line in enumerate(lines):
        m_if = re.match(r"^interface\s+(\S+)", line)
        if m_if:
            current_iface = m_if.group(1)
            continue
        if not current_iface:
            continue
        m_acl = re.match(r"^\s*ip access-group (\S+)\s+(in|out)", line)
        if m_acl:
            facts.append(StructuredFact(i, i, "acls",
                                         {"name": m_acl.group(1), "applied_interface": current_iface,
                                          "direction": m_acl.group(2)},
                                         True, line.strip()[:300]))
            continue
        m_ip = re.match(r"^\s*ip address\s+(\S+)\s+(\S+)", line)
        if m_ip:
            facts.append(StructuredFact(i, i, "interfaces_detail",
                                         {"name": current_iface, "ip_address": m_ip.group(1)},
                                         True, line.strip()[:300]))
            continue
        m_vlan = re.match(r"^\s*switchport access vlan\s+(\d+)", line)
        if m_vlan:
            vlan_id = int(m_vlan.group(1))
            facts.append(StructuredFact(i, i, "vlans", {"id": vlan_id}, True, line.strip()[:300]))
            facts.append(StructuredFact(i, i, "interfaces_detail",
                                         {"name": current_iface, "vlan": vlan_id}, True, line.strip()[:300]))
            continue
        m_desc = re.match(r"^\s*description\s+(.+)", line)
        if m_desc:
            facts.append(StructuredFact(i, i, "interfaces_detail",
                                         {"name": current_iface, "description": m_desc.group(1).strip()},
                                         True, line.strip()[:300]))
            continue
        m_shut = re.match(r"^\s*shutdown\s*$", line)
        if m_shut:
            facts.append(StructuredFact(i, i, "interfaces_detail",
                                         {"name": current_iface, "admin_state": "down"}, True, line.strip()[:300]))
            continue

    return facts


def _structured_extract_juniper(raw_text: str) -> List[StructuredFact]:
    facts: List[StructuredFact] = []

    for m in re.finditer(r"^set system syslog host (\S+) any (\S+)", raw_text, re.M):
        s, e = _line_span(raw_text, m.start(), m.end())
        facts.append(StructuredFact(s, e, "logging.syslog_servers", m.group(1), True, m.group(0).strip()[:300]))
        facts.append(StructuredFact(s, e, "logging.syslog_servers_detail",
                                     {"address": m.group(1), "severity": m.group(2)}, True, m.group(0).strip()[:300]))

    for m in re.finditer(r"^set system ntp server\s+(\S+)", raw_text, re.M):
        s, e = _line_span(raw_text, m.start(), m.end())
        facts.append(StructuredFact(s, e, "logging.ntp.servers", m.group(1), True, m.group(0).strip()[:300]))

    for m in re.finditer(r"^set vlans (\S+) vlan-id (\d+)", raw_text, re.M):
        s, e = _line_span(raw_text, m.start(), m.end())
        facts.append(StructuredFact(s, e, "vlans", {"name": m.group(1), "id": int(m.group(2))},
                                     True, m.group(0).strip()[:300]))

    for m in re.finditer(r"^set routing-options static route (\S+) next-hop (\S+)", raw_text, re.M):
        s, e = _line_span(raw_text, m.start(), m.end())
        facts.append(StructuredFact(s, e, "routing.static_routes",
                                     {"destination": m.group(1), "next_hop": m.group(2)},
                                     True, m.group(0).strip()[:300]))

    for m in re.finditer(r"^set protocols ospf area \S+ interface \S+", raw_text, re.M):
        s, e = _line_span(raw_text, m.start(), m.end())
        facts.append(StructuredFact(s, e, "routing.ospf", {"enabled": True}, False, m.group(0).strip()[:300]))

    for m in re.finditer(r"^set protocols bgp group \S+ peer-as (\d+)", raw_text, re.M):
        s, e = _line_span(raw_text, m.start(), m.end())
        facts.append(StructuredFact(s, e, "routing.bgp", {"enabled": True, "as_number": int(m.group(1))},
                                     False, m.group(0).strip()[:300]))

    return facts


def _structured_extract_fortios(raw_text: str) -> List[StructuredFact]:
    facts: List[StructuredFact] = []

    for m in re.finditer(
        r"^config system global\n(?:.*\n)*?\s*set admin-sport (\d+)\n(?:.*\n)*?^end",
        raw_text, re.M,
    ):
        s, e = _line_span(raw_text, m.start(), m.end())
        facts.append(StructuredFact(s, e, "management.http.port", int(m.group(1)), False, m.group(0).strip()[:300]))

    for m in re.finditer(r"^\s*set server\s+\"?([\d.]+)\"?", raw_text, re.M):
        s, e = _line_span(raw_text, m.start(), m.end())
        facts.append(StructuredFact(s, e, "logging.syslog_servers", m.group(1), True, m.group(0).strip()[:300]))

    return facts


def _structured_extract_panos(raw_text: str) -> List[StructuredFact]:
    facts: List[StructuredFact] = []
    for m in re.finditer(r"set network interface \S+ .*ip (\S+)", raw_text, re.M):
        s, e = _line_span(raw_text, m.start(), m.end())
        facts.append(StructuredFact(s, e, "interfaces_detail", {"ip_address": m.group(1)},
                                     True, m.group(0).strip()[:300]))
    return facts


_STRUCTURED_EXTRACTORS = {
    "Cisco": _structured_extract_cisco,
    "Juniper": _structured_extract_juniper,
    "Fortinet": _structured_extract_fortios,
    "Palo Alto Networks": _structured_extract_panos,
}


def set_or_append_dotted(model: SecurityBaselineModel, dotted_path: str, value, append: bool = False) -> bool:
    """Set (or append to) a dotted path like 'management.ssh.version' or
    'aaa.radius_servers' on the baseline model. Returns True if the field is
    a known typed field; False if it should go into extra_parameters instead
    (used by the AI pipeline for novel params, and by the deterministic
    structured extractors below for facts that don't fit the schema).

    The typed sub-models (SSHConfig, TelnetConfig, ...) set
    `validate_assignment=True`, so a value that doesn't match the declared
    type (e.g. the string "v2" landing on `management.ssh.version:
    Optional[int]`) raises ValidationError here instead of being silently
    stored. Treat that the same as an unknown field: park it in
    `extra_parameters` (visible, flagged) instead of letting a mistyped
    value corrupt a typed compliance fact the OPA engine will evaluate.

    `append=True` is for List[...] fields (e.g. `aaa.radius_servers`,
    `logging.syslog_servers_detail`, `vlans`) discovered incrementally from
    context blocks: pydantic's validate-on-assignment only fires on
    `setattr`, not on in-place `list.append()`, so this rebuilds the list
    (`current + [value]`) and reassigns it -- a malformed appended value
    still raises ValidationError and is safely quarantined the same way a
    malformed scalar is, instead of silently corrupting the list in place.
    """
    parts = dotted_path.split(".")
    obj = model
    try:
        for p in parts[:-1]:
            obj = getattr(obj, p)
        leaf = parts[-1]
        if append:
            current = getattr(obj, leaf)
            if not isinstance(current, list):
                raise AttributeError(f"{dotted_path} is not a list field")
            setattr(obj, leaf, current + [value])
        else:
            setattr(obj, leaf, value)
        return True
    except AttributeError:
        if append:
            model.extra_parameters.setdefault(dotted_path, [])
            if isinstance(model.extra_parameters[dotted_path], list):
                model.extra_parameters[dotted_path].append(value)
            else:
                model.extra_parameters[dotted_path] = [model.extra_parameters[dotted_path], value]
        else:
            model.extra_parameters[dotted_path] = value
        return False
    except ValidationError:
        if append:
            model.extra_parameters.setdefault(f"{dotted_path}_unvalidated", [])
            model.extra_parameters[f"{dotted_path}_unvalidated"].append(value)
        else:
            model.extra_parameters[dotted_path] = value
        return False


def _set_dotted(model: SecurityBaselineModel, dotted_path: str, value) -> bool:
    """Backwards-compatible scalar-set alias of `set_or_append_dotted` --
    used by the flat (regex, parameter, value_fn) Rule tuples above, which
    never target list fields."""
    return set_or_append_dotted(model, dotted_path, value, append=False)


def _group_unknown_blocks(raw_text: str, matched_line_numbers: set, max_blocks: int = 80) -> List[str]:
    """Group contiguous/near-contiguous unmatched, well-formed lines into
    context blocks for the AI/RAG pipeline, instead of handing it isolated
    single lines with no surrounding context (problem statement item 2/5).

    A block continues across a small gap (<=2 lines) so a nested stanza
    whose header line WAS matched by a flat rule (e.g. an Cisco
    "aaa authentication login default group radius local" line that's
    already deterministically parsed) doesn't fracture the still-unknown
    child lines that follow it into needless singletons, while a real
    gap (a fully separate, already-understood section) still starts a new
    block. Comment/blank lines are skipped for classification purposes but
    still included in a block's text when they fall inside it, preserving
    original formatting for the AI's context window.
    """
    lines = raw_text.splitlines()
    unknown_idx: List[int] = []
    for i, raw_line in enumerate(lines):
        line = raw_line.strip()
        if not line or line.startswith(("!", "#", "/*", "*")):
            continue
        if i in matched_line_numbers:
            continue
        unknown_idx.append(i)

    if not unknown_idx:
        return []

    blocks: List[Tuple[int, int]] = []
    block_start = unknown_idx[0]
    prev = unknown_idx[0]
    for idx in unknown_idx[1:]:
        if idx - prev <= 2:
            prev = idx
            continue
        blocks.append((block_start, prev))
        block_start = idx
        prev = idx
    blocks.append((block_start, prev))

    block_texts = []
    for start, end in blocks[:max_blocks]:
        block_texts.append("\n".join(lines[start:end + 1]).strip())
    return block_texts


def parse_config(vendor: str, raw_text: str, model_version: str = "parser-v1") -> SecurityBaselineModel:
    """Run the deterministic parser for a known vendor. Any line not touched
    by a rule (flat OR structured) is grouped with its surrounding context
    into a block and handed to the AI/RAG pipeline (see ai/normalize.py) for
    multi-fact interpretation -- never discarded.

    A malformed configuration never aborts the scan: every rule application
    and every line classification is individually isolated, so one bad
    section degrades coverage stats instead of raising.
    """
    baseline = SecurityBaselineModel(device={"vendor": vendor, "os": "unknown"})
    rules = VENDOR_RULES.get(vendor, [])
    stats = ParseStats()

    matched_line_numbers: set[int] = set()
    for pattern, param, value_fn in rules:
        try:
            matches = list(pattern.finditer(raw_text))
        except re.error as e:  # a broken rule pattern must not kill the scan
            stats.rule_errors.append(f"{param}: pattern error ({e})")
            continue
        for m in matches:
            try:
                value = value_fn(m)
                _set_dotted(baseline, param, value)
                baseline.provenance.append(
                    NormalizedParameter(
                        raw_command=m.group(0).strip()[:300],
                        normalized_parameter=param,
                        value=value,
                        confidence=1.0,
                        source="parser",
                        model_version=model_version,
                        human_validated=True,
                    )
                )
                start_line = raw_text.count("\n", 0, m.start())
                end_line = raw_text.count("\n", 0, m.end())
                matched_line_numbers.update(range(start_line, end_line + 1))
            except Exception as e:  # noqa: BLE001 - a single bad capture never fails the scan
                stats.rule_errors.append(f"{param}: {e.__class__.__name__} on match {m.group(0)[:80]!r}")

    # Structured (multi-field / list-appending) deterministic extraction --
    # RADIUS/TACACS servers, VLANs, ACLs, interfaces, routing, syslog/NTP/
    # SNMP server lists. Runs in the SAME pass as the flat rules above so
    # its matched lines are excluded from "unsupported" before AI ever sees
    # them (problem statement item 8: deterministic extraction first).
    structured_extractor = _STRUCTURED_EXTRACTORS.get(vendor)
    if structured_extractor:
        try:
            structured_facts = structured_extractor(raw_text)
        except Exception as e:  # noqa: BLE001 - a broken extractor must not kill the scan
            structured_facts = []
            stats.rule_errors.append(f"structured-extractor: {e.__class__.__name__}: {e}")
        for fact in structured_facts:
            try:
                set_or_append_dotted(baseline, fact.parameter, fact.value, append=fact.append)
                baseline.provenance.append(
                    NormalizedParameter(
                        raw_command=fact.raw,
                        normalized_parameter=fact.parameter,
                        value=fact.value,
                        confidence=1.0,
                        source="parser",
                        model_version=model_version,
                        human_validated=True,
                    )
                )
                matched_line_numbers.update(range(fact.start_line, fact.end_line + 1))
            except Exception as e:  # noqa: BLE001
                stats.rule_errors.append(f"{fact.parameter}: {e.__class__.__name__} applying structured fact")

    unknown_lines: List[str] = []
    for i, raw_line in enumerate(raw_text.splitlines()):
        line = raw_line.strip()
        if not line or line.startswith(("!", "#", "/*", "*")):
            continue
        stats.total_lines += 1
        if i in matched_line_numbers:
            stats.successful += 1
            continue
        if _looks_malformed(line):
            stats.malformed += 1
            stats.malformed_lines.append(line[:200])
            continue
        stats.unsupported += 1
        unknown_lines.append(line)

    # Collect unmatched, well-formed lines for the AI normalization stage,
    # grouped into context blocks (not isolated single lines) so the AI can
    # see relationships between related lines (problem statement item 2/5).
    # Malformed lines are deliberately excluded — they're not "unknown
    # syntax to interpret", they're broken syntax to flag for human review.
    # Nothing here is capped away and dropped: `max_blocks` in
    # `_group_unknown_blocks` limits how many blocks are sent per scan for
    # latency, and any lines beyond that cap are still preserved verbatim,
    # uncapped, in `_all_unknown_lines` for the coverage report / human
    # review queue -- see ai/normalize.py's zero-discard guarantee.
    baseline.extra_parameters["_unknown_blocks"] = _group_unknown_blocks(raw_text, matched_line_numbers)
    baseline.extra_parameters["_all_unknown_lines"] = unknown_lines
    baseline.extra_parameters["_parse_stats"] = stats.to_dict()

    return baseline