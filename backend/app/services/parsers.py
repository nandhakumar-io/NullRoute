"""
Deterministic, rule-based parsers that turn known vendor syntax into
NormalizedParameter entries on the Security Baseline Model.

Design: each vendor module is a list of (regex, normalized_parameter, value_fn)
tuples. Any config line that matches NONE of the known patterns is collected
into `unknown_lines` and handed to the AI/RAG normalization pipeline
(ai/normalize.py) instead — the parser never guesses.
"""
from __future__ import annotations

import re
from typing import Callable, Dict, List, Optional, Tuple

from app.models.baseline import (ACLRule, AAAConfig, FirewallPolicy, NormalizedParameter, RadiusServer,
                                 SecurityBaselineModel, SyslogServer, TACACSServer, VLAN)

Rule = Tuple[re.Pattern, str, Callable[[re.Match], object]]


def set_or_append_dotted(model: SecurityBaselineModel, dotted_path: str, value, append: bool = False):
    """Set or append a value to a dotted path while tolerating nested model objects."""
    parts = dotted_path.split(".")
    obj = model
    for key in parts[:-1]:
        current = getattr(obj, key, None)
        if current is None:
            if key == "ntp":
                current = type("NTP", (), {})()
            else:
                current = type("Node", (), {})()
            setattr(obj, key, current)
        obj = current

    final_key = parts[-1]
    current = getattr(obj, final_key, None)
    if append:
        if current is None:
            current = []
            setattr(obj, final_key, current)
        if not isinstance(current, list):
            current = [current]
            setattr(obj, final_key, current)
        current.append(value)
        return
    setattr(obj, final_key, value)


def _rules_cisco() -> List[Rule]:
    return [
        (re.compile(r"^hostname\s+(\S+)", re.M), "device.hostname", lambda m: m.group(1)),
        (re.compile(r"^ip domain-name\s+(\S+)", re.M), "extra_parameters.domain_name", lambda m: m.group(1)),
        (re.compile(r"^ip ssh version\s+(\d)", re.M), "management.ssh.version", lambda m: int(m.group(1))),
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
        (re.compile(r"^set system host-name\s+(\S+)|^host-name\s+(\S+)", re.M), "device.hostname", lambda m: m.group(1) or m.group(2)),
        (re.compile(r"^set system services ssh\b|^ssh\b", re.M), "management.ssh.enabled", lambda m: True),
        (re.compile(r"^set system services ssh protocol-version v2|^protocol-version v2", re.M), "management.ssh.version", lambda m: 2),
        (re.compile(r"^set system login idle-time (\d+)", re.M), "management.ssh.idle_timeout", lambda m: int(m.group(1)) * 60),
        (re.compile(r"^set system services telnet", re.M), "management.telnet.enabled", lambda m: True),
        (re.compile(r"^set system services web-management http\b(?!s)", re.M), "management.http.enabled", lambda m: True),
        (re.compile(r"^set system services web-management https", re.M), "management.http.https_only", lambda m: True),
        (re.compile(r"^set system syslog host (\S+)", re.M), "logging.remote_syslog", lambda m: True),
        (re.compile(r"^set system login user .* authentication", re.M), "aaa.local_fallback", lambda m: True),
        (re.compile(r"^set system root-authentication plain-text-password", re.M), "password_policy.encrypted_storage", lambda m: False),
        (re.compile(r"^set system root-authentication encrypted-password|^encrypted-password\s+(\S+)", re.M), "password_policy.encrypted_storage", lambda m: True),
        (re.compile(r"^set snmp community (\S+)", re.M), "snmp.community_strings_default",
         lambda m: m.group(1).strip('"').lower() in ("public", "private")),
        (re.compile(r"^set system ntp server\s+(\S+)", re.M), "logging.ntp_synced", lambda m: True),
        (re.compile(r"^set system login message", re.M), "management.banner_configured", lambda m: True),
        # Flattened JSON/XML rules to prevent AI hallucination
        (re.compile(r"^name\s+(?!admin|any|messages|\*|authorization|interactive-commands|public)(ge|xe|et|-|mgmt|PROXMOX|STUDENT|0)[^\s]*", re.I), "interfaces.name", lambda m: m.group(0).split()[-1]),
        (re.compile(r"^port-mode\s+access", re.M), "interfaces.port_security_enabled", lambda m: True),
        (re.compile(r"^class\s+super-user", re.M), "aaa.enabled", lambda m: True),
        (re.compile(r"^uid\s+\d+", re.M), "aaa.enabled", lambda m: True),
        (re.compile(r"^(name)\s+(admin|messages|\*|any|public|authorization|interactive-commands|\d+)", re.I), "extra_parameters.unknown_evidence", lambda m: True),
        (re.compile(r"^(members)\s+\S+", re.I), "extra_parameters.unknown_evidence", lambda m: True),
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


def _rules_aruba() -> List[Rule]:
    return [
        (re.compile(r"^hostname\s+(\S+)", re.M), "device.hostname", lambda m: m.group(1)),
        (re.compile(r"^ssh server$", re.M), "management.ssh.enabled", lambda m: True),
        (re.compile(r"^ssh session-timeout\s+(\d+)", re.M), "management.ssh.idle_timeout", lambda m: int(m.group(1)) * 60),
        (re.compile(r"^no telnet-server$", re.M), "management.telnet.enabled", lambda m: False),
        (re.compile(r"^web-management\s+https$", re.M), "management.http.https_only", lambda m: True),
        (re.compile(r"^logging\s+(\S+)", re.M), "logging.remote_syslog", lambda m: True),
        (re.compile(r"^ntp server\s+(\S+)", re.M), "logging.ntp_synced", lambda m: True),
        (re.compile(r"^aaa authentication login default\s+.*", re.M), "aaa.enabled", lambda m: True),
        (re.compile(r"^radius-server host\s+(\S+)", re.M), "aaa.enabled", lambda m: True),
        (re.compile(r"^snmp-server community\s+\S+\s+\S+", re.M), "snmp.enabled", lambda m: True),
        (re.compile(r"^password complexity enable$", re.M), "password_policy.complexity_required", lambda m: True),
        (re.compile(r"^password minimum-length\s+(\d+)", re.M), "password_policy.min_length", lambda m: int(m.group(1))),
        (re.compile(r"^banner\s+motd\b", re.M), "management.banner_configured", lambda m: True),
    ]


def _rules_sophos() -> List[Rule]:
    return [
        (re.compile(r"^set hostname\s+(\S+)", re.M), "device.hostname", lambda m: m.group(1)),
        (re.compile(r"^set device-access-profile name\s+\S+\s+https\s+enable$", re.M), "management.http.https_only", lambda m: True),
        (re.compile(r"^set device-access-profile name\s+\S+\s+telnet\s+disable$", re.M), "management.telnet.enabled", lambda m: False),
        (re.compile(r"^set device-access-profile name\s+\S+\s+ssh\s+enable$", re.M), "management.ssh.enabled", lambda m: True),
        (re.compile(r"^set ssh-idle-timeout\s+(\d+)", re.M), "management.ssh.idle_timeout", lambda m: int(m.group(1)) * 60),
        (re.compile(r"^set password-complexity\s+enable$", re.M), "password_policy.complexity_required", lambda m: True),
        (re.compile(r"^set password-minimum-length\s+(\d+)", re.M), "password_policy.min_length", lambda m: int(m.group(1))),
        (re.compile(r"^set log-server\s+(\S+)", re.M), "logging.remote_syslog", lambda m: True),
        (re.compile(r"^set ntp-server\s+(\S+)", re.M), "logging.ntp_synced", lambda m: True),
        (re.compile(r"^set snmp-agent\s+enable$", re.M), "snmp.enabled", lambda m: True),
        (re.compile(r"^set admin-authentication-method\s+(\S+)", re.M), "aaa.authentication_method", lambda m: m.group(1)),
        (re.compile(r"^set radius-server ip\s+(\S+)", re.M), "aaa.enabled", lambda m: True),
        (re.compile(r"^set login-disclaimer\s+enable$", re.M), "management.banner_configured", lambda m: True),
    ]


VENDOR_RULES = {
    "Cisco": _rules_cisco(),
    "Juniper": _rules_juniper(),
    "Fortinet": _rules_fortios(),
    "Palo Alto Networks": _rules_panos(),
    "Arista": _rules_arista(),
    "Aruba": _rules_aruba(),
    "SONiC": _rules_sonic(),
    "Sophos": _rules_sophos(),
}


def _set_dotted(model: SecurityBaselineModel, dotted_path: str, value) -> bool:
    """Set a dotted path like 'management.ssh.version' on the baseline model.
    Returns True if the field is a known typed field; False if it should go
    into extra_parameters instead (used by the AI pipeline for novel params)."""
    parts = dotted_path.split(".")
    obj = model
    try:
        for p in parts[:-1]:
            obj = getattr(obj, p)
        setattr(obj, parts[-1], value)
        return True
    except AttributeError:
        model.extra_parameters[dotted_path] = value
        return False


def _record_match(baseline: SecurityBaselineModel, pattern, param: str, value, raw_text: str):
    _set_dotted(baseline, param, value)
    baseline.provenance.append(
        NormalizedParameter(
            raw_command=raw_text.strip()[:300],
            normalized_parameter=param,
            value=value,
            confidence=1.0,
            source="parser",
            model_version="parser-v1",
            human_validated=True,
        )
    )


PARSER_VERSION = "parser-v1"


def parse_config(vendor: str, raw_text: str, model_version: str = "parser-v1") -> SecurityBaselineModel:
    """Run the deterministic parser for a known vendor. Any line not touched
    by a rule is collected as an 'unknown' candidate for the AI/RAG pipeline
    (see ai/normalize.py) and, if confidence stays low, the Training Center.
    """
    baseline = SecurityBaselineModel(device={"vendor": vendor, "os": "unknown"})
    rules = VENDOR_RULES.get(vendor, [])
    raw_lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
    baseline.extra_parameters["_input_lines"] = raw_lines
    baseline.extra_parameters["_unknown_lines"] = []
    baseline.extra_parameters["_unknown_blocks"] = []

    matched_lines = set()

    # Best-effort raw-line -> 1-based source line number lookup for
    # provenance (spec section 9). Duplicate lines resolve to their first
    # occurrence, which is an accepted approximation for evidentiary purposes
    # — exact per-match offsets would require switching every regex to
    # line-by-line matching, which most vendor rules above are not written
    # for (several intentionally match multi-line spans).
    _line_number_index: Dict[str, int] = {}
    for _i, _l in enumerate(raw_text.splitlines(), start=1):
        _stripped = _l.strip()
        if _stripped and _stripped not in _line_number_index:
            _line_number_index[_stripped] = _i

    def _line_number(raw: str) -> Optional[int]:
        first_line = raw.strip().splitlines()[0].strip() if raw.strip() else ""
        return _line_number_index.get(first_line)

    def add_provenance(param: str, value: object, raw: str):
        baseline.provenance.append(
            NormalizedParameter(
                raw_command=raw[:300],
                normalized_parameter=param,
                value=value,
                confidence=1.0,
                source="parser",
                vendor=vendor,
                line_number=_line_number(raw),
                parser_version=PARSER_VERSION,
                model_version=model_version,
                human_validated=True,
            )
        )

    for pattern, param, value_fn in rules:
        for match in pattern.finditer(raw_text):
            value = value_fn(match)
            _set_dotted(baseline, param, value)
            add_provenance(param, value, match.group(0).strip())
            matched_lines.add(match.group(0).strip())

    if vendor == "Cisco":
        lines = raw_text.splitlines()
        idx = 0
        while idx < len(lines):
            line = lines[idx].strip()
            if line.startswith("radius server "):
                server_name = line.split()[2]
                address = None
                auth_port = None
                acct_port = None
                j = idx + 1
                while j < len(lines):
                    next_line = lines[j].strip()
                    if not next_line or next_line.startswith("!"):
                        j += 1
                        continue
                    if next_line.startswith("address ipv4 "):
                        m = re.search(r"address ipv4\s+(\S+)\s+auth-port\s+(\d+)\s+acct-port\s+(\d+)", next_line)
                        if m:
                            address = m.group(1)
                            auth_port = int(m.group(2))
                            acct_port = int(m.group(3))
                        break
                    if next_line.startswith("radius server ") or next_line.startswith("ip ") or next_line.startswith("aaa ") or next_line.startswith("logging "):
                        break
                    j += 1
                if address:
                    server = RadiusServer(address=address, auth_port=auth_port, acct_port=acct_port)
                    baseline.aaa.radius_servers.append(server)
                    add_provenance("aaa.radius_servers", server.model_dump(), line + "\n" + (
                        next((lines[k].strip() for k in range(idx + 1, len(lines)) if lines[k].strip().startswith("address ipv4 ")), "")
                    ))
                    matched_lines.add(line)
                    for k in range(idx + 1, len(lines)):
                        if lines[k].strip().startswith("address ipv4 "):
                            matched_lines.add(lines[k].strip())
                            break
                idx += 1
                continue
            if line.startswith("router ospf "):
                m = re.match(r"router ospf\s+(\d+)", line)
                if m:
                    baseline.routing.ospf.enabled = True
                    baseline.routing.ospf.process_id = int(m.group(1))
                    add_provenance("routing.ospf.process_id", int(m.group(1)), line)
                    matched_lines.add(line)
            if line.startswith("interface "):
                iface_name = line.split()[1]
                j = idx + 1
                while j < len(lines):
                    next_line = lines[j].strip()
                    if not next_line or next_line.startswith("!"):
                        break
                    if next_line.startswith("ip access-group "):
                        m = re.match(r"ip access-group\s+(\S+)\s+(\S+)", next_line)
                        if m:
                            acl = ACLRule(name=m.group(1), direction=m.group(2), action="permit")
                            baseline.acls.append(acl)
                            add_provenance("acls", acl.model_dump(), line + "\n" + next_line)
                            matched_lines.add(line)
                            matched_lines.add(next_line)
                        break
                    if next_line.startswith("switchport access vlan "):
                        m = re.match(r"switchport access vlan\s+(\d+)", next_line)
                        if m:
                            vlan = VLAN(id=int(m.group(1)), name=None)
                            baseline.vlans.append(vlan)
                            add_provenance("vlans", vlan.model_dump(), line + "\n" + next_line)
                            matched_lines.add(line)
                            matched_lines.add(next_line)
                        break
                    j += 1
            if line.startswith("logging host "):
                m = re.match(r"logging host\s+(\S+)", line)
                if m:
                    item = SyslogServer(address=m.group(1), severity=None)
                    baseline.logging.syslog_servers = baseline.logging.syslog_servers or []
                    baseline.logging.syslog_servers.append(m.group(1))
                    baseline.logging.syslog_servers_detail.append(item)
                    add_provenance("logging.syslog_servers_detail", item.model_dump(), line)
                    matched_lines.add(line)
            if line.startswith("ntp server "):
                m = re.match(r"ntp server\s+(\S+)", line)
                if m:
                    baseline.logging.ntp.servers.append(m.group(1))
                    add_provenance("logging.ntp.servers", m.group(1), line)
                    matched_lines.add(line)
            if line.startswith("vlan ") and "name" in " ".join(lines[idx:idx+3]):
                m = re.match(r"vlan\s+(\d+)", line)
                if m and idx + 1 < len(lines):
                    name_line = lines[idx + 1].strip()
                    name_match = re.match(r"name\s+(\S+)", name_line)
                    if name_match:
                        vlan = VLAN(id=int(m.group(1)), name=name_match.group(1))
                        baseline.vlans.append(vlan)
                        add_provenance("vlans", vlan.model_dump(), line + "\n" + name_line)
                        matched_lines.add(line)
                        matched_lines.add(name_line)
            idx += 1

    elif vendor == "Juniper":
        for line in raw_lines:
            if line.startswith("set vlans "):
                m = re.match(r"set vlans\s+(\S+)\s+vlan-id\s+(\d+)", line)
                if m:
                    vlan = VLAN(id=int(m.group(2)), name=m.group(1))
                    baseline.vlans.append(vlan)
                    add_provenance("vlans", vlan.model_dump(), line)
                    matched_lines.add(line)
            if line.startswith("set system syslog host "):
                m = re.match(r"set system syslog host\s+(\S+)\s+\S+\s+(\S+)", line)
                if m:
                    item = SyslogServer(address=m.group(1), severity=m.group(2))
                    baseline.logging.syslog_servers = baseline.logging.syslog_servers or []
                    baseline.logging.syslog_servers.append(m.group(1))
                    baseline.logging.syslog_servers_detail.append(item)
                    add_provenance("logging.syslog_servers_detail", item.model_dump(), line)
                    matched_lines.add(line)
            if line.startswith("set system ntp server "):
                m = re.match(r"set system ntp server\s+(\S+)", line)
                if m:
                    baseline.logging.ntp.servers.append(m.group(1))
                    add_provenance("logging.ntp.servers", m.group(1), line)
                    matched_lines.add(line)

    elif vendor == "Fortinet":
        for line in raw_lines:
            if line.startswith("set admin-sport "):
                m = re.match(r"set admin-sport\s+(\d+)", line)
                if m:
                    baseline.management.http.port = int(m.group(1))
                    add_provenance("management.http.port", int(m.group(1)), line)
                    matched_lines.add(line)
            if line.startswith("set server "):
                m = re.match(r"set server\s+\"?([\d.]+)\"?", line)
                if m:
                    baseline.logging.syslog_servers = baseline.logging.syslog_servers or []
                    baseline.logging.syslog_servers.append(m.group(1))
                    item = SyslogServer(address=m.group(1))
                    baseline.logging.syslog_servers_detail.append(item)
                    add_provenance("logging.syslog_servers_detail", item.model_dump(), line)
                    matched_lines.add(line)

        # `config firewall policy` / `edit <id>` ... `next` blocks. These are
        # stateful zone/service rules, not ACLs — kept in firewall_policies
        # (see models/baseline.py FirewallPolicy) so zone-based compliance
        # controls (e.g. "no any/any/allow") can be evaluated without the
        # compliance layer needing to know FortiOS syntax.
        in_fw_policy_block = False
        current_edit_lines: List[str] = []
        for line in raw_lines:
            if line.startswith("config firewall policy"):
                in_fw_policy_block = True
                matched_lines.add(line)
                continue
            if not in_fw_policy_block:
                continue
            if line == "end":
                in_fw_policy_block = False
                continue
            if line.startswith("edit "):
                current_edit_lines = [line]
                matched_lines.add(line)
                continue
            if line == "next":
                if current_edit_lines:
                    block_text = "\n".join(current_edit_lines)

                    def _get(field_re):
                        mm = re.search(field_re, block_text)
                        return mm.group(1) if mm else None

                    def _get_list(field_re):
                        mm = re.search(field_re, block_text)
                        return re.findall(r'"([^"]+)"', mm.group(0)) if mm else None

                    edit_id = re.match(r"edit\s+(\S+)", current_edit_lines[0])
                    policy = FirewallPolicy(
                        name=_get(r'set name\s+"([^"]+)"') or (edit_id.group(1) if edit_id else "unnamed"),
                        action=_get(r"set action\s+(\S+)") or "deny",  # FortiOS default is implicit deny
                        source_zone=_get(r'set srcintf\s+"([^"]+)"'),
                        destination_zone=_get(r'set dstintf\s+"([^"]+)"'),
                        service=_get_list(r"set service\s+(.+)"),
                        logging_enabled=("set logtraffic" in block_text) or None,
                        enabled=("set status disable" not in block_text),
                    )
                    baseline.firewall_policies.append(policy)
                    add_provenance("firewall_policies", policy.model_dump(), block_text)
                    matched_lines.update(current_edit_lines)
                matched_lines.add(line)
                current_edit_lines = []
                continue
            current_edit_lines.append(line)

    elif vendor == "Palo Alto Networks":
        # `set rulebase security rules <name> ...` — PAN-OS's `set`-format
        # config repeats the rule name on every line for that rule, so group
        # by rule name first rather than trying to match one line at a time.
        rule_lines: Dict[str, List[str]] = {}
        for line in raw_lines:
            m = re.match(r"set rulebase security rules\s+(\S+)\s+(.*)", line)
            if m:
                rule_lines.setdefault(m.group(1), []).append(m.group(2))
                matched_lines.add(line)
        for name, fields in rule_lines.items():
            block_text = " ".join(fields)

            def _pf(field_re, text=block_text):
                mm = re.search(field_re, text)
                return mm.group(1) if mm else None

            def _pf_list(field_re, text=block_text):
                mm = re.search(field_re, text)
                return mm.group(1).split() if mm else None

            policy = FirewallPolicy(
                name=name,
                action=_pf(r"\baction\s+(\S+)") or "deny",
                source_zone=_pf(r"\bfrom\s+(\S+)"),
                destination_zone=_pf(r"\bto\s+(\S+)"),
                service=_pf_list(r"\bservice\s+((?:\S+\s*)+?)(?:\s+(?:action|application|log-end)\b|$)"),
                application=_pf_list(r"\bapplication\s+((?:\S+\s*)+?)(?:\s+(?:action|service|log-end)\b|$)"),
                logging_enabled=("log-end yes" in block_text) or None,
                enabled=True,
            )
            baseline.firewall_policies.append(policy)
            add_provenance("firewall_policies", policy.model_dump(), f"set rulebase security rules {name} ...")

    for line in raw_lines:
        if line in matched_lines or any(pattern.match(line) for pattern, _, _ in rules):
            continue
        baseline.extra_parameters["_unknown_lines"].append(line)
    baseline.extra_parameters["_unknown_blocks"] = list(baseline.extra_parameters["_unknown_lines"])

    return baseline