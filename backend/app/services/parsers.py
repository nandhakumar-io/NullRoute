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
from typing import Callable, List, Tuple

from app.models.baseline import NormalizedParameter, SecurityBaselineModel

Rule = Tuple[re.Pattern, str, Callable[[re.Match], object]]


def _rules_cisco() -> List[Rule]:
    return [
        (re.compile(r"^hostname\s+(\S+)", re.M), "device.hostname", lambda m: m.group(1)),
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
        (re.compile(r"^set system host-name\s+(\S+)", re.M), "device.hostname", lambda m: m.group(1)),
        (re.compile(r"^set system services ssh\b", re.M), "management.ssh.enabled", lambda m: True),
        (re.compile(r"^set system services ssh protocol-version v2", re.M), "management.ssh.version", lambda m: 2),
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


def parse_config(vendor: str, raw_text: str, model_version: str = "parser-v1") -> SecurityBaselineModel:
    """Run the deterministic parser for a known vendor. Any line not touched
    by a rule is collected as an 'unknown' candidate for the AI/RAG pipeline
    (see ai/normalize.py) and, if confidence stays low, the Training Center.
    """
    baseline = SecurityBaselineModel(device={"vendor": vendor, "os": "unknown"})
    rules = VENDOR_RULES.get(vendor, [])

    matched_spans = set()
    for pattern, param, value_fn in rules:
        for m in pattern.finditer(raw_text):
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
            matched_spans.add((m.start(), m.end()))

    # Collect unmatched, non-trivial lines for the AI normalization stage.
    baseline.extra_parameters["_unknown_lines"] = [
        line.strip()
        for line in raw_text.splitlines()
        if line.strip() and not line.strip().startswith(("!", "#", "/*", "*"))
        and not any(pattern.match(line.strip()) for pattern, _, _ in rules)
    ][:200]  # cap for demo/performance

    return baseline
