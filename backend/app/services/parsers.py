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
        # `version 17.9` / `version 15.2` etc -- the first line of an IOS/IOS-XE
        # running-config. This is the ONLY reliable in-band signal of the
        # device's OS/firmware version, so the LLM/AI normalization stage and
        # remediation template selection (remediation_templates.get_template)
        # can key off the device's *actual* release rather than assuming
        # every Cisco box is the same IOS-XE train.
        (re.compile(r"^version\s+([\w.()]+)\s*$", re.M), "device.version", lambda m: m.group(1)),
        (re.compile(r"^ip domain-name\s+(\S+)", re.M), "extra_parameters.domain_name", lambda m: m.group(1)),
        (re.compile(r"^ip ssh version\s+(\d)", re.M), "management.ssh.version", lambda m: int(m.group(1))),
        (re.compile(r"^ip ssh time-out\s+(\d+)", re.M), "management.ssh.idle_timeout", lambda m: int(m.group(1)) * 60),
        (re.compile(r"^ip ssh authentication-retries\s+(\d+)", re.M), "extra_parameters.ssh_auth_retries", lambda m: int(m.group(1))),
        (re.compile(r"^line vty.*\n(?:.*\n)*?\s*transport input (\S+)", re.M), "management.ssh.enabled",
         lambda m: "ssh" in m.group(1) and "telnet" not in m.group(1)),
        (re.compile(r"^line vty.*\n(?:.*\n)*?\s*transport input.*telnet", re.M), "management.telnet.enabled", lambda m: True),
        (re.compile(r"^line vty.*\n(?:.*\n)*?\s*exec-timeout\s+(\d+)\s+(\d+)", re.M), "extra_parameters.vty_exec_timeout_seconds",
         lambda m: int(m.group(1)) * 60 + int(m.group(2))),
        (re.compile(r"^no ip http server", re.M), "management.http.enabled", lambda m: False),
        (re.compile(r"^ip http server\b(?!.*secure)", re.M), "management.http.enabled", lambda m: True),
        (re.compile(r"^ip http secure-server", re.M), "management.http.https_only", lambda m: True),
        (re.compile(r"^logging (?:host|server) (\S+)", re.M), "logging.remote_syslog", lambda m: True),
        (re.compile(r"^logging trap (\S+)", re.M), "logging.log_level", lambda m: m.group(1)),
        (re.compile(r"^aaa new-model", re.M), "aaa.enabled", lambda m: True),
        (re.compile(r"^aaa authentication login default (\S+)", re.M), "aaa.authentication_method", lambda m: m.group(1)),
        (re.compile(r"^aaa accounting (?:exec|commands \d+) default.*group\s+\S+", re.M), "aaa.accounting_enabled", lambda m: True),
        (re.compile(r"^login block-for\s+\d+\s+attempts\s+\d+\s+within\s+\d+", re.M), "extra_parameters.login_brute_force_protection", lambda m: True),
        (re.compile(r"^snmp-server community (\S+)", re.M), "snmp.community_strings_default",
         lambda m: m.group(1).lower() in ("public", "private")),
        (re.compile(r"^snmp-server (?:host|user).*\bv3\b", re.M), "snmp.version", lambda m: "3"),
        (re.compile(r"^service password-encryption", re.M), "password_policy.encrypted_storage", lambda m: True),
        (re.compile(r"^enable secret", re.M), "extra_parameters.enable_secret_configured", lambda m: True),
        (re.compile(r"^banner (?:motd|login)", re.M), "management.banner_configured", lambda m: True),
        (re.compile(r"^ntp server\s+(\S+)", re.M), "logging.ntp_synced", lambda m: True),
        (re.compile(r"^ntp authenticate", re.M), "extra_parameters.ntp_authenticated", lambda m: True),
        (re.compile(r"^no cdp run", re.M), "extra_parameters.cdp_disabled", lambda m: True),
        (re.compile(r"^no ip source-route", re.M), "extra_parameters.source_routing_disabled", lambda m: True),
        (re.compile(r"^no ip proxy-arp", re.M), "extra_parameters.proxy_arp_disabled", lambda m: True),
        (re.compile(r"^no service pad", re.M), "extra_parameters.pad_service_disabled", lambda m: True),
        (re.compile(r"^ip ssh server algorithm encryption\s+(.+)", re.M), "crypto.ssh_key_exchange_algorithms",
         lambda m: [a.strip() for a in m.group(1).split()]),
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
        (re.compile(r"^set system ntp authentication-key", re.M), "extra_parameters.ntp_authenticated", lambda m: True),
        (re.compile(r"^set system login message", re.M), "management.banner_configured", lambda m: True),
        (re.compile(r"^set system login retry-options tries-before-disconnect\s+(\d+)", re.M),
         "extra_parameters.login_brute_force_protection", lambda m: True),
        (re.compile(r"^set system services ssh root-login deny", re.M), "extra_parameters.ssh_root_login_denied", lambda m: True),
        (re.compile(r"^delete system services ssh protocol-version v1|^set system services ssh protocol-version v2 only",
                     re.M), "management.ssh.version", lambda m: 2),
        (re.compile(r"^set system services ssh connection-limit\s+(\d+)", re.M),
         "extra_parameters.ssh_connection_limit", lambda m: int(m.group(1))),
        (re.compile(r"^set system syslog host \S+ structured-data", re.M), "extra_parameters.structured_syslog", lambda m: True),
        (re.compile(r"^set system accounting events (login|change-log|interactive-commands)", re.M), "aaa.accounting_enabled", lambda m: True),
        (re.compile(r"^set system radius-server", re.M), "extra_parameters.radius_configured", lambda m: True),
        (re.compile(r"^set system tacplus-server", re.M), "extra_parameters.tacacs_configured", lambda m: True),
        (re.compile(r"^set system services web-management https system-generated-certificate", re.M),
         "management.http.https_only", lambda m: True),
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
        # FortiOS full-configuration exports (`show full-configuration`) start
        # with a `#config-version=FGVM64-7.4.1-FW-build2464-...` header --
        # the one reliable in-band FortiOS firmware/build signal, so it's
        # captured for the same reason the Cisco `version` line is: so
        # normalization and remediation template selection know the real
        # device version instead of assuming a single "FortiOS" baseline.
        (re.compile(r"^#config-version=\S*?-(\d+\.\d+\.\d+)-", re.M), "device.version", lambda m: m.group(1)),
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
        (re.compile(r"set strong-crypto\s+enable", re.M), "crypto.weak_ciphers_disabled", lambda m: True),
        (re.compile(r"set admin-lockout-threshold\s+(\d+)", re.M), "extra_parameters.login_brute_force_protection", lambda m: True),
        (re.compile(r"set admin-lockout-duration\s+(\d+)", re.M), "extra_parameters.lockout_duration_seconds", lambda m: int(m.group(1))),
        (re.compile(r"set ssh-hostkey-algo\b|set ssh-kex-algo\b|set ssh-enc-algo\b", re.M), "extra_parameters.ssh_algorithms_hardened", lambda m: True),
        (re.compile(r"set fail-open\s+disable", re.M), "extra_parameters.ips_fail_open_disabled", lambda m: True),
        (re.compile(r"set two-factor\s+\S+", re.M), "extra_parameters.mfa_configured", lambda m: True),
        (re.compile(r"set fortitoken-cloud\s+enable|set two-factor\s+fortitoken", re.M), "extra_parameters.mfa_configured", lambda m: True),
        (re.compile(r"set alertemail\s+enable|set fds-license-expiring-days", re.M), "extra_parameters.alerting_configured", lambda m: True),
        (re.compile(r"set auto-update\s+enable|set schedule-update\s+enable", re.M), "extra_parameters.auto_updates_enabled", lambda m: True),
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
    # Cloud network devices (security groups / NSGs / firewall rules) are
    # JSON, not line-oriented CLI, so they have no regex Rule tuples here --
    # they're parsed structurally in _parse_cloud_firewall_rules below. The
    # empty list just documents that these are first-class vendors (see
    # SUPPORTED_VENDORS in vendor_detect.py), not an oversight.
    "AWS": [],
    "Azure": [],
    "GCP": [],
}

CLOUD_VENDORS = {"AWS", "Azure", "GCP"}

# Default OS family for each on-prem vendor's rule set (see remediation_
# templates.py, which keys CLI templates by (control_id, vendor, os_family)).
# Previously the parser always left baseline.device.os == "unknown" for
# every on-prem vendor and only device.version (e.g. "17.9") got captured,
# so remediation_service's os_family lookup never had a real OS family to
# match against -- it only ever worked by accident, via the
# _SINGLE_OS_FAMILY fallback in remediation_templates.get_template(), which
# silently breaks the moment a second OS family is registered for the same
# vendor. Setting the real family here makes the (control_id, vendor,
# os_family) lookup exact, so the CLI handed back always matches the
# device's actual syntax family -- not just "whichever one happened to be
# the only one registered".
VENDOR_OS_FAMILY = {
    "Cisco": "IOS-XE",
    "Juniper": "Junos",
    "Fortinet": "FortiOS",
    "Palo Alto Networks": "PAN-OS",
    "Arista": "EOS",
    "Aruba": "AOS-CX",
    "SONiC": "SONiC",
    "Sophos": "XGS",
}


def _open_to_internet(cidrs: List[str]) -> bool:
    return any(c.strip() in ("0.0.0.0/0", "::/0") for c in cidrs)


def _parse_cloud_firewall_rules(baseline: SecurityBaselineModel, vendor: str, raw_text: str) -> bool:
    """Structural parser for cloud network devices: AWS Security Groups
    (CloudFormation `AWS::EC2::SecurityGroup` or `describe-security-groups`
    JSON), Azure NSGs (ARM `Microsoft.Network/networkSecurityGroups` or the
    `az network nsg rule list` shape), and GCP firewall rules (Compute API
    `compute#firewall`, single object or `{"items": [...]}`).

    Every rule found is normalized into the same vendor-neutral
    FirewallPolicy the on-prem firewall parsers already populate (see
    class docstring in models/baseline.py) so compliance controls like
    "no rule allows 0.0.0.0/0" run identically across on-prem and cloud.
    Returns False (and leaves the baseline untouched) if raw_text isn't
    parseable JSON at all, so the caller can fall through to the normal
    unknown-line/AI path instead of silently producing nothing.
    """
    import json as _json

    try:
        doc = _json.loads(raw_text)
    except (ValueError, TypeError):
        return False

    def _add_policy(name, action, direction, protocol, ports, cidrs, raw_obj):
        policy = FirewallPolicy(
            name=name or "unnamed",
            action=(action or "allow").lower(),
            source_zone=direction,
            service=[p for p in ([protocol] if protocol else []) + (ports or []) if p] or None,
            source=cidrs or None,
            logging_enabled=None,
            enabled=True,
        )
        baseline.firewall_policies.append(policy)
        raw_snippet = _json.dumps(raw_obj, sort_keys=True)[:300]
        baseline.provenance.append(
            NormalizedParameter(
                raw_command=raw_snippet,
                normalized_parameter="firewall_policies",
                value=policy.model_dump(),
                confidence=1.0,
                source="parser",
                vendor=vendor,
                parser_version=PARSER_VERSION,
                human_validated=True,
            )
        )
        if _open_to_internet(cidrs or []):
            baseline.extra_parameters.setdefault("open_to_internet_rules", [])
            baseline.extra_parameters["open_to_internet_rules"].append(name or "unnamed")

    found_any = False

    if vendor == "AWS":
        # CloudFormation-style: {"Resources": {"LogicalId": {"Type": "AWS::EC2::SecurityGroup", "Properties": {...}}}}
        resources = doc.get("Resources") if isinstance(doc, dict) else None
        if isinstance(resources, dict):
            for logical_id, res in resources.items():
                if not isinstance(res, dict):
                    continue
                res_type = res.get("Type")
                props = res.get("Properties", {}) or {}
                if res_type == "AWS::EC2::SecurityGroup":
                    baseline.device.hostname = baseline.device.hostname or props.get("GroupName") or logical_id
                    for direction, key in (("ingress", "SecurityGroupIngress"), ("egress", "SecurityGroupEgress")):
                        for rule in props.get(key, []) or []:
                            cidrs = [rule[k] for k in ("CidrIp", "CidrIpv6") if rule.get(k)]
                            ports = []
                            if rule.get("FromPort") is not None:
                                to_port = rule.get("ToPort", rule.get("FromPort"))
                                ports = [f"{rule['FromPort']}-{to_port}" if to_port != rule["FromPort"] else str(rule["FromPort"])]
                            _add_policy(f"{logical_id}:{direction}", "allow", direction,
                                        rule.get("IpProtocol"), ports, cidrs, rule)
                            found_any = True
                elif res_type == "AWS::EC2::NetworkAcl":
                    baseline.device.hostname = baseline.device.hostname or logical_id
                # `AWS::EC2::NetworkAclEntry` resources reference their NACL via
                # NetworkAclId (usually a {"Ref": "..."} to the NACL resource
                # above) rather than nesting inside it, so they're handled as
                # their own top-level resources below rather than as children.
                elif res_type == "AWS::EC2::NetworkAclEntry":
                    nacl_ref = props.get("NetworkAclId")
                    nacl_id = nacl_ref.get("Ref") if isinstance(nacl_ref, dict) else nacl_ref
                    cidrs = [c for c in (props.get("CidrBlock"), props.get("Ipv6CidrBlock")) if c]
                    proto = props.get("Protocol")
                    port_range = props.get("PortRange") or {}
                    ports = []
                    if port_range.get("From") is not None:
                        to_p = port_range.get("To", port_range.get("From"))
                        ports = [f"{port_range['From']}-{to_p}" if to_p != port_range["From"] else str(port_range["From"])]
                    direction = "egress" if props.get("Egress") else "ingress"
                    _add_policy(f"{nacl_id or 'nacl'}:{direction}:{props.get('RuleNumber', logical_id)}",
                                props.get("RuleAction"), direction, proto, ports, cidrs, props)
                    found_any = True
        # `aws ec2 describe-security-groups` output: {"SecurityGroups": [...]}
        for sg in doc.get("SecurityGroups", []) if isinstance(doc, dict) else []:
            baseline.device.hostname = baseline.device.hostname or sg.get("GroupName") or sg.get("GroupId")
            for direction, key in (("ingress", "IpPermissions"), ("egress", "IpPermissionsEgress")):
                for perm in sg.get(key, []) or []:
                    cidrs = [r.get("CidrIp") for r in perm.get("IpRanges", []) or []]
                    cidrs += [r.get("CidrIpv6") for r in perm.get("Ipv6Ranges", []) or []]
                    cidrs = [c for c in cidrs if c]
                    from_p, to_p = perm.get("FromPort"), perm.get("ToPort")
                    ports = [f"{from_p}-{to_p}" if from_p != to_p else str(from_p)] if from_p is not None else []
                    _add_policy(f"{sg.get('GroupId', 'sg')}:{direction}", "allow", direction,
                                perm.get("IpProtocol"), ports, cidrs, perm)
                    found_any = True
        # `aws ec2 describe-network-acls` output: {"NetworkAcls": [...]}
        for nacl in doc.get("NetworkAcls", []) if isinstance(doc, dict) else []:
            nacl_id = nacl.get("NetworkAclId", "nacl")
            baseline.device.hostname = baseline.device.hostname or nacl_id
            for entry in nacl.get("Entries", []) or []:
                cidrs = [c for c in (entry.get("CidrBlock"), entry.get("Ipv6CidrBlock")) if c]
                port_range = entry.get("PortRange") or {}
                ports = []
                if port_range.get("From") is not None:
                    to_p = port_range.get("To", port_range.get("From"))
                    ports = [f"{port_range['From']}-{to_p}" if to_p != port_range["From"] else str(port_range["From"])]
                direction = "egress" if entry.get("Egress") else "ingress"
                _add_policy(f"{nacl_id}:{direction}:{entry.get('RuleNumber', 'rule')}",
                            entry.get("RuleAction"), direction, entry.get("Protocol"), ports, cidrs, entry)
                found_any = True
        # AWS Network Firewall rule groups (5-tuple stateful rules or
        # stateless rules with match attributes), either CloudFormation
        # `AWS::NetworkFirewall::RuleGroup` or `describe-rule-group` output.
        rule_group_props = None
        if isinstance(resources, dict):
            for res in resources.values():
                if isinstance(res, dict) and res.get("Type") == "AWS::NetworkFirewall::RuleGroup":
                    rule_group_props = ((res.get("Properties") or {}).get("RuleGroup") or {})
                    break
        if rule_group_props is None and isinstance(doc, dict) and "RuleGroup" in doc:
            rule_group_props = doc.get("RuleGroup") or {}
        if rule_group_props:
            rules_source = (rule_group_props.get("RulesSource") or {})
            for i, rule in enumerate(rules_source.get("StatefulRules", []) or []):
                header = rule.get("Header", {}) or {}
                cidrs = [c for c in (header.get("Source"),) if c and c != "ANY"]
                action = "allow" if str(rule.get("Action", "")).upper() == "PASS" else "deny"
                _add_policy(f"stateful-rule-{i}", action, "any", header.get("Protocol"),
                            [header.get("DestinationPort")] if header.get("DestinationPort") else [],
                            cidrs, rule)
                found_any = True
        # `aws network-firewall describe-rule-group` output nests the same
        # shape one level deeper: {"RuleGroup": {"RuleGroup": {...}}}
        elif isinstance(doc, dict) and isinstance(doc.get("RuleGroup"), dict) and isinstance(doc["RuleGroup"].get("RuleGroup"), dict):
            inner = doc["RuleGroup"]["RuleGroup"]
            rules_source = inner.get("RulesSource") or {}
            for i, rule in enumerate(rules_source.get("StatefulRules", []) or []):
                header = rule.get("Header", {}) or {}
                cidrs = [c for c in (header.get("Source"),) if c and c != "ANY"]
                action = "allow" if str(rule.get("Action", "")).upper() == "PASS" else "deny"
                _add_policy(f"stateful-rule-{i}", action, "any", header.get("Protocol"),
                            [header.get("DestinationPort")] if header.get("DestinationPort") else [],
                            cidrs, rule)
                found_any = True

    elif vendor == "Azure":
        # ARM template: {"resources": [{"type": "Microsoft.Network/networkSecurityGroups", "name": ..., "properties": {"securityRules": [...]}}]}
        for res in doc.get("resources", []) if isinstance(doc, dict) else []:
            if not isinstance(res, dict):
                continue
            res_type = (res.get("type") or "").lower()
            if "networksecuritygroups" in res_type:
                baseline.device.hostname = baseline.device.hostname or res.get("name")
                for rule in (res.get("properties", {}) or {}).get("securityRules", []) or []:
                    rp = rule.get("properties", rule)
                    cidrs = [rp.get("sourceAddressPrefix")] if rp.get("sourceAddressPrefix") else []
                    cidrs += rp.get("sourceAddressPrefixes") or []
                    ports = [rp.get("destinationPortRange")] if rp.get("destinationPortRange") else []
                    _add_policy(rule.get("name"), rp.get("access"), (rp.get("direction") or "").lower(),
                                rp.get("protocol"), ports, [c for c in cidrs if c], rule)
                    found_any = True
            elif "azurefirewalls" in res_type:
                # Azure Firewall: {"properties": {"networkRuleCollections": [
                #   {"name": ..., "properties": {"action": {"type": "Allow"|"Deny"},
                #    "rules": [{"name":..,"protocols":[..],"sourceAddresses":[..],
                #               "destinationAddresses":[..],"destinationPorts":[..]}]}}]}}
                baseline.device.hostname = baseline.device.hostname or res.get("name")
                fw_props = res.get("properties", {}) or {}
                for coll_key in ("networkRuleCollections", "applicationRuleCollections"):
                    for coll in fw_props.get(coll_key, []) or []:
                        coll_props = coll.get("properties", coll) or {}
                        action = ((coll_props.get("action") or {}).get("type") or "allow")
                        for rule in coll_props.get("rules", []) or []:
                            cidrs = rule.get("sourceAddresses") or []
                            dest = rule.get("destinationAddresses") or rule.get("targetFqdns") or []
                            ports = rule.get("destinationPorts") or []
                            protocols = rule.get("protocols") or []
                            proto = protocols[0] if protocols and isinstance(protocols[0], str) else (
                                protocols[0].get("protocolType") if protocols else None)
                            policy_name = rule.get("name") or coll.get("name")
                            svc = [p for p in ([proto] if proto else []) + list(ports) + list(dest) if p] or None
                            policy = FirewallPolicy(
                                name=policy_name or "unnamed", action=(action or "allow").lower(),
                                source_zone=coll_key.replace("RuleCollections", ""),
                                service=svc, source=cidrs or None, logging_enabled=None, enabled=True,
                            )
                            baseline.firewall_policies.append(policy)
                            baseline.provenance.append(NormalizedParameter(
                                raw_command=_json.dumps(rule, sort_keys=True)[:300],
                                normalized_parameter="firewall_policies", value=policy.model_dump(),
                                confidence=1.0, source="parser", vendor=vendor,
                                parser_version=PARSER_VERSION, human_validated=True,
                            ))
                            if _open_to_internet(cidrs):
                                baseline.extra_parameters.setdefault("open_to_internet_rules", [])
                                baseline.extra_parameters["open_to_internet_rules"].append(policy_name or "unnamed")
                            found_any = True
        # `az network nsg rule list` output: {"name": "...", "securityRules": [...]} or a bare list of rules
        rule_list = doc.get("securityRules") if isinstance(doc, dict) else (doc if isinstance(doc, list) else None)
        if isinstance(rule_list, list) and not found_any:
            if isinstance(doc, dict):
                baseline.device.hostname = baseline.device.hostname or doc.get("name")
            for rule in rule_list:
                if not isinstance(rule, dict):
                    continue
                cidrs = [rule.get("sourceAddressPrefix")] if rule.get("sourceAddressPrefix") else []
                ports = [rule.get("destinationPortRange")] if rule.get("destinationPortRange") else []
                _add_policy(rule.get("name"), rule.get("access"), (rule.get("direction") or "").lower(),
                            rule.get("protocol"), ports, [c for c in cidrs if c], rule)
                found_any = True
        # `az network firewall network-rule list` output: bare list/{"rules": [...]} of Azure Firewall rules
        af_rule_list = doc.get("rules") if isinstance(doc, dict) and not found_any else None
        if isinstance(af_rule_list, list):
            for rule in af_rule_list:
                if not isinstance(rule, dict):
                    continue
                cidrs = rule.get("sourceAddresses") or []
                ports = rule.get("destinationPorts") or []
                protocols = rule.get("protocols") or []
                proto = protocols[0] if protocols and isinstance(protocols[0], str) else None
                _add_policy(rule.get("name"), "allow", "any", proto, list(ports), cidrs, rule)
                found_any = True

    elif vendor == "GCP":
        # Single firewall resource, or a collection: {"items": [...]}
        items = doc.get("items") if isinstance(doc, dict) and "items" in doc else (
            [doc] if isinstance(doc, dict) and doc.get("kind") == "compute#firewall" else
            (doc if isinstance(doc, list) else [])
        )
        for fw in items:
            if not isinstance(fw, dict):
                continue
            baseline.device.hostname = baseline.device.hostname or fw.get("name")
            cidrs = fw.get("sourceRanges") or fw.get("destinationRanges") or []
            direction = (fw.get("direction") or "INGRESS").lower()
            rule_set = fw.get("allowed") or fw.get("denied") or []
            action = "allow" if fw.get("allowed") else "deny"
            if not rule_set:
                _add_policy(fw.get("name"), action, direction, None, [], cidrs, fw)
                found_any = True
            for entry in rule_set:
                ports = entry.get("ports") or []
                _add_policy(fw.get("name"), action, direction, entry.get("IPProtocol"), ports, cidrs, fw)
                found_any = True
        # Hierarchical Firewall Policy: {"kind": "compute#firewallPolicy",
        # "rules": [{"action": "allow"|"deny"|"goto_next", "direction": "INGRESS",
        #            "match": {"srcIpRanges": [..], "layer4Configs": [{"ipProtocol":..,"ports":[..]}]}}]}
        # or a list response: {"kind": "compute#firewallPolicyList", "items": [{...policy...}]}
        policies = []
        if isinstance(doc, dict) and doc.get("kind") == "compute#firewallPolicy":
            policies = [doc]
        elif isinstance(doc, dict) and doc.get("kind") == "compute#firewallPolicyList":
            policies = [p for p in doc.get("items", []) or [] if isinstance(p, dict)]
        for policy_doc in policies:
            baseline.device.hostname = baseline.device.hostname or policy_doc.get("displayName") or policy_doc.get("name")
            for rule in policy_doc.get("rules", []) or []:
                match = rule.get("match", {}) or {}
                cidrs = match.get("srcIpRanges") or match.get("destIpRanges") or []
                l4_configs = match.get("layer4Configs") or []
                if not l4_configs:
                    _add_policy(f"rule-{rule.get('priority', 'n')}", rule.get("action"),
                                (rule.get("direction") or "INGRESS").lower(), None, [], cidrs, rule)
                    found_any = True
                for l4 in l4_configs:
                    ports = l4.get("ports") or []
                    _add_policy(f"rule-{rule.get('priority', 'n')}", rule.get("action"),
                                (rule.get("direction") or "INGRESS").lower(), l4.get("ipProtocol"), ports, cidrs, rule)
                    found_any = True

    return found_any


def _set_dotted(model: SecurityBaselineModel, dotted_path: str, value) -> bool:
    """Set a dotted path like 'management.ssh.version' on the baseline model.
    Returns True if the field is a known typed field; False if it should go
    into extra_parameters instead (used by the AI pipeline for novel params).

    Falls back to extra_parameters on either AttributeError (walking into a
    plain dict, e.g. `extra_parameters.foo`) or ValueError (pydantic v2
    rejecting setattr on an undefined field on a typed model) -- catching
    only AttributeError silently let an undotted, non-existent field name
    crash the whole parse. The fallback key always has any leading
    'extra_parameters.' stripped so the value lands at
    baseline.extra_parameters['foo'], not the redundant/inconsistent
    baseline.extra_parameters['extra_parameters.foo'] (see the equivalent
    fix in services/pipeline.py::_apply_to_baseline for the AI-normalization
    path, which hit the same bug)."""
    parts = dotted_path.split(".")
    obj = model
    try:
        for p in parts[:-1]:
            obj = getattr(obj, p)
        setattr(obj, parts[-1], value)
        return True
    except (AttributeError, ValueError):
        key = dotted_path[len("extra_parameters."):] if dotted_path.startswith("extra_parameters.") else dotted_path
        model.extra_parameters[key] = value
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
    baseline = SecurityBaselineModel(device={"vendor": vendor, "os": VENDOR_OS_FAMILY.get(vendor, "unknown")})
    rules = VENDOR_RULES.get(vendor, [])
    raw_lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
    baseline.extra_parameters["_input_lines"] = raw_lines
    baseline.extra_parameters["_unknown_lines"] = []
    baseline.extra_parameters["_unknown_blocks"] = []

    if vendor in CLOUD_VENDORS:
        # Cloud devices ship as one JSON document, not line-oriented CLI --
        # a per-line regex pass over pretty-printed JSON would either match
        # nothing or match garbage. Parse it structurally instead; every
        # physical line of a *successfully* parsed document is considered
        # covered (its content lives in the FirewallPolicy entries + raw
        # provenance snippets above) so it doesn't get duplicated into
        # _unknown_lines and shipped wholesale to the AI/RAG pipeline.
        if _parse_cloud_firewall_rules(baseline, vendor, raw_text):
            baseline.device.os = vendor
            return baseline
        # Not a recognized cloud shape (or not valid JSON) -- fall through to
        # the normal unknown-line handling below so it still reaches the
        # AI/RAG pipeline rather than being silently dropped.

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

    # Character-offset index of every non-blank physical line in raw_text,
    # used below to find exactly which physical line(s) a regex match spans
    # -- see the note at the finditer loop for why this replaced using
    # match.group(0) directly.
    _line_spans: List[Tuple[int, int, str]] = []
    _pos = 0
    for _raw_line in raw_text.splitlines(True):
        _stripped_line = _raw_line.strip()
        _end = _pos + len(_raw_line)
        if _stripped_line:
            _line_spans.append((_pos, _end, _stripped_line))
        _pos = _end

    def _lines_covering(start: int, end: int) -> List[str]:
        return [text for (a, b, text) in _line_spans if a < end and b > start]

    for pattern, param, value_fn in rules:
        for match in pattern.finditer(raw_text):
            value = value_fn(match)
            _set_dotted(baseline, param, value)
            # BUG FIX: this used to record only `match.group(0).strip()` --
            # for rules whose regex captures a *prefix* of the line (e.g.
            # `^enable secret`, `^banner (?:motd|login)`,
            # `^aaa authentication login default (\S+)` which stops at the
            # first token), group(0) is shorter than the actual physical
            # line. That truncated string then never equals the real entry
            # in raw_lines, so:
            #   1. provenance/raw_command silently lost everything after the
            #      matched prefix (the secret hash, banner text, AAA method
            #      list, etc.) even though a rule "handled" the line.
            #   2. the final unknown-line loop below used to re-run
            #      `pattern.match(line)` against the FULL line as a
            #      fallback, which *did* match (regex .match() only
            #      anchors the start, not the end) -- so the full line was
            #      wrongly treated as "already covered" and silently
            #      dropped: not recorded with its full content, and never
            #      forwarded to the AI/RAG pipeline either. That was the
            #      root cause of most real config lines effectively being
            #      discarded by normalization.
            # Fix: resolve the match's character span back to the actual
            # physical line(s) it falls within and use THAT full text for
            # both provenance and matched-line tracking.
            covered = _lines_covering(match.start(), match.end())
            full_text = "\n".join(covered) if covered else match.group(0).strip()
            add_provenance(param, value, full_text)
            matched_lines.update(covered)
            if not covered:
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
        # NOTE: this used to also skip a line whenever `pattern.match(line)`
        # succeeded for ANY rule, as a "belt and suspenders" check. Because
        # `.match()` only anchors at the start of the string, that silently
        # treated every line sharing a rule's keyword prefix as "already
        # matched" even when no actual finditer() match had captured it
        # (e.g. a second, differently-valued `enable secret ...` line, or
        # any line starting with a matched rule's first few tokens) -- so it
        # discarded real lines instead of forwarding them to the AI/RAG
        # pipeline. matched_lines (built from actual regex matches, mapped
        # back to full physical lines above) is the accurate source of
        # truth; nothing else is needed here.
        if line in matched_lines:
            continue
        baseline.extra_parameters["_unknown_lines"].append(line)
    baseline.extra_parameters["_unknown_blocks"] = list(baseline.extra_parameters["_unknown_lines"])

    return baseline