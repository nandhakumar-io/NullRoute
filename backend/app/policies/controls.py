"""
Normalized, framework-independent control catalog.

Each control targets a dotted path on the flattened Security Baseline Model
(see SecurityBaselineModel.flatten()) so the SAME control works for every
vendor once that vendor's config has been normalized. This is what makes the
compliance engine vendor-agnostic per the problem statement.

`operator` + `expected` are evaluated deterministically in
services/compliance.py (mirrored by policies/*.rego for the OPA path) —
the AI is never involved at this stage.
"""
from dataclasses import dataclass, field
from typing import Any, List, Optional


@dataclass
class Control:
    control_id: str
    framework: str
    title: str
    parameter: str
    operator: str  # eq, ne, gte, lte, in, exists, not_true
    expected: Any
    severity: str  # CRITICAL/HIGH/MEDIUM/LOW
    remediation_template: str  # {vendor} placeholder resolved per-vendor


CONTROLS: List[Control] = [
    Control("CIS-SSH-001", "CIS", "SSH protocol version must be 2",
            "management.ssh.version", "eq", 2, "HIGH",
            "Configure the device to use SSH protocol version 2 only."),
    Control("CIS-TELNET-001", "CIS", "Telnet must be disabled for management access",
            "management.telnet.enabled", "eq", False, "CRITICAL",
            "Disable the Telnet management service; use SSH exclusively."),
    Control("CIS-HTTP-001", "CIS", "Unencrypted HTTP management interface must be disabled",
            "management.http.enabled", "eq", False, "HIGH",
            "Disable plaintext HTTP management access; use HTTPS only."),
    Control("CIS-HTTP-002", "CIS", "HTTPS must be enforced for web management",
            "management.http.https_only", "eq", True, "MEDIUM",
            "Enable HTTPS-only enforcement for the web management interface."),
    Control("CIS-SSH-002", "CIS", "SSH idle session timeout must not exceed 600 seconds",
            "management.ssh.idle_timeout", "lte", 600, "MEDIUM",
            "Set the SSH/administrative idle session timeout to 600 seconds or less."),
    Control("CIS-LOG-001", "CIS", "Remote syslog logging must be enabled",
            "logging.remote_syslog", "eq", True, "HIGH",
            "Configure a remote syslog server and enable logging forwarding."),
    Control("CIS-AAA-001", "CIS", "Centralized AAA authentication must be enabled",
            "aaa.enabled", "eq", True, "HIGH",
            "Enable AAA (new-model / equivalent) and configure a centralized authentication method."),
    Control("CIS-SNMP-001", "CIS", "Default SNMP community strings must not be used",
            "snmp.community_strings_default", "eq", False, "CRITICAL",
            "Change default SNMP community strings ('public'/'private') to unique, strong values, or migrate to SNMPv3."),
    Control("CIS-PWD-001", "CIS", "Password/secret storage must be encrypted",
            "password_policy.encrypted_storage", "eq", True, "HIGH",
            "Enable password encryption service so secrets are never stored in plaintext."),
    Control("CIS-BANNER-001", "CIS", "A legal/warning banner must be configured",
            "management.banner_configured", "eq", True, "LOW",
            "Configure a login/MOTD banner with an appropriate legal warning notice."),
    Control("NIST-AC-17", "NIST-800-53", "Remote access must use SSHv2 (AC-17 Remote Access)",
            "management.ssh.version", "eq", 2, "HIGH",
            "Enforce SSH protocol version 2 for all remote administrative access."),
    Control("NIST-AU-3", "NIST-800-53", "Audit records must be sent to a remote log host (AU-3)",
            "logging.remote_syslog", "eq", True, "HIGH",
            "Forward audit/system logs to a centralized, remote syslog collector."),
    Control("NIST-IA-5", "NIST-800-53", "Authenticator management: no default SNMP secrets (IA-5)",
            "snmp.community_strings_default", "eq", False, "CRITICAL",
            "Replace default SNMP community strings; prefer SNMPv3 with authPriv."),
    Control("STIG-NET-001", "DISA-STIG", "The network device must not have Telnet enabled",
            "management.telnet.enabled", "eq", False, "CRITICAL",
            "Disable the Telnet service; STIG requires encrypted management protocols only."),
    Control("STIG-NET-002", "DISA-STIG", "SSH idle timeout must be configured (<= 600s)",
            "management.ssh.idle_timeout", "lte", 600, "MEDIUM",
            "Configure SSH/exec idle timeout to 600 seconds or less per STIG guidance."),
    Control("ISO27001-A9-1", "ISO-27001", "Access control: management access must be authenticated centrally (A.9)",
            "aaa.enabled", "eq", True, "HIGH",
            "Implement centralized authentication (AAA/TACACS+/RADIUS) for all administrative access."),
    Control("ISO27001-A12-4", "ISO-27001", "Logging and monitoring must be enabled (A.12.4)",
            "logging.remote_syslog", "eq", True, "HIGH",
            "Enable and centralize system event logging as required by A.12.4."),
]


def controls_for_framework(framework: Optional[str]) -> List[Control]:
    if not framework or framework.upper() == "ALL":
        return CONTROLS
    return [c for c in CONTROLS if c.framework.upper() == framework.upper()]
