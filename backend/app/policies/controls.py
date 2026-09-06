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
    domain: str = "management"  # routes the control to a policies/security/*.rego file
    evidence_requirement: str = ""  # what raw evidence must exist for this to be a valid PASS, not just a default


# Adding a control (CIS-25, CIS-26, ...) is a data-only change: append a
# Control() entry with an existing `domain` (or add a matching
# policies/security/<domain>.rego file for a brand-new domain) and mirror it
# in policies/common/controls.rego. No evaluation logic anywhere — Python or
# Rego — needs to change; services/compliance.py, policies/common/evaluate.rego
# and every policies/frameworks/*.rego file just iterate whatever is here.
CONTROLS: List[Control] = [
    Control("CIS-SSH-001", "CIS", "SSH protocol version must be 2",
            "management.ssh.version", "eq", 2, "HIGH",
            "Configure the device to use SSH protocol version 2 only.",
            "management", "A management/SSH stanza declaring protocol version 2 (e.g. 'ip ssh version 2')."),
    Control("CIS-TELNET-001", "CIS", "Telnet must be disabled for management access",
            "management.telnet.enabled", "eq", False, "CRITICAL",
            "Disable the Telnet management service; use SSH exclusively.",
            "management", "VTY/management-line transport configuration showing telnet excluded or explicitly disabled."),
    Control("CIS-HTTP-001", "CIS", "Unencrypted HTTP management interface must be disabled",
            "management.http.enabled", "eq", False, "HIGH",
            "Disable plaintext HTTP management access; use HTTPS only.",
            "management", "Explicit directive disabling the plaintext HTTP admin service."),
    Control("CIS-HTTP-002", "CIS", "HTTPS must be enforced for web management",
            "management.http.https_only", "eq", True, "MEDIUM",
            "Enable HTTPS-only enforcement for the web management interface.",
            "management", "Directive enabling the HTTPS/secure web-management service."),
    Control("CIS-SSH-002", "CIS", "SSH idle session timeout must not exceed 600 seconds",
            "management.ssh.idle_timeout", "lte", 600, "MEDIUM",
            "Set the SSH/administrative idle session timeout to 600 seconds or less.",
            "management", "An explicit idle/exec-timeout value on the management or VTY line."),
    Control("CIS-SSH-003", "CIS", "SSH management service must not run on a non-default port without justification",
            "management.ssh.port", "exists", None, "LOW",
            "Confirm the configured SSH admin port is intentional and documented.",
            "management", "An explicit admin/SSH port assignment in the configuration."),
    Control("CIS-BANNER-001", "CIS", "A legal/warning banner must be configured",
            "management.banner_configured", "eq", True, "LOW",
            "Configure a login/MOTD banner with an appropriate legal warning notice.",
            "management", "A banner/login-message directive present in the configuration."),
    Control("CIS-LOG-001", "CIS", "Remote syslog logging must be enabled",
            "logging.remote_syslog", "eq", True, "HIGH",
            "Configure a remote syslog server and enable logging forwarding.",
            "logging", "A logging/syslog-host directive pointing at a remote collector address."),
    Control("CIS-LOG-002", "CIS", "Device clock must be synchronized via NTP",
            "logging.ntp_synced", "eq", True, "MEDIUM",
            "Configure at least one NTP server so audit-log timestamps are trustworthy.",
            "logging", "An NTP server directive in the configuration."),
    Control("CIS-AAA-001", "CIS", "Centralized AAA authentication must be enabled",
            "aaa.enabled", "eq", True, "HIGH",
            "Enable AAA (new-model / equivalent) and configure a centralized authentication method.",
            "aaa", "An AAA/new-model enable directive."),
    Control("CIS-AAA-002", "CIS", "A non-default centralized authentication method must be configured",
            "aaa.authentication_method", "ne", None, "MEDIUM",
            "Configure AAA authentication to use TACACS+/RADIUS rather than local-only fallback.",
            "aaa", "An 'aaa authentication login default <method>' (or vendor equivalent) directive."),
    Control("CIS-SNMP-001", "CIS", "Default SNMP community strings must not be used",
            "snmp.community_strings_default", "eq", False, "CRITICAL",
            "Change default SNMP community strings ('public'/'private') to unique, strong values, or migrate to SNMPv3.",
            "snmp", "An SNMP community-string directive whose value was checked against the default list."),
    Control("CIS-PWD-001", "CIS", "Password/secret storage must be encrypted",
            "password_policy.encrypted_storage", "eq", True, "HIGH",
            "Enable password encryption service so secrets are never stored in plaintext.",
            "password", "A 'service password-encryption' (or vendor equivalent) directive."),
    Control("CIS-PWD-002", "CIS", "Minimum password length must be at least 8 characters",
            "password_policy.min_length", "gte", 8, "MEDIUM",
            "Set the minimum administrative password length to 8 characters or more.",
            "password", "A password-policy minimum-length directive with an explicit numeric value."),
    Control("CIS-PWD-003", "CIS", "Password complexity requirements must be enforced",
            "password_policy.complexity_required", "eq", True, "MEDIUM",
            "Enable the platform's password-complexity policy for administrative accounts.",
            "password", "A password-policy directive enabling complexity enforcement."),
    Control("NIST-AC-17", "NIST-800-53", "Remote access must use SSHv2 (AC-17 Remote Access)",
            "management.ssh.version", "eq", 2, "HIGH",
            "Enforce SSH protocol version 2 for all remote administrative access.",
            "management", "A management/SSH stanza declaring protocol version 2."),
    Control("NIST-AC-17-2", "NIST-800-53", "Telnet must not be used for remote administrative access (AC-17)",
            "management.telnet.enabled", "eq", False, "CRITICAL",
            "Disable Telnet; AC-17 requires cryptographically protected remote access sessions.",
            "management", "VTY/management-line transport configuration showing telnet excluded."),
    Control("NIST-AU-3", "NIST-800-53", "Audit records must be sent to a remote log host (AU-3)",
            "logging.remote_syslog", "eq", True, "HIGH",
            "Forward audit/system logs to a centralized, remote syslog collector.",
            "logging", "A logging/syslog-host directive pointing at a remote collector address."),
    Control("NIST-AU-8", "NIST-800-53", "Audit records must use synchronized time stamps (AU-8)",
            "logging.ntp_synced", "eq", True, "MEDIUM",
            "Configure NTP so all audit timestamps use an authoritative, synchronized time source.",
            "logging", "An NTP server directive in the configuration."),
    Control("NIST-IA-5", "NIST-800-53", "Authenticator management: no default SNMP secrets (IA-5)",
            "snmp.community_strings_default", "eq", False, "CRITICAL",
            "Replace default SNMP community strings; prefer SNMPv3 with authPriv.",
            "snmp", "An SNMP community-string directive whose value was checked against the default list."),
    Control("NIST-IA-5-2", "NIST-800-53", "Password minimum length must be enforced (IA-5)",
            "password_policy.min_length", "gte", 8, "MEDIUM",
            "Set the minimum administrative password length to 8 characters or more.",
            "password", "A password-policy minimum-length directive with an explicit numeric value."),
    Control("STIG-NET-001", "DISA-STIG", "The network device must not have Telnet enabled",
            "management.telnet.enabled", "eq", False, "CRITICAL",
            "Disable the Telnet service; STIG requires encrypted management protocols only.",
            "management", "VTY/management-line transport configuration showing telnet excluded."),
    Control("STIG-NET-002", "DISA-STIG", "SSH idle timeout must be configured (<= 600s)",
            "management.ssh.idle_timeout", "lte", 600, "MEDIUM",
            "Configure SSH/exec idle timeout to 600 seconds or less per STIG guidance.",
            "management", "An explicit idle/exec-timeout value on the management or VTY line."),
    Control("STIG-NET-003", "DISA-STIG", "The network device must enforce password encryption for locally stored credentials",
            "password_policy.encrypted_storage", "eq", True, "HIGH",
            "Enable password/secret encryption so no credential is stored in plaintext.",
            "password", "A 'service password-encryption' (or vendor equivalent) directive."),
    Control("STIG-NET-004", "DISA-STIG", "The network device must forward audit records to a central log host",
            "logging.remote_syslog", "eq", True, "HIGH",
            "Configure and enable remote syslog forwarding.",
            "logging", "A logging/syslog-host directive pointing at a remote collector address."),
    Control("ISO27001-A9-1", "ISO-27001", "Access control: management access must be authenticated centrally (A.9)",
            "aaa.enabled", "eq", True, "HIGH",
            "Implement centralized authentication (AAA/TACACS+/RADIUS) for all administrative access.",
            "aaa", "An AAA/new-model enable directive."),
    Control("ISO27001-A9-4", "ISO-27001", "Secure log-on procedures must exclude unencrypted remote access (A.9.4)",
            "management.telnet.enabled", "eq", False, "CRITICAL",
            "Disable Telnet; require an encrypted protocol (SSH) for all administrative log-on.",
            "management", "VTY/management-line transport configuration showing telnet excluded."),
    Control("ISO27001-A12-4", "ISO-27001", "Logging and monitoring must be enabled (A.12.4)",
            "logging.remote_syslog", "eq", True, "HIGH",
            "Enable and centralize system event logging as required by A.12.4.",
            "logging", "A logging/syslog-host directive pointing at a remote collector address."),
    Control("ISO27001-A9-2", "ISO-27001", "Secret/password storage must be protected (A.9.2/A.9.4)",
            "password_policy.encrypted_storage", "eq", True, "HIGH",
            "Enable password/secret encryption so no credential is stored in plaintext.",
            "password", "A 'service password-encryption' (or vendor equivalent) directive."),
]


def controls_for_framework(framework: Optional[str]) -> List[Control]:
    if not framework or framework.upper() == "ALL":
        return CONTROLS
    return [c for c in CONTROLS if c.framework.upper() == framework.upper()]


def controls_for_domain(domain: str) -> List[Control]:
    return [c for c in CONTROLS if c.domain == domain]