package compliance.common.controls

# Central control catalog consumed by every domain policy file.
# This intentionally mirrors backend/app/policies/controls.py control-for-
# control: OPA is the authoritative decision engine now, but keeping the two
# catalogs in lockstep means the (test-only) Python reference evaluator used
# in unit tests can be checked for parity against this file.
#
# Each control carries a `domain` used to route it to the right
# policies/security/*.rego file, and a `parameter` which is a dotted path
# looked up in the flattened Security Baseline Model (input.baseline).

controls = {
	"CIS-SSH-001": {
		"framework": "CIS", "domain": "management",
		"title": "SSH protocol version must be 2",
		"parameter": "management.ssh.version", "operator": "eq", "expected": 2,
		"severity": "HIGH",
		"remediation": "Configure the device to use SSH protocol version 2 only.",
	},
	"CIS-TELNET-001": {
		"framework": "CIS", "domain": "management",
		"title": "Telnet must be disabled for management access",
		"parameter": "management.telnet.enabled", "operator": "eq", "expected": false,
		"severity": "CRITICAL",
		"remediation": "Disable the Telnet management service; use SSH exclusively.",
	},
	"CIS-HTTP-001": {
		"framework": "CIS", "domain": "management",
		"title": "Unencrypted HTTP management interface must be disabled",
		"parameter": "management.http.enabled", "operator": "eq", "expected": false,
		"severity": "HIGH",
		"remediation": "Disable plaintext HTTP management access; use HTTPS only.",
	},
	"CIS-HTTP-002": {
		"framework": "CIS", "domain": "management",
		"title": "HTTPS must be enforced for web management",
		"parameter": "management.http.https_only", "operator": "eq", "expected": true,
		"severity": "MEDIUM",
		"remediation": "Enable HTTPS-only enforcement for the web management interface.",
	},
	"CIS-SSH-002": {
		"framework": "CIS", "domain": "management",
		"title": "SSH idle session timeout must not exceed 600 seconds",
		"parameter": "management.ssh.idle_timeout", "operator": "lte", "expected": 600,
		"severity": "MEDIUM",
		"remediation": "Set the SSH/administrative idle session timeout to 600 seconds or less.",
	},
	"CIS-BANNER-001": {
		"framework": "CIS", "domain": "management",
		"title": "A legal/warning banner must be configured",
		"parameter": "management.banner_configured", "operator": "eq", "expected": true,
		"severity": "LOW",
		"remediation": "Configure a login/MOTD banner with an appropriate legal warning notice.",
	},
	"CIS-LOG-001": {
		"framework": "CIS", "domain": "logging",
		"title": "Remote syslog logging must be enabled",
		"parameter": "logging.remote_syslog", "operator": "eq", "expected": true,
		"severity": "HIGH",
		"remediation": "Configure a remote syslog server and enable logging forwarding.",
	},
	"CIS-AAA-001": {
		"framework": "CIS", "domain": "aaa",
		"title": "Centralized AAA authentication must be enabled",
		"parameter": "aaa.enabled", "operator": "eq", "expected": true,
		"severity": "HIGH",
		"remediation": "Enable AAA (new-model / equivalent) and configure a centralized authentication method.",
	},
	"CIS-SNMP-001": {
		"framework": "CIS", "domain": "snmp",
		"title": "Default SNMP community strings must not be used",
		"parameter": "snmp.community_strings_default", "operator": "eq", "expected": false,
		"severity": "CRITICAL",
		"remediation": "Change default SNMP community strings ('public'/'private') to unique, strong values, or migrate to SNMPv3.",
	},
	"CIS-PWD-001": {
		"framework": "CIS", "domain": "password",
		"title": "Password/secret storage must be encrypted",
		"parameter": "password_policy.encrypted_storage", "operator": "eq", "expected": true,
		"severity": "HIGH",
		"remediation": "Enable password encryption service so secrets are never stored in plaintext.",
	},
	"NIST-AC-17": {
		"framework": "NIST-800-53", "domain": "management",
		"title": "Remote access must use SSHv2 (AC-17 Remote Access)",
		"parameter": "management.ssh.version", "operator": "eq", "expected": 2,
		"severity": "HIGH",
		"remediation": "Enforce SSH protocol version 2 for all remote administrative access.",
	},
	"NIST-AU-3": {
		"framework": "NIST-800-53", "domain": "logging",
		"title": "Audit records must be sent to a remote log host (AU-3)",
		"parameter": "logging.remote_syslog", "operator": "eq", "expected": true,
		"severity": "HIGH",
		"remediation": "Forward audit/system logs to a centralized, remote syslog collector.",
	},
	"NIST-IA-5": {
		"framework": "NIST-800-53", "domain": "snmp",
		"title": "Authenticator management: no default SNMP secrets (IA-5)",
		"parameter": "snmp.community_strings_default", "operator": "eq", "expected": false,
		"severity": "CRITICAL",
		"remediation": "Replace default SNMP community strings; prefer SNMPv3 with authPriv.",
	},
	"STIG-NET-001": {
		"framework": "DISA-STIG", "domain": "management",
		"title": "The network device must not have Telnet enabled",
		"parameter": "management.telnet.enabled", "operator": "eq", "expected": false,
		"severity": "CRITICAL",
		"remediation": "Disable the Telnet service; STIG requires encrypted management protocols only.",
	},
	"STIG-NET-002": {
		"framework": "DISA-STIG", "domain": "management",
		"title": "SSH idle timeout must be configured (<= 600s)",
		"parameter": "management.ssh.idle_timeout", "operator": "lte", "expected": 600,
		"severity": "MEDIUM",
		"remediation": "Configure SSH/exec idle timeout to 600 seconds or less per STIG guidance.",
	},
	"ISO27001-A9-1": {
		"framework": "ISO-27001", "domain": "aaa",
		"title": "Access control: management access must be authenticated centrally (A.9)",
		"parameter": "aaa.enabled", "operator": "eq", "expected": true,
		"severity": "HIGH",
		"remediation": "Implement centralized authentication (AAA/TACACS+/RADIUS) for all administrative access.",
	},
	"ISO27001-A12-4": {
		"framework": "ISO-27001", "domain": "logging",
		"title": "Logging and monitoring must be enabled (A.12.4)",
		"parameter": "logging.remote_syslog", "operator": "eq", "expected": true,
		"severity": "HIGH",
		"remediation": "Enable and centralize system event logging as required by A.12.4.",
	},
}
