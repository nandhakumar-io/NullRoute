"""
Tests for new vendor parsers — Aruba AOS-CX and Sophos XG/SFOS.

These use the same offline deterministic parse_config() path as the
existing test_normalization_pipeline.py tests, so they need no
external services, LLM, or GPU.
"""
import pytest

from app.services.parsers import parse_config, VENDOR_RULES


ARUBA_CONFIG = """\
hostname aruba-core-sw01
ssh server
ssh session-timeout 10
no telnet-server
web-management https
logging 10.10.10.100
ntp server 10.10.10.200
aaa authentication login default radius local
radius-server host 10.10.10.100
snmp-server community readonly ro
password complexity enable
password minimum-length 10
banner motd ^
This is an authorized access only system.
^
"""

SOPHOS_CONFIG = """\
set hostname sophos-xg01
set device-access-profile name admin-mgmt https enable
set device-access-profile name admin-mgmt telnet disable
set device-access-profile name admin-mgmt ssh enable
set ssh-idle-timeout 10
set password-complexity enable
set password-minimum-length 12
set log-server 10.10.10.100
set ntp-server 10.10.10.200
set snmp-agent enable
set snmp-community-string readonlyaccess
set admin-authentication-method radius
set radius-server ip 10.10.10.100
set login-disclaimer enable
"""


def test_aruba_vendor_rules_are_registered():
    """Aruba must appear in VENDOR_RULES so parse_config dispatches to its rules."""
    assert "Aruba" in VENDOR_RULES, "Aruba rules must be registered in VENDOR_RULES"
    assert len(VENDOR_RULES["Aruba"]) >= 10, "Expected at least 10 Aruba rule tuples"


def test_sophos_vendor_rules_are_registered():
    """Sophos must appear in VENDOR_RULES."""
    assert "Sophos" in VENDOR_RULES, "Sophos rules must be registered in VENDOR_RULES"
    assert len(VENDOR_RULES["Sophos"]) >= 10, "Expected at least 10 Sophos rule tuples"


def test_aruba_hostname_parsed():
    baseline = parse_config("Aruba", ARUBA_CONFIG)
    assert baseline.device.hostname == "aruba-core-sw01"


def test_aruba_ssh_enabled():
    baseline = parse_config("Aruba", ARUBA_CONFIG)
    flat = baseline.flatten()
    assert flat.get("management.ssh.enabled") is True


def test_aruba_ssh_idle_timeout():
    baseline = parse_config("Aruba", ARUBA_CONFIG)
    flat = baseline.flatten()
    # 10 minutes × 60 = 600 seconds
    assert flat.get("management.ssh.idle_timeout") == 600


def test_aruba_telnet_disabled():
    baseline = parse_config("Aruba", ARUBA_CONFIG)
    flat = baseline.flatten()
    assert flat.get("management.telnet.enabled") is False


def test_aruba_https_only():
    baseline = parse_config("Aruba", ARUBA_CONFIG)
    flat = baseline.flatten()
    assert flat.get("management.http.https_only") is True


def test_aruba_syslog_and_ntp():
    baseline = parse_config("Aruba", ARUBA_CONFIG)
    flat = baseline.flatten()
    assert flat.get("logging.remote_syslog") is True
    assert flat.get("logging.ntp_synced") is True


def test_aruba_aaa_and_radius():
    baseline = parse_config("Aruba", ARUBA_CONFIG)
    flat = baseline.flatten()
    assert flat.get("aaa.enabled") is True


def test_aruba_password_policy():
    baseline = parse_config("Aruba", ARUBA_CONFIG)
    flat = baseline.flatten()
    assert flat.get("password_policy.complexity_required") is True
    assert flat.get("password_policy.min_length") == 10


def test_aruba_banner():
    baseline = parse_config("Aruba", ARUBA_CONFIG)
    flat = baseline.flatten()
    assert flat.get("management.banner_configured") is True


def test_aruba_all_deterministic_facts_carry_full_provenance():
    baseline = parse_config("Aruba", ARUBA_CONFIG)
    parser_facts = [p for p in baseline.provenance if p.source == "parser"]
    assert parser_facts, "Expected at least one deterministic Aruba fact"
    for p in parser_facts:
        assert p.confidence == 1.0
        assert p.human_validated is True
        assert p.model_version


# --------------------------------------------------------------------------
# Sophos tests
# --------------------------------------------------------------------------

def test_sophos_hostname_parsed():
    baseline = parse_config("Sophos", SOPHOS_CONFIG)
    assert baseline.device.hostname == "sophos-xg01"


def test_sophos_https_management():
    baseline = parse_config("Sophos", SOPHOS_CONFIG)
    flat = baseline.flatten()
    assert flat.get("management.http.https_only") is True


def test_sophos_ssh_enabled():
    baseline = parse_config("Sophos", SOPHOS_CONFIG)
    flat = baseline.flatten()
    assert flat.get("management.ssh.enabled") is True


def test_sophos_telnet_disabled():
    baseline = parse_config("Sophos", SOPHOS_CONFIG)
    flat = baseline.flatten()
    assert flat.get("management.telnet.enabled") is False


def test_sophos_ssh_idle_timeout():
    baseline = parse_config("Sophos", SOPHOS_CONFIG)
    flat = baseline.flatten()
    # 10 minutes × 60 = 600 seconds
    assert flat.get("management.ssh.idle_timeout") == 600


def test_sophos_password_policy():
    baseline = parse_config("Sophos", SOPHOS_CONFIG)
    flat = baseline.flatten()
    assert flat.get("password_policy.complexity_required") is True
    assert flat.get("password_policy.min_length") == 12


def test_sophos_syslog_and_ntp():
    baseline = parse_config("Sophos", SOPHOS_CONFIG)
    flat = baseline.flatten()
    assert flat.get("logging.remote_syslog") is True
    assert flat.get("logging.ntp_synced") is True


def test_sophos_snmp_enabled():
    baseline = parse_config("Sophos", SOPHOS_CONFIG)
    flat = baseline.flatten()
    assert flat.get("snmp.enabled") is True


def test_sophos_banner():
    baseline = parse_config("Sophos", SOPHOS_CONFIG)
    flat = baseline.flatten()
    assert flat.get("management.banner_configured") is True


def test_sophos_aaa_authentication_method():
    baseline = parse_config("Sophos", SOPHOS_CONFIG)
    flat = baseline.flatten()
    assert flat.get("aaa.authentication_method") == "radius"


def test_sophos_all_deterministic_facts_carry_full_provenance():
    baseline = parse_config("Sophos", SOPHOS_CONFIG)
    parser_facts = [p for p in baseline.provenance if p.source == "parser"]
    assert parser_facts, "Expected at least one deterministic Sophos fact"
    for p in parser_facts:
        assert p.confidence == 1.0
        assert p.human_validated is True
