"""Config merge engine: remediation deltas applied to a running config.

The first scenario is the exact device from the bug report screenshot
(Cisco ISR 2911: telnet on VTY, HTTP server on, default `public` community).
"""
import pytest

from app.services import config_merge as cm

SCREENSHOT_CFG = """!
version 15.2
!
hostname Cisco-R1
!
! Cisco ISR 2911
!
ip domain-name lab.local
username admin privilege 15 secret Admin@123
!
crypto key generate rsa modulus 2048
ip ssh version 2
!
line vty 0 4
 login local
 transport input ssh telnet
!
ip http server
ip http authentication local
!
snmp-server community public RO
!
end
"""


def _lines(text):
    return [l.rstrip() for l in text.splitlines()]


def test_telnet_fix_replaces_transport_line_inside_vty_only():
    res = cm.apply_commands(SCREENSHOT_CFG, "conf t\nline vty 0 4\ntransport input ssh\nend", "Cisco")
    merged = _lines(res.merged_text)
    assert " transport input ssh" in merged
    assert " transport input ssh telnet" not in merged
    # nothing else moved: the diff is exactly one modified line
    stats = cm.diff_stats(SCREENSHOT_CFG, res.merged_text)
    assert stats["added"] == 1 and stats["removed"] == 1
    assert res.confidence == "HIGH"
    assert [a.action for a in res.applied] == ["replaced"]


def test_no_ip_http_server_is_shown_as_negation_like_ios_does():
    res = cm.apply_commands(SCREENSHOT_CFG, "conf t\nno ip http server\nend", "Cisco IOS-XE")
    merged = _lines(res.merged_text)
    assert "ip http server" not in merged
    assert "no ip http server" in merged
    assert "ip http authentication local" in merged  # unrelated line untouched


def test_default_snmp_community_removed_and_replacement_added_next_to_siblings():
    res = cm.apply_commands(
        SCREENSHOT_CFG,
        "conf t\nno snmp-server community public\nsnmp-server community S3cr3tRO RO\nend",
        "Cisco",
    )
    merged = _lines(res.merged_text)
    assert not any(l.startswith("snmp-server community public") for l in merged)
    assert "snmp-server community S3cr3tRO RO" in merged


def test_idempotent_second_application_changes_nothing():
    first = cm.apply_commands(SCREENSHOT_CFG, "line vty 0 4\ntransport input ssh", "Cisco")
    second = cm.apply_commands(first.merged_text, "line vty 0 4\ntransport input ssh", "Cisco")
    assert second.merged_text == first.merged_text
    assert not second.changed


def test_multiple_blocks_separated_by_end_each_apply_to_their_own_context():
    snippet = (
        "! CIS-TELNET-001\nconf t\nline vty 0 4\ntransport input ssh\nend\n\n"
        "! CIS-SSH-002\nconf t\nline vty 0 4\nexec-timeout 10 0\nend\n\n"
        "! CIS-LOG-001\nconf t\nlogging host 10.1.1.9\nlogging trap informational\nend\n"
    )
    res = cm.apply_commands(SCREENSHOT_CFG, snippet, "Cisco")
    merged = _lines(res.merged_text)
    vty = merged.index("line vty 0 4")
    assert " transport input ssh" in merged[vty:vty + 5]
    assert " exec-timeout 10 0" in merged[vty:vty + 5]
    # global commands did NOT land inside the vty block
    assert "logging host 10.1.1.9" in merged
    assert merged.index("logging host 10.1.1.9") > vty + 3


def test_deployable_commands_strip_wrappers_and_close_contexts():
    snippet = (
        "conf t\nline vty 0 4\ntransport input ssh\nend\n\n"
        "conf t\nno ip http server\nend\nwrite memory\n"
    )
    cmds = cm.deployable_commands(snippet, "Cisco")
    assert cmds == ["line vty 0 4", "transport input ssh", "exit", "no ip http server"]
    assert not any(c.lower() in ("conf t", "end", "write memory") for c in cmds)


def test_vty_change_is_expanded_to_every_vty_block_on_the_device():
    cfg = "hostname r\n!\nline vty 0 4\n transport input ssh telnet\n!\nline vty 5 15\n transport input telnet\n!\nend\n"
    snippet = "conf t\nline vty 0 4\ntransport input ssh\nend"
    expanded = cm.expand_vty_contexts(snippet, cfg)
    res = cm.apply_commands(cfg, expanded, "Cisco")
    merged = _lines(res.merged_text)
    assert merged.count(" transport input ssh") == 2
    assert not any("telnet" in l for l in merged)
    cmds = cm.deployable_commands(expanded, "Cisco")
    assert cmds.count("line vty 5 15") == 1 and cmds.count("line vty 0 4") == 1


def test_missing_context_is_created_and_reported():
    res = cm.apply_commands("hostname r\n!\nend\n", "line vty 0 4\nexec-timeout 10 0", "Cisco")
    assert any(a.action == "created_context" for a in res.applied)
    assert "line vty 0 4" in res.merged_text and " exec-timeout 10 0" in res.merged_text


def test_no_transport_input_telnet_removes_only_that_token():
    cfg = "hostname r\nline vty 0 4\n transport input ssh telnet\n!\nend\n"
    res = cm.apply_commands(cfg, "line vty 0 4\nno transport input telnet", "Arista")
    assert " transport input ssh" in _lines(res.merged_text)


def test_banner_block_is_preserved_verbatim():
    cfg = "hostname r\nbanner motd ^C\nAUTHORIZED ACCESS ONLY\n^C\nline vty 0 4\n login\n!\nend\n"
    res = cm.apply_commands(cfg, "line vty 0 4\nexec-timeout 10 0", "Cisco")
    assert "banner motd ^C\nAUTHORIZED ACCESS ONLY\n^C" in res.merged_text


def test_junos_set_style_delete_and_set():
    cfg = "set system host-name R1\nset system services telnet\nset system services ssh\n"
    res = cm.apply_commands(cfg, "configure\ndelete system services telnet\nset system services ssh\ncommit", "Juniper")
    merged = _lines(res.merged_text)
    assert "set system services telnet" not in merged
    assert merged.count("set system services ssh") == 1
    assert res.style == "set"
    assert cm.deployable_commands("configure\ndelete system services telnet\ncommit", "Juniper") == [
        "delete system services telnet"
    ]


def test_fortios_block_merge_sets_leaf_in_place():
    cfg = "config system global\n    set admin-telnet enable\n    set hostname \"FW\"\nend\n"
    res = cm.apply_commands(cfg, "config system global\nset admin-telnet disable\nend", "Fortinet")
    assert "set admin-telnet disable" in res.merged_text
    assert "set admin-telnet enable" not in res.merged_text
    assert 'set hostname "FW"' in res.merged_text


def test_unknown_platform_is_flagged_low_confidence_not_faked():
    res = cm.apply_commands("weird proprietary { x; }\n", "do-something", "AcmeOS")
    assert res.confidence == "LOW" and res.warnings


def test_empty_current_config_returns_delta_only_with_warning():
    res = cm.apply_commands(None, "line vty 0 4\ntransport input ssh", "Cisco")
    assert res.warnings
    assert "transport input ssh" in res.merged_text


def test_placeholders_found_and_filled():
    text = "logging host <SYSLOG_HOST>\nsnmp-server community <RO_COMMUNITY> RO"
    assert cm.find_placeholders(text) == ["SYSLOG_HOST", "RO_COMMUNITY"]
    filled = cm.fill_placeholders(text, {"SYSLOG_HOST": "10.0.0.5"})
    assert cm.find_placeholders(filled) == ["RO_COMMUNITY"]


def test_canonical_hash_ignores_volatile_lines_and_bangs():
    a = "Building configuration...\nCurrent configuration : 1234 bytes\n!\n! Last configuration change at 10:00\nhostname r\n!\nline vty 0 4\n login\n"
    b = "Building configuration...\nCurrent configuration : 1240 bytes\n!\n! Last configuration change at 11:59\nhostname r\nline vty 0 4\n login\n!\n"
    assert cm.config_hash(a) == cm.config_hash(b)
    assert cm.config_hash(a) != cm.config_hash(a.replace("login", "login local"))


def test_line_delta_is_order_insensitive():
    d = cm.line_delta("a\nb\nc", "c\nb\nx")
    assert d["added"] == ["x"] and d["removed"] == ["a"]


def test_is_full_config_heuristic():
    assert cm.is_full_config(SCREENSHOT_CFG)
    assert not cm.is_full_config("conf t\nline vty 0 4\ntransport input ssh\nend")
    assert not cm.is_full_config("hostname r1\ntransport input telnet\n")


@pytest.mark.parametrize("vendor,expected", [
    ("Cisco Systems", "cisco"), ("cisco_ios-xe", "cisco"), ("Arista Networks", "arista"),
    ("Juniper Networks", "juniper"), ("FortiOS", "fortigate"), ("Palo Alto Networks", "paloalto"),
    ("Ad-Hoc", ""), (None, ""), ("Unknown", ""),
])
def test_vendor_key_normalisation(vendor, expected):
    assert cm.normalize_vendor_key(vendor) == expected
