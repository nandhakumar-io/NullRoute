"""
Tests for the context-aware, lossless, vendor-agnostic normalization
pipeline: services/parsers.py (deterministic, block-grouping) +
ai/normalize.py (block-based multi-fact AI/RAG normalization, offline
heuristic path).

These tests run fully offline: `interpret_block` fails over to the
deterministic heuristic (no OLLAMA_HOST reachable in CI/sandbox), so
every assertion here only relies on behavior guaranteed even without a
live LLM -- the whole point of the "never fake completeness" requirement.
"""
import pytest

from app.ai.normalize import compute_coverage, interpret_block, to_normalized_parameters
from app.services.parsers import parse_config

CISCO_CONFIG = """
hostname core-sw01
aaa new-model
aaa authentication login default group radius local
radius server RADIUS01
 address ipv4 10.10.10.10 auth-port 1812 acct-port 1813
ip ssh version 2
logging host 10.10.10.10
interface GigabitEthernet0/1
 switchport access vlan 20
ntp server 10.10.10.20
snmp-server community readonly ro
router ospf 1
interface GigabitEthernet0/2
 ip access-group BLOCK_EXTERNAL in
some-completely-unknown-vendor-specific-directive foo bar baz
"""

JUNIPER_CONFIG = """
set system host-name edge-rtr01
set system services ssh protocol-version v2
set system syslog host 10.10.10.10 any warning
set system ntp server 10.10.10.20
set vlans USERS vlan-id 20
totally-unrecognized-juniper-knob enabled
"""

FORTINET_CONFIG = """
config system global
 set admin-sport 443
end
set server "10.10.10.10"
"""

FORTIFW_POLICY_CONFIG = """
config firewall policy
    edit 1
        set name "allow-web"
        set srcintf "port1"
        set dstintf "port2"
        set action accept
        set service "HTTP" "HTTPS"
        set logtraffic all
    next
end
"""

PANOS_RULEBASE_CONFIG = """
set rulebase security rules RULE1 from zone-a to zone-b source any destination any application any service any action allow
set rulebase security rules RULE1 log-end yes
"""

PANOS_CONFIG = """
set deviceconfig system hostname fw01
set deviceconfig system service disable-telnet yes
"""


async def _normalize_all(vendor: str, raw_text: str):
    baseline = parse_config(vendor, raw_text)
    unknown_blocks = baseline.extra_parameters.pop("_unknown_blocks", [])
    for block_text in unknown_blocks:
        block_result = await interpret_block(vendor, block_text, [])
        for norm_param in to_normalized_parameters(block_result):
            baseline.provenance.append(norm_param)
            if norm_param.normalized_parameter == "extra_parameters.unknown_evidence":
                baseline.extra_parameters.setdefault("unknown_evidence", [])
                baseline.extra_parameters["unknown_evidence"].append(norm_param.value)
            else:
                from app.services.parsers import set_or_append_dotted
                is_list = norm_param.normalized_parameter in {
                    "aaa.radius_servers", "aaa.tacacs_servers", "vlans", "acls",
                    "logging.syslog_servers", "logging.syslog_servers_detail",
                    "logging.ntp.servers", "snmp.community_strings", "snmp.trap_servers",
                    "interfaces_detail", "firewall_policies", "routing.static_routes",
                }
                set_or_append_dotted(baseline, norm_param.normalized_parameter, norm_param.value, append=is_list)
    baseline.extra_parameters["_coverage"] = compute_coverage(baseline)
    return baseline


def _provenance_raw_commands(baseline) -> list:
    return [p.raw_command for p in baseline.provenance]


@pytest.mark.asyncio
async def test_cisco_deterministic_facts_preserved():
    baseline = parse_config("Cisco", CISCO_CONFIG)
    flat = baseline.flatten()
    assert flat["management.ssh.version"] == 2
    assert flat["logging.remote_syslog"] is True
    assert baseline.aaa.radius_servers[0].address == "10.10.10.10"
    assert baseline.aaa.radius_servers[0].auth_port == 1812
    assert baseline.aaa.radius_servers[0].acct_port == 1813
    assert any(v.id == 20 for v in baseline.vlans)
    assert baseline.routing.ospf.enabled is True
    assert baseline.routing.ospf.process_id == 1
    assert any(a.name == "BLOCK_EXTERNAL" and a.direction == "in" for a in baseline.acls)
    # Every deterministic fact carries full provenance.
    parser_facts = [p for p in baseline.provenance if p.source == "parser"]
    assert parser_facts
    for p in parser_facts:
        assert p.confidence == 1.0
        assert p.human_validated is True
        assert p.model_version


@pytest.mark.asyncio
async def test_cisco_unknown_vendor_directive_retained_not_discarded():
    baseline = await _normalize_all("Cisco", CISCO_CONFIG)
    coverage = baseline.extra_parameters["_coverage"]
    assert coverage["discarded_lines"] == 0
    # The nonsense vendor-specific line must show up SOMEWHERE as evidence
    # -- either as unknown_evidence or (if the heuristic guessed a keyword
    # match) at minimum still present verbatim in provenance raw_command.
    all_raw = _provenance_raw_commands(baseline)
    unknown_evidence = baseline.extra_parameters.get("unknown_evidence", [])
    haystack = " ".join(all_raw) + " ".join(unknown_evidence)
    assert "some-completely-unknown-vendor-specific-directive" in haystack


@pytest.mark.asyncio
async def test_cisco_multiple_facts_from_one_block():
    """The radius server block has TWO independent facts nested together
    (server address + auth/acct ports) -- this must survive as one
    structured aaa.radius_servers entry, not be flattened/lost, proving
    multi-fact / relationship-aware extraction (item 2/5)."""
    baseline = parse_config("Cisco", CISCO_CONFIG)
    assert len(baseline.aaa.radius_servers) == 1
    server = baseline.aaa.radius_servers[0]
    assert server.address == "10.10.10.10"
    assert server.auth_port == 1812
    assert server.acct_port == 1813


@pytest.mark.asyncio
async def test_juniper_vendor_syntax_normalizes_to_common_concept():
    baseline = parse_config("Juniper", JUNIPER_CONFIG)
    flat = baseline.flatten()
    # Juniper's "protocol-version v2" and Cisco's "ip ssh version 2" both
    # normalize into the same vendor-neutral management.ssh.version.
    assert flat["management.ssh.version"] == 2
    assert any(s.address == "10.10.10.10" and s.severity == "warning" for s in baseline.logging.syslog_servers_detail)
    assert "10.10.10.20" in baseline.logging.ntp.servers
    assert any(v.name == "USERS" and v.id == 20 for v in baseline.vlans)


@pytest.mark.asyncio
async def test_cisco_and_juniper_ssh_v2_normalize_to_same_logical_parameter():
    """SIH26155 Part 1 final acceptance criterion, made explicit as its own
    test rather than left implicit across two separate test functions:
    Cisco's 'ip ssh version 2' and Juniper's 'set system services ssh
    protocol-version v2' are different vendor syntax for the identical
    control, and MUST collapse to one vendor-neutral fact with independent
    provenance for each source."""
    cisco = parse_config("Cisco", CISCO_CONFIG)
    juniper = parse_config("Juniper", JUNIPER_CONFIG)

    assert cisco.flatten()["management.ssh.version"] == 2
    assert juniper.flatten()["management.ssh.version"] == 2

    cisco_prov = next(p for p in cisco.provenance if p.normalized_parameter == "management.ssh.version")
    juniper_prov = next(p for p in juniper.provenance if p.normalized_parameter == "management.ssh.version")
    assert cisco_prov.raw_command == "ip ssh version 2"
    assert juniper_prov.raw_command == "set system services ssh protocol-version v2"
    assert cisco_prov.vendor == "Cisco"
    assert juniper_prov.vendor == "Juniper"
    # Same logical fact, distinct raw evidence -- vendor syntax never
    # leaked into the compliance-facing value.
    assert cisco_prov.value == juniper_prov.value == 2


@pytest.mark.asyncio
async def test_fortinet_firewall_policy_extracted_not_dropped():
    baseline = parse_config("Fortinet", FORTIFW_POLICY_CONFIG)
    assert len(baseline.firewall_policies) == 1
    policy = baseline.firewall_policies[0]
    assert policy.name == "allow-web"
    assert policy.action == "accept"
    assert policy.source_zone == "port1"
    assert policy.destination_zone == "port2"
    assert "HTTP" in (policy.service or [])


@pytest.mark.asyncio
async def test_panos_firewall_policy_extracted_not_dropped():
    baseline = parse_config("Palo Alto Networks", PANOS_RULEBASE_CONFIG)
    assert len(baseline.firewall_policies) == 1
    policy = baseline.firewall_policies[0]
    assert policy.name == "RULE1"
    assert policy.source_zone == "zone-a"
    assert policy.destination_zone == "zone-b"
    assert policy.action == "allow"


def test_low_confidence_vendor_guess_forces_review_not_confident_match():
    """Spec section 4: 'Low-confidence detection must not silently become a
    confident vendor.' A weak-heuristic guess must always carry
    review_required=True regardless of what vendor name it guessed."""
    from app.services.vendor_detect import REVIEW_CONFIDENCE_THRESHOLD, detect_vendor

    weak_cisco_text = "interface Vlan10\nspanning-tree mode rapid-pvst\n"
    guess = detect_vendor(weak_cisco_text)
    assert guess.confidence < REVIEW_CONFIDENCE_THRESHOLD
    assert guess.review_required is True


def test_confident_supported_vendor_guess_does_not_require_review():
    from app.services.vendor_detect import detect_vendor

    guess = detect_vendor(CISCO_CONFIG)
    assert guess.vendor == "Cisco"
    assert guess.confidence >= 0.75
    assert guess.review_required is False


@pytest.mark.asyncio
async def test_juniper_unknown_line_retained():
    baseline = await _normalize_all("Juniper", JUNIPER_CONFIG)
    coverage = baseline.extra_parameters["_coverage"]
    assert coverage["discarded_lines"] == 0
    all_raw = _provenance_raw_commands(baseline)
    unknown_evidence = baseline.extra_parameters.get("unknown_evidence", [])
    haystack = " ".join(all_raw) + " ".join(unknown_evidence)
    assert "totally-unrecognized-juniper-knob" in haystack


@pytest.mark.asyncio
async def test_fortinet_nested_block_extracted():
    baseline = parse_config("Fortinet", FORTINET_CONFIG)
    flat = baseline.flatten()
    assert flat["management.http.port"] == 443
    if baseline.logging.syslog_servers is not None:
        assert "10.10.10.10" in baseline.logging.syslog_servers


@pytest.mark.asyncio
async def test_panos_vendor_syntax_normalizes():
    baseline = parse_config("Palo Alto Networks", PANOS_CONFIG)
    flat = baseline.flatten()
    assert flat["management.telnet.enabled"] is False
    assert flat["device.hostname"] == "fw01"


@pytest.mark.asyncio
async def test_coverage_report_shape_and_zero_discard():
    baseline = await _normalize_all("Cisco", CISCO_CONFIG)
    coverage = baseline.extra_parameters["_coverage"]
    for key in ("input_lines", "deterministic_facts", "ai_facts", "unknown_lines",
                "normalized_facts", "discarded_lines"):
        assert key in coverage
    assert coverage["discarded_lines"] == 0
    assert coverage["input_lines"] > 0
    assert coverage["normalized_facts"] > 0


@pytest.mark.asyncio
async def test_ai_never_overrides_explicit_deterministic_evidence():
    """Deterministic facts are applied first and are never revisited by
    the AI stage for the same matched lines -- confirmed by checking the
    typed field still holds the deterministic value after full
    normalization runs on top."""
    baseline = await _normalize_all("Cisco", CISCO_CONFIG)
    assert baseline.flatten()["management.ssh.version"] == 2


@pytest.mark.asyncio
async def test_low_confidence_ai_fact_does_not_silently_pass_as_known():
    """A weak keyword-only heuristic match must never be marked
    human_validated=True (i.e. treated as KNOWN) -- it stays flagged for
    review (item 11)."""
    block_result = await interpret_block("Cisco", "some ambiguous unknown-ish directive", [])
    for fact in block_result.facts:
        if fact.confidence < 0.75:
            assert fact.needs_human_review is True


@pytest.mark.asyncio
async def test_interpret_block_never_returns_nothing_for_nonempty_block():
    """Every non-empty line must end up as either a fact or an explicit
    unknown -- the zero-discard guarantee at the interpret_block level."""
    block_text = "totally made up directive one\ntotally made up directive two"
    block_result = await interpret_block("Cisco", block_text, [])
    accounted = len(block_result.facts) + len(block_result.unknown_lines)
    assert accounted >= 2