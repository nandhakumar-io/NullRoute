"""
Executable proof of the Part 2 §14 demo scenario: a real Cisco config with
SSHv1 enabled parses -> normalizes -> evaluates against a CIS control ->
FAILs at HIGH severity with evidence and remediation, and the same
*concept*, evaluated through the same control, produces the same result
when the equivalent misconfiguration appears in Juniper and Fortinet syntax
— i.e. vendor syntax is not compliance logic (IMPLEMENTATION_AUDIT.md §9).

Uses the real deterministic parser (app.services.parsers.parse_config)
against literal vendor config fixtures, and
app.policies.reference_evaluator (TEST-ONLY — see that module's docstring)
in place of a live OPA call, since this sandbox has no network egress and
cannot run a real OPA instance. Run this file under real pytest against a
live OPA + policies/ bundle before treating it as a full end-to-end
guarantee — see reference_evaluator.py's docstring.
"""
from app.policies.reference_evaluator import evaluate_reference
from app.services.parsers import parse_config

CISCO_SSHV1 = """
hostname core-sw01
ip ssh version 1
ip ssh time-out 600
line vty 0 4
 transport input ssh
no ip http server
ip http secure-server
aaa new-model
logging host 10.0.0.5
"""

CISCO_SSHV2 = CISCO_SSHV1.replace("ip ssh version 1", "ip ssh version 2")

CISCO_TELNET = """
hostname core-sw01
line vty 0 4
 transport input telnet
"""

JUNIPER_TELNET = """
set system host-name edge-rtr01
set system services telnet
"""

FORTINET_TELNET = """
config system global
    set hostname "fw-edge01"
end
config system admin
    set admin-telnet enable
end
"""

CISCO_NO_TELNET_MENTION = """
hostname core-sw01
ip ssh version 2
line vty 0 4
 transport input ssh
"""


def test_cisco_sshv1_fails_cis_ssh_001_at_high_with_evidence_and_remediation():
    """The exact §14 demo: Cisco SSHv1 -> CIS-SSH-001 -> FAIL/HIGH -> evidence -> remediation."""
    baseline = parse_config("Cisco", CISCO_SSHV1)
    result = evaluate_reference(baseline.flatten(), framework="CIS")

    finding = next(f for f in result["findings"] if f["control_id"] == "CIS-SSH-001")
    assert finding["result"] == "FAIL"
    assert finding["severity"] == "HIGH"
    assert finding["actual"] == 1
    assert finding["expected"] == 2
    assert finding["remediation"]

    # Evidence: the raw config line that produced this parameter must be
    # traceable in the baseline's provenance (finding -> parameter -> raw
    # config, per §5's traceability requirement).
    matches = [p for p in baseline.provenance if p.normalized_parameter == "management.ssh.version"]
    assert matches, "no provenance entry for management.ssh.version"
    assert "ip ssh version 1" in matches[0].raw_command

    assert result["decision"] in ("REVIEW", "BLOCK")


def test_cisco_sshv2_passes_the_same_control():
    baseline = parse_config("Cisco", CISCO_SSHV2)
    result = evaluate_reference(baseline.flatten(), framework="CIS")
    finding = next(f for f in result["findings"] if f["control_id"] == "CIS-SSH-001")
    assert finding["result"] == "PASS"
    assert finding["actual"] == 2


def test_telnet_control_produces_identical_result_across_cisco_juniper_fortinet():
    """The multi-vendor proof (§9/§14 follow-up): same concept (Telnet
    enabled), expressed in three different vendors' native syntax, must
    evaluate through the SAME control_id to the SAME result/severity/
    expected — with vendor-specific evidence for each. This is the direct,
    checkable form of "vendor syntax != compliance logic"."""
    fixtures = {
        "Cisco": CISCO_TELNET,
        "Juniper": JUNIPER_TELNET,
        "Fortinet": FORTINET_TELNET,
    }

    per_vendor_findings = {}
    for vendor, raw_text in fixtures.items():
        baseline = parse_config(vendor, raw_text)
        result = evaluate_reference(baseline.flatten(), framework="CIS")
        finding = next(f for f in result["findings"] if f["control_id"] == "CIS-TELNET-001")
        per_vendor_findings[vendor] = finding

        # Each vendor's evidence must be traceable back to that vendor's own
        # raw config line, not a shared/generic string.
        matches = [p for p in baseline.provenance if p.normalized_parameter == "management.telnet.enabled"]
        assert matches, f"no provenance entry for management.telnet.enabled ({vendor})"

    reference = per_vendor_findings["Cisco"]
    for vendor, finding in per_vendor_findings.items():
        assert finding["control_id"] == reference["control_id"] == "CIS-TELNET-001"
        assert finding["result"] == reference["result"] == "FAIL", f"{vendor} did not FAIL"
        assert finding["severity"] == reference["severity"] == "CRITICAL"
        assert finding["expected"] == reference["expected"] is False
        assert finding["actual"] is True, f"{vendor} actual should be True (telnet enabled)"


def test_no_telnet_mention_is_not_applicable_never_a_false_pass_or_fail():
    """Negative case: a config that never mentions Telnet at all must
    evaluate NOT_APPLICABLE, never a false-positive FAIL (telnet assumed
    enabled) or false-negative PASS (telnet assumed disabled) — the
    parser must not guess (see problem-statement RULE 12)."""
    baseline = parse_config("Cisco", CISCO_NO_TELNET_MENTION)
    result = evaluate_reference(baseline.flatten(), framework="CIS")
    finding = next(f for f in result["findings"] if f["control_id"] == "CIS-TELNET-001")
    assert finding["result"] == "NOT_APPLICABLE"
    assert finding["actual"] is None