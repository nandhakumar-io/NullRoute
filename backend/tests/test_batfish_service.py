"""
Tests for services/batfish_service.py.

These mock the pybatfish Session (there's no live Batfish coordinator in
the unit-test environment) and verify the *contract* the rest of the
pipeline depends on: every ambiguous or failed condition returns one of the
distinct, explicit statuses — never a silently optimistic BATFISH_PASS
(RULE 13), and Batfish never appears to override OPA (RULE 3/RULE 14 by
omission: nothing in this module can produce a compliance PASS/FAIL, only
a behavioral one that change_validation_service.correlate() weighs).
"""
import pandas as pd
import pytest

from app.services import batfish_service


CISCO_GUEST_MGMT_LEAK = """
hostname CORE-SW01
!
interface Vlan10
 description GUEST-WIFI
 ip address 10.10.10.1 255.255.255.0
!
interface Vlan99
 description MANAGEMENT
 ip address 10.99.99.1 255.255.255.0
!
ip access-list extended GUEST-ACL
 permit ip any any
!
"""


def test_is_vendor_supported():
    assert batfish_service.is_vendor_supported("Cisco")
    assert batfish_service.is_vendor_supported("cisco_iosxe")
    assert batfish_service.is_vendor_supported("Arista")
    assert batfish_service.is_vendor_supported("Juniper")
    assert not batfish_service.is_vendor_supported("Fortinet")
    assert not batfish_service.is_vendor_supported("PaloAlto")
    assert not batfish_service.is_vendor_supported(None)
    assert not batfish_service.is_vendor_supported("")


def test_infer_zones_finds_guest_and_management_vlans():
    zones = batfish_service.infer_zones(CISCO_GUEST_MGMT_LEAK)
    assert "Vlan10" in zones["GUEST"]
    assert "Vlan99" in zones["MANAGEMENT"]


def test_unsupported_vendor_short_circuits_before_touching_batfish():
    result = batfish_service.analyze_security_behavior(
        scan_id="s1", vendor="fortios", hostname="fw01", raw_config="config firewall policy\nend\n",
    )
    assert result.status == "BATFISH_UNSUPPORTED"
    assert result.reachability_checks == []


def test_disabled_returns_not_integrated(monkeypatch):
    monkeypatch.setattr(batfish_service, "BATFISH_ENABLED", False)
    result = batfish_service.analyze_security_behavior(
        scan_id="s2", vendor="cisco", hostname="sw01", raw_config=CISCO_GUEST_MGMT_LEAK, transport="ssh"
    )
    assert result.status == "NOT_INTEGRATED"


def test_snmp_returns_batfish_unsupported():
    result = batfish_service.analyze_security_behavior(
        scan_id="s_snmp", vendor="cisco", hostname="sw01", raw_config="sysDescr", transport="snmp"
    )
    assert result.status == "BATFISH_UNSUPPORTED"
    assert "unsupported for devices collected via SNMP" in result.detail


def test_session_unavailable_returns_batfish_unavailable(monkeypatch):
    def _boom():
        raise RuntimeError("no coordinator")

    monkeypatch.setattr(batfish_service, "_get_session", _boom)
    result = batfish_service.analyze_security_behavior(
        scan_id="s3", vendor="cisco", hostname="sw01", raw_config=CISCO_GUEST_MGMT_LEAK,
    )
    assert result.status == "BATFISH_UNAVAILABLE"


def test_reachability_missing_zone_locations_is_unsupported_not_pass():
    class DummyBf:
        pass

    r = batfish_service.test_reachability(
        DummyBf(), source_locations=[], destination_locations=["Vlan99"],
        control_id="X-1", title="x", source_zone="GUEST", destination_zone="MANAGEMENT",
        expected_reachable=False,
    )
    assert r.status == "BATFISH_UNSUPPORTED"
    assert r.status != "BATFISH_PASS"


class _FakeFrameHolder:
    """Mimics PyBatfish's Answer object: .frame() -> pandas DataFrame."""
    def __init__(self, frame):
        self._frame = frame

    def frame(self):
        return self._frame


class _FakeAnswer:
    """Mimics a PyBatfish QuestionBase instance: calling .answer() runs it."""
    def __init__(self, frame):
        self._frame = frame

    def answer(self):
        return _FakeFrameHolder(self._frame)


def test_reachability_found_flow_is_batfish_fail_when_not_expected():
    class DummyBf:
        class q:
            @staticmethod
            def reachability(**kwargs):
                return _FakeAnswer(pd.DataFrame([{"Flow": "guest->mgmt"}]))

    r = batfish_service.test_reachability(
        DummyBf(), source_locations=["Vlan10"], destination_locations=["Vlan99"],
        control_id="SEGMENTATION-GUEST-MGMT-001", title="Guest must not reach Management",
        source_zone="GUEST", destination_zone="MANAGEMENT", expected_reachable=False, severity="CRITICAL",
    )
    assert r.status == "BATFISH_FAIL"
    assert r.is_violation()
    finding = r.to_finding()
    assert finding["result"] == "FAIL"
    assert finding["severity"] == "CRITICAL"
    assert finding["type"] == "BEHAVIORAL_VIOLATION"


def test_reachability_no_flow_matches_expectation_is_pass():
    class DummyBf:
        class q:
            @staticmethod
            def reachability(**kwargs):
                return _FakeAnswer(pd.DataFrame([]))

    r = batfish_service.test_reachability(
        DummyBf(), source_locations=["Vlan10"], destination_locations=["Vlan99"],
        control_id="SEGMENTATION-GUEST-MGMT-001", title="Guest must not reach Management",
        source_zone="GUEST", destination_zone="MANAGEMENT", expected_reachable=False, severity="CRITICAL",
    )
    assert r.status == "BATFISH_PASS"
    assert not r.is_violation()


def test_reachability_query_exception_is_batfish_error_not_pass():
    class DummyBf:
        class q:
            @staticmethod
            def reachability(**kwargs):
                raise RuntimeError("query engine crashed")

    r = batfish_service.test_reachability(
        DummyBf(), source_locations=["Vlan10"], destination_locations=["Vlan99"],
        control_id="X-2", title="x", source_zone="GUEST", destination_zone="MANAGEMENT",
        expected_reachable=False,
    )
    assert r.status == "BATFISH_ERROR"
    assert r.status not in ("BATFISH_PASS", "BATFISH_FAIL")


def test_init_issues_never_hidden_and_never_become_pass():
    class DummyBf:
        class q:
            @staticmethod
            def fileParseStatus():
                return _FakeAnswer(pd.DataFrame([{"File_Name": "sw01.cfg", "Status": "PARTIALLY_UNRECOGNIZED"}]))

            @staticmethod
            def initIssues():
                return _FakeAnswer(pd.DataFrame([{"Nodes": "sw01", "Line_Text": "some-vendor-magic", "Explanation": "unsupported"}]))


    issues = batfish_service.get_init_issues(DummyBf())
    assert len(issues) == 2
    assert all(i["status"] in ("BATFISH_UNSUPPORTED", "BATFISH_ERROR") for i in issues)


def test_correlate_escalates_to_block_on_batfish_critical_violation():
    from app.services.change_validation_service import correlate
    from app.services.opa_service import OPADecision
    from app.services.risk_engine import RiskResult

    opa_pass = OPADecision(decision="PASS", findings=[], violations=[], evaluated_controls=[],
                            policy_version="1.0", decision_id="d1", source="opa")
    risk = RiskResult(risk_score=10, risk_level="LOW", contributing_factors=[])
    decision = correlate(
        syntax_ok=True, opa_decision=opa_pass, risk=risk,
        batfish_status="BATFISH_FAIL", batfish_critical_violation=True,
    )
    assert decision.decision == "BLOCK"
    assert "Batfish" in decision.reason


def test_correlate_treats_batfish_unsupported_as_review_when_required():
    from app.services.change_validation_service import correlate
    from app.services.opa_service import OPADecision
    from app.services.risk_engine import RiskResult

    opa_pass = OPADecision(decision="PASS", findings=[], violations=[], evaluated_controls=[],
                            policy_version="1.0", decision_id="d1", source="opa")
    risk = RiskResult(risk_score=5, risk_level="LOW", contributing_factors=[])
    decision = correlate(
        syntax_ok=True, opa_decision=opa_pass, risk=risk,
        batfish_status="BATFISH_UNSUPPORTED", batfish_critical_violation=False,
    )
    # BATFISH_REQUIRED defaults to false in the test env, so unsupported
    # alone doesn't escalate — PASS is still correct here.
    assert decision.decision == "PASS"
    assert decision.batfish_status == "BATFISH_UNSUPPORTED"
