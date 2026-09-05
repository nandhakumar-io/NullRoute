import httpx
import pytest
import respx

from app.services import opa_service, risk_engine, evidence_service
from app.services.change_validation_service import correlate
from app.services.opa_service import OPADecision, OPAUnavailableError, OPAMalformedResponseError

OPA_EVAL_URL = f"{opa_service.OPA_URL}/v1/data/compliance/evaluate"


def _opa_body(decision, findings, violations=None, policy_version="1.0.0"):
    return {
        "result": {
            "decision": decision,
            "findings": findings,
            "violations": violations if violations is not None else [f for f in findings if f["result"] == "FAIL"],
            "evaluated_controls": [f["control_id"] for f in findings],
            "policy_version": policy_version,
        }
    }


PASS_FINDING = {"control_id": "CIS-SSH-001", "framework": "CIS", "title": "SSH v2", "severity": "HIGH",
                "parameter": "management.ssh.version", "expected": 2, "actual": 2, "result": "PASS",
                "reason": "ok", "remediation": None}

CRITICAL_FAIL = {"control_id": "CIS-TELNET-001", "framework": "CIS", "title": "Telnet disabled", "severity": "CRITICAL",
                  "parameter": "management.telnet.enabled", "expected": False, "actual": True, "result": "FAIL",
                  "reason": "telnet on", "remediation": "disable telnet"}

HIGH_FAIL = {"control_id": "CIS-LOG-001", "framework": "CIS", "title": "Remote syslog", "severity": "HIGH",
             "parameter": "logging.remote_syslog", "expected": True, "actual": False, "result": "FAIL",
             "reason": "no syslog", "remediation": "enable syslog"}


@pytest.mark.asyncio
@respx.mock
async def test_opa_pass():
    respx.post(OPA_EVAL_URL).mock(return_value=httpx.Response(200, json=_opa_body("PASS", [PASS_FINDING])))
    decision = await opa_service.evaluate_baseline("scan-1", {"vendor": "Cisco"}, "Cisco", "ALL", {"management.ssh.version": 2})
    assert decision.decision == "PASS"
    assert decision.source == "opa"
    assert decision.findings[0]["result"] == "PASS"


@pytest.mark.asyncio
@respx.mock
async def test_opa_fail_critical_blocks():
    respx.post(OPA_EVAL_URL).mock(return_value=httpx.Response(200, json=_opa_body("BLOCK", [CRITICAL_FAIL])))
    decision = await opa_service.evaluate_baseline("scan-2", {"vendor": "Cisco"}, "Cisco", "ALL", {"management.telnet.enabled": True})
    assert decision.decision == "BLOCK"
    assert decision.violations[0]["severity"] == "CRITICAL"


@pytest.mark.asyncio
@respx.mock
async def test_opa_unavailable_raises():
    respx.post(OPA_EVAL_URL).mock(side_effect=httpx.ConnectError("connection refused"))
    with pytest.raises(OPAUnavailableError):
        await opa_service.evaluate_baseline("scan-3", {"vendor": "Cisco"}, "Cisco", "ALL", {})


@pytest.mark.asyncio
@respx.mock
async def test_opa_malformed_response_raises():
    respx.post(OPA_EVAL_URL).mock(return_value=httpx.Response(200, json={"result": {"decision": "MAYBE"}}))
    with pytest.raises(OPAMalformedResponseError):
        await opa_service.evaluate_baseline("scan-4", {"vendor": "Cisco"}, "Cisco", "ALL", {})


def test_fail_closed_decision_block_mode(monkeypatch):
    monkeypatch.setattr(opa_service, "OPA_FAIL_MODE", "block")
    decision = opa_service.fail_closed_decision("scan-5", "timeout")
    assert decision.decision == "BLOCK"
    assert decision.source == "fail_closed"
    assert decision.findings[0]["control_id"] == "OPA-AVAILABILITY"


def test_fail_closed_decision_review_mode(monkeypatch):
    monkeypatch.setattr(opa_service, "OPA_FAIL_MODE", "review")
    decision = opa_service.fail_closed_decision("scan-6", "timeout")
    assert decision.decision == "REVIEW"


def test_sanitize_baseline_strips_secrets():
    flat = {
        "management.ssh.version": 2,
        "snmp.community_string_value": "public",
        "aaa.tacacs_password": "hunter2",
        "device.ssh_key_fingerprint": "abcd",
        "logging.remote_syslog": True,
    }
    clean = opa_service.sanitize_baseline(flat)
    assert "snmp.community_string_value" not in clean
    assert "aaa.tacacs_password" not in clean
    assert "device.ssh_key_fingerprint" not in clean
    assert clean["management.ssh.version"] == 2
    assert clean["logging.remote_syslog"] is True


def test_risk_engine_deterministic_and_bounded():
    findings = [CRITICAL_FAIL, HIGH_FAIL, PASS_FINDING]
    r1 = risk_engine.calculate_risk(findings)
    r2 = risk_engine.calculate_risk(findings)
    assert r1.risk_score == r2.risk_score  # deterministic
    assert 0 <= r1.risk_score <= 100
    assert r1.risk_level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    # one CRITICAL + one HIGH FAIL should land at least in HIGH band
    assert r1.risk_score >= 50


def test_risk_engine_no_fails_is_low():
    r = risk_engine.calculate_risk([PASS_FINDING])
    assert r.risk_score == 0
    assert r.risk_level == "LOW"


def test_correlation_syntax_error_blocks():
    decision = OPADecision(decision="PASS", findings=[], violations=[])
    risk = risk_engine.RiskResult(risk_score=0, risk_level="LOW")
    result = correlate(syntax_ok=False, opa_decision=decision, risk=risk, syntax_error_detail="bad line 4")
    assert result.decision == "BLOCK"
    assert result.syntax_status == "SYNTAX_ERROR"


def test_correlation_opa_block_wins():
    decision = OPADecision(decision="BLOCK", findings=[CRITICAL_FAIL], violations=[CRITICAL_FAIL])
    risk = risk_engine.calculate_risk([CRITICAL_FAIL])
    result = correlate(syntax_ok=True, opa_decision=decision, risk=risk)
    assert result.decision == "BLOCK"
    assert result.opa_status == "BLOCK"


def test_correlation_opa_review_propagates():
    decision = OPADecision(decision="REVIEW", findings=[HIGH_FAIL], violations=[HIGH_FAIL])
    risk = risk_engine.calculate_risk([HIGH_FAIL])
    result = correlate(syntax_ok=True, opa_decision=decision, risk=risk)
    assert result.decision == "REVIEW"


def test_correlation_all_pass():
    decision = OPADecision(decision="PASS", findings=[PASS_FINDING], violations=[])
    risk = risk_engine.calculate_risk([PASS_FINDING])
    result = correlate(syntax_ok=True, opa_decision=decision, risk=risk)
    assert result.decision == "PASS"


def test_correlation_batfish_unsupported_review_only_when_required(monkeypatch):
    import app.services.change_validation_service as cvs
    decision = OPADecision(decision="PASS", findings=[PASS_FINDING], violations=[])
    risk = risk_engine.calculate_risk([PASS_FINDING])

    monkeypatch.setattr(cvs, "BATFISH_REQUIRED", False)
    result = correlate(syntax_ok=True, opa_decision=decision, risk=risk, batfish_status="BATFISH_UNSUPPORTED")
    assert result.decision == "PASS"

    monkeypatch.setattr(cvs, "BATFISH_REQUIRED", True)
    result = correlate(syntax_ok=True, opa_decision=decision, risk=risk, batfish_status="BATFISH_UNSUPPORTED")
    assert result.decision == "REVIEW"


def test_evidence_canonicalization_is_deterministic():
    evidence = {"b": 1, "a": [3, 2, 1], "c": {"z": 1, "y": 2}}
    c1 = evidence_service.canonicalize_evidence(evidence)
    c2 = evidence_service.canonicalize_evidence(dict(reversed(list(evidence.items()))))
    assert c1 == c2


def test_evidence_hash_and_verify_roundtrip():
    evidence = evidence_service.build_evidence(
        scan_id="scan-1", device_id="dev-1", tenant_id="tenant-1", event_type="scan.completed",
        actor="system", vendor="Cisco", config_hash="abc123", baseline_hash="def456",
        opa_result={"decision": "PASS", "policy_version": "1.0.0", "decision_id": "xyz", "violations": []},
        batfish_result={"status": "NOT_INTEGRATED"}, risk_result={"risk_score": 0, "risk_level": "LOW"},
        final_decision="PASS", framework="CIS", control_ids=["CIS-SSH-001"], finding_ids=[],
    )
    canonical = evidence_service.canonicalize_evidence(evidence)
    h = evidence_service.hash_evidence(canonical)
    result = evidence_service.verify_evidence(h, evidence)
    assert result["match"] is True
    assert result["status"] == "INTEGRITY_VERIFIED"


def test_evidence_tamper_detection():
    evidence = evidence_service.build_evidence(
        scan_id="scan-1", device_id="dev-1", tenant_id="tenant-1", event_type="scan.completed",
        actor="system", vendor="Cisco", config_hash="abc123", baseline_hash="def456",
        opa_result={"decision": "BLOCK", "policy_version": "1.0.0", "decision_id": "xyz", "violations": [CRITICAL_FAIL]},
        batfish_result={"status": "NOT_INTEGRATED"}, risk_result={"risk_score": 80, "risk_level": "CRITICAL"},
        final_decision="BLOCK", framework="CIS", control_ids=["CIS-TELNET-001"], finding_ids=[],
    )
    original_hash = evidence_service.hash_evidence(evidence_service.canonicalize_evidence(evidence))

    tampered = dict(evidence)
    tampered["final_decision"] = "PASS"  # simulate tampering with the verdict
    result = evidence_service.verify_evidence(original_hash, tampered)
    assert result["match"] is False
    assert result["status"] == "INTEGRITY_FAILURE"
