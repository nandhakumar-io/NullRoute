"""
TEST-ONLY reference evaluator. NEVER used in the production decision path —
OPA is the sole authoritative compliance decision engine (problem statement
rules 2 and 14; see services/compliance.py's module docstring). Do not
import this from application code.

This exists purely so unit tests can assert an expected OPA finding shape
without a live OPA instance to POST to (this sandbox has no network egress
and cannot install/run a real OPA binary). It mirrors
policies/common/evaluate.rego's operator logic — including the UNVERIFIED
branch (see IMPLEMENTATION_AUDIT.md §A) — control-for-control against the
SAME `backend/app/policies/controls.py` catalog that
app/policies/catalog_parity.py already checks stays in lockstep with the
Rego catalog. If the two ever diverge, that parity test fails first and
loudly, independent of this file.

Any test using this file is validating "does our Python understanding of
what OPA should do match the parsed baseline", not "does OPA actually
return this" — run these tests against a real OPA + policies/ bundle in
CI/staging before trusting the decision end-to-end.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.policies.controls import CONTROLS, Control


def _result_for(control: Control, actual: Any, is_unverified: bool) -> str:
    if actual is None:
        return "NOT_APPLICABLE"
    if is_unverified:
        return "UNVERIFIED"

    op = control.operator
    if op == "eq":
        return "PASS" if actual == control.expected else "FAIL"
    if op == "ne":
        return "PASS" if actual != control.expected else "FAIL"
    if op == "lte":
        return "PASS" if actual <= control.expected else "FAIL"
    if op == "gte":
        return "PASS" if actual >= control.expected else "FAIL"
    if op == "in":
        return "PASS" if actual in control.expected else "FAIL"
    if op == "exists":
        return "PASS"
    if op == "not_true":
        return "PASS" if actual is not True else "FAIL"
    raise ValueError(f"Unknown operator {op!r} on control {control.control_id}")


def _reason_for(control: Control, actual: Any, result: str) -> str:
    if result == "PASS":
        return f"{control.parameter} is {actual}, which satisfies the required policy."
    if result == "FAIL":
        return f"{control.parameter} is {actual}, but policy requires {control.operator} {control.expected}."
    if result == "NOT_APPLICABLE":
        return f"{control.parameter} was not present in the normalized configuration baseline."
    if result == "UNVERIFIED":
        return (
            f"{control.parameter} was normalized to {actual} by AI/RAG interpretation with low "
            "confidence and has not yet been human-approved in the Training Center; PASS/FAIL "
            "cannot be certified until it is."
        )
    raise ValueError(f"Unknown result {result!r}")


def evaluate_reference(
    flattened_baseline: Dict[str, Any],
    framework: str = "ALL",
    unverified_parameters: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Reference (test-only) equivalent of policies/baseline.rego's
    `compliance.evaluate` package: takes a flattened baseline and returns
    the same {decision, findings, violations, evaluated_controls,
    policy_version} shape OPA would."""
    unverified = set(unverified_parameters or [])
    controls = CONTROLS if framework in (None, "ALL") else [c for c in CONTROLS if c.framework == framework]

    findings = []
    for control in controls:
        actual = flattened_baseline.get(control.parameter)
        result = _result_for(control, actual, control.parameter in unverified)
        findings.append({
            "control_id": control.control_id,
            "framework": control.framework,
            "title": control.title,
            "severity": control.severity,
            "parameter": control.parameter,
            "expected": control.expected,
            "actual": actual,
            "result": result,
            "reason": _reason_for(control, actual, result),
            "remediation": control.remediation_template if result == "FAIL" else (
                "Review and approve this normalized value in the Training Center, then re-run the "
                "scan to get a certified PASS/FAIL." if result == "UNVERIFIED" else None
            ),
        })

    violations = [f for f in findings if f["result"] == "FAIL"]
    unverified_findings = [f for f in findings if f["result"] == "UNVERIFIED"]

    if any(v["severity"] == "CRITICAL" for v in violations):
        decision = "BLOCK"
    elif any(v["severity"] == "HIGH" for v in violations):
        decision = "REVIEW"
    elif sum(1 for v in violations if v["severity"] == "MEDIUM") >= 3:
        decision = "REVIEW"
    elif unverified_findings:
        decision = "REVIEW"
    else:
        decision = "PASS"

    return {
        "decision": decision,
        "findings": findings,
        "violations": violations,
        "evaluated_controls": [f["control_id"] for f in findings],
        "policy_version": "reference-evaluator-test-only",
    }