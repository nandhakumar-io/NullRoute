"""
Deterministic compliance evaluation — thin adapter between the Security
Baseline Model and OPA.

CRITICAL DESIGN RULE (per problem statement, rules 2 and 14): OPA is the
sole authoritative decision engine. If OPA is unreachable or returns a
malformed response, this module does NOT fall back to re-implementing the
rules in Python — it fails closed via opa_service.fail_closed_decision(),
which the pipeline/correlation layer turns into BLOCK or REVIEW per
OPA_FAIL_MODE. The Python `controls.py` catalog still exists, but only as
the source data mirrored into policies/common/controls.rego and as a
fixture for tests that check OPA/Python parity — it is never used to
compute a live decision.

Both this module and OPA consume ONLY the flattened Security Baseline Model
(dotted-path -> value) produced after AI/parser normalization + Pydantic
validation. No raw AI text ever reaches this layer.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.models.baseline import SecurityBaselineModel
from app.services import opa_service
from app.services.opa_service import OPADecision, OPAMalformedResponseError, OPAUnavailableError


def _remediation_for(remediation: Optional[str], vendor: str) -> Optional[str]:
    if not remediation:
        return remediation
    vendor_hint = {
        "Cisco": "(Cisco IOS-XE CLI: enter `configure terminal` first.)",
        "Juniper": "(Junos: use `set` commands then `commit`.)",
        "Fortinet": "(FortiOS CLI: `config system global` context.)",
        "Palo Alto Networks": "(PAN-OS: `set deviceconfig system` then `commit`.)",
        "Arista": "(EOS CLI: standard `configure` context, EOS syntax mirrors IOS.)",
        "SONiC": "(SONiC: apply via `config` CLI or config_db.json patch + `config reload`.)",
    }.get(vendor, "")
    return f"{remediation} {vendor_hint}".strip()


def _find_evidence(baseline: SecurityBaselineModel, parameter: Optional[str]) -> str:
    if parameter:
        for p in baseline.provenance:
            if p.normalized_parameter == parameter:
                return p.raw_command
    return "(parameter not found in source configuration — evaluated as absent/default)"


async def evaluate_baseline_via_opa(
    scan_id: str, baseline: SecurityBaselineModel, framework: Optional[str] = "ALL",
) -> OPADecision:
    """Call OPA; fail closed (never fall back to Python) if it can't be
    reached or returns something malformed."""
    flattened = baseline.flatten()
    device = {
        "vendor": baseline.device.vendor, "os": baseline.device.os,
        "model": baseline.device.model, "hostname": baseline.device.hostname,
    }
    try:
        return await opa_service.evaluate_baseline(
            scan_id=scan_id, device=device, vendor=baseline.device.vendor or "Unknown",
            framework=framework or "ALL", flattened_baseline=flattened,
        )
    except (OPAUnavailableError, OPAMalformedResponseError) as e:
        return opa_service.fail_closed_decision(scan_id, reason=str(e))


def opa_decision_to_findings(decision: OPADecision, baseline: SecurityBaselineModel) -> List[Dict[str, Any]]:
    """Adapt OPA's finding shape (control_id/expected/actual/reason/...) to
    the Finding ORM row shape (expected_value/actual_value/evidence_line/...)
    already used by scans.py/reports.py/the frontend."""
    findings: List[Dict[str, Any]] = []
    vendor = baseline.device.vendor or ""
    for f in decision.findings:
        findings.append({
            "framework": f.get("framework", "SYSTEM"),
            "control_id": f["control_id"],
            "title": f.get("title", f["control_id"]),
            "severity": f.get("severity", "MEDIUM"),
            "expected_value": str(f.get("expected")),
            "actual_value": str(f.get("actual")),
            "parameter": f.get("parameter") or "",
            "result": f["result"],
            "evidence_line": _find_evidence(baseline, f.get("parameter")),
            "remediation": _remediation_for(f.get("remediation"), vendor),
        })
    return findings


def compute_score(findings: List[Dict[str, Any]]) -> float:
    applicable = [f for f in findings if f["result"] != "NOT_APPLICABLE"]
    if not applicable:
        return 0.0
    passed = sum(1 for f in applicable if f["result"] == "PASS")
    return round(100.0 * passed / len(applicable), 1)
