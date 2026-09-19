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

from sqlalchemy.orm import Session

from app.models.baseline import SecurityBaselineModel
from app.services import custom_control_service, opa_service
from app.services.opa_service import OPADecision, OPAMalformedResponseError, OPAUnavailableError


def _remediation_for(remediation: Optional[str], vendor: str, result: str = "FAIL") -> Optional[str]:
    """policies/common/evaluate.rego's remediation_for() already returns
    non-null remediation text for FAIL (an actionable CLI change is
    needed), NOT_APPLICABLE (null -- nothing to do) and UNVERIFIED (a
    fixed "go approve this in the Training Center" instruction, not a CLI
    change at all). This function used to append the vendor CLI hint
    (`(Cisco IOS-XE CLI: enter 'configure terminal' first.)` etc.) to
    *any* non-null remediation regardless of `result` -- so an UNVERIFIED
    finding's human-review instruction got a misleading vendor CLI hint
    tacked onto it, as if there were a command to type. The hint is now
    only appended for FAIL, where the remediation text really is a CLI
    change; NOT_APPLICABLE (already null) and UNVERIFIED both pass through
    unchanged.
    """
    if not remediation:
        return remediation
    if result != "FAIL":
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


def _find_provenance(baseline: SecurityBaselineModel, parameter: Optional[str]):
    """Look up the NormalizedParameter (raw_line -> value mapping) behind a
    finding's parameter, so the Evidence Trace view can show whether it came
    from the deterministic parser or an AI interpretation, and at what
    confidence. Returns None when there's no single-parameter provenance to
    show (e.g. Batfish reachability findings)."""
    if parameter:
        for p in baseline.provenance:
            if p.normalized_parameter == parameter:
                return p
    return None


async def evaluate_baseline_via_opa(
    scan_id: str,
    baseline: SecurityBaselineModel,
    framework: Optional[str] = "ALL",
    db: Optional[Session] = None,
    tenant_id: Optional[str] = None,
) -> OPADecision:
    """Call OPA; fail closed (never fall back to Python) if it can't be
    reached or returns something malformed.

    db/tenant_id are optional so existing call sites that don't have a
    tenant in scope keep working unchanged, but pass both whenever
    available: it's what loads a tenant's approved CustomControl rows
    (services/custom_control_service.py::for_opa_input) into
    input.custom_controls — without it, tenant-defined custom controls are
    silently skipped for that evaluation, same as before this was wired
    up. See IMPLEMENTATION_AUDIT.md §C."""
    flattened = baseline.flatten()
    device = {
        "vendor": baseline.device.vendor, "os": baseline.device.os,
        "model": baseline.device.model, "hostname": baseline.device.hostname,
    }
    custom_controls = custom_control_service.for_opa_input(db, tenant_id) if (db and tenant_id) else []
    try:
        return await opa_service.evaluate_baseline(
            scan_id=scan_id, device=device, vendor=baseline.device.vendor or "Unknown",
            framework=framework or "ALL", flattened_baseline=flattened,
            custom_controls=custom_controls,
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
        prov = _find_provenance(baseline, f.get("parameter"))
        result = f["result"]
        findings.append({
            "framework": f.get("framework", "SYSTEM"),
            "control_id": f["control_id"],
            "title": f.get("title", f["control_id"]),
            "severity": f.get("severity", "MEDIUM"),
            "expected_value": str(f.get("expected")),
            "actual_value": str(f.get("actual")),
            "parameter": f.get("parameter") or "",
            "result": result,
            "evidence_line": _find_evidence(baseline, f.get("parameter")),
            # reason_for() in policies/common/evaluate.rego returns a
            # human-readable sentence for every result branch (PASS/FAIL/
            # NOT_APPLICABLE/UNVERIFIED) -- it was already in OPA's response
            # but this adapter dropped it on the floor, so the Finding rows'
            # `reason` column (which exists on the model) was always NULL.
            "reason": f.get("reason"),
            # Same decision-level policy_version stamped onto every finding
            # from this evaluation, so a Finding row is self-describing (the
            # exact policy revision that produced it) without a join back to
            # OPAAnalysis.
            "policy_version": decision.policy_version,
            "remediation": _remediation_for(f.get("remediation"), vendor, result),
            "source": prov.source if prov else None,
            "confidence": prov.confidence if prov else None,
            # The exact config line the evidence came from (when the parser
            # or AI normalization recorded one), so the Evidence Trace view
            # can jump straight to it instead of only showing the raw
            # command text.
            "line_number": prov.line_number if prov else None,
            # Denormalized so vendor_scores / the cross-vendor compliance
            # matrix (routers/compliance.py) can filter/group without a
            # join -- previously computed above but never attached to the
            # row, so every OPA finding landed with vendor=NULL and both
            # of those views were always empty.
            "vendor": vendor or None,
        })
    return findings


def compute_score(findings: List[Dict[str, Any]]) -> float:
    applicable = [f for f in findings if f["result"] != "NOT_APPLICABLE"]
    if not applicable:
        return 100.0
    passed = sum(1 for f in applicable if f["result"] == "PASS")
    return round(100.0 * passed / len(applicable), 1)
