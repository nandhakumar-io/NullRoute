"""Normalized security-baseline drift detection (Parts 2-5).

Unlike `drift_service.py` (Phase 11's raw line-diff + keyword triage,
still used for the raw-config diff view), this module compares two
`SecurityBaselineModel.flatten()` dotted-path dicts parameter-by-parameter
and classifies each change using the SAME control catalog
(`app.policies.controls.CONTROLS`) the compliance engine and Rego bundle
are generated from -- so there is exactly one place a parameter's
security meaning is defined, never a second copy of the rules.

Two independent signals are combined, and neither is invented here:
  1. Direction, from the control's own `operator`/`expected` (e.g.
     "management.ssh.version eq 2") -- used ONLY to say whether a value
     moved toward or away from the documented-secure value. This is a
     bounded, boolean-ish comparison (not a general rule engine) and,
     like the Phase 11 heuristic, NEVER stands in for a compliance
     verdict.
  2. Compliance correlation, from `opa_service.evaluate_change()` --
     OPA evaluates the SAME before/after baselines and returns which
     controls newly fail/pass. This IS the authoritative compliance
     state (Part 5: "OPA remains authoritative for compliance"); this
     module only attaches it as evidence on the finding, never derives
     it itself. If OPA can't be reached, the finding is still recorded
     with drift_type/severity from (1) alone and `compliance_state` left
     empty rather than guessed.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.models.baseline import SecurityBaselineModel
from app.models.db import Scan, SecurityDriftFinding
from app.policies.controls import CONTROLS, Control
from app.services import opa_service

logger = logging.getLogger("security_baseline_drift")

# Top-level SecurityBaselineModel sections considered security-relevant.
# A parameter under one of these with NO matching control is UNKNOWN_IMPACT
# (Part 4: "If the system cannot determine security impact = UNKNOWN_IMPACT.
# Do not guess.") rather than being waved through as a plain config change.
_SECURITY_SECTIONS = ("management", "aaa", "password_policy", "snmp", "logging")

# parameter (dotted path) -> Control, for O(1) lookup. Multiple controls can
# target one path (e.g. two SSH controls); tie-broken by taking the highest
# severity for direction classification.
_CONTROLS_BY_PARAMETER: Dict[str, List[Control]] = {}
for _c in CONTROLS:
    _CONTROLS_BY_PARAMETER.setdefault(_c.parameter, []).append(_c)

_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


# Bookkeeping-only top-level fields that always differ between two
# baselines regardless of actual configuration content (a fresh
# `normalized_at` timestamp every time a baseline is built; `raw_config_hash`
# is redundant with the raw-diff DriftEvent and not itself a security
# parameter) -- excluded so they never show up as spurious drift findings.
_EXCLUDED_PARAMETERS = {"normalized_at", "raw_config_hash"}


@dataclass
class ParameterDrift:
    parameter: str
    previous_value: Any
    current_value: Any
    drift_type: str
    severity: Optional[str] = None
    compliance_controls: List[str] = field(default_factory=list)
    compliance_state: Optional[Dict[str, str]] = None  # {"previous": "PASS", "current": "FAIL"} when OPA-correlated


def _is_compliant(control: Control, value: Any) -> Optional[bool]:
    """Bounded direction check against a control's own operator/expected --
    the exact same primitive operators the catalog already documents for
    every control. Returns None (undeterminable) rather than guessing on
    an operator this triage helper doesn't recognize."""
    op, expected = control.operator, control.expected
    try:
        if op == "eq":
            return value == expected
        if op == "ne":
            return value != expected
        if op == "gte":
            return value is not None and value >= expected
        if op == "lte":
            return value is not None and value <= expected
        if op == "in":
            return value in expected
        if op == "exists":
            return value is not None
        if op == "not_true":
            return value is not True
    except TypeError:
        return None
    return None


def _best_control(parameter: str) -> Optional[Control]:
    candidates = _CONTROLS_BY_PARAMETER.get(parameter)
    if not candidates:
        return None
    return max(candidates, key=lambda c: _SEVERITY_RANK.get(c.severity, 0))


def classify_parameter(parameter: str, previous_value: Any, current_value: Any) -> ParameterDrift:
    if previous_value == current_value:
        return ParameterDrift(parameter, previous_value, current_value, "NO_CHANGE")

    control = _best_control(parameter)
    if control is not None:
        was_compliant = _is_compliant(control, previous_value)
        is_compliant = _is_compliant(control, current_value)
        controls = [c.control_id for c in _CONTROLS_BY_PARAMETER[parameter]]
        if was_compliant is True and is_compliant is False:
            return ParameterDrift(parameter, previous_value, current_value, "SECURITY_DEGRADATION",
                                   severity=control.severity, compliance_controls=controls)
        if was_compliant is False and is_compliant is True:
            return ParameterDrift(parameter, previous_value, current_value, "SECURITY_IMPROVEMENT",
                                   severity=control.severity, compliance_controls=controls)
        if was_compliant is None or is_compliant is None:
            return ParameterDrift(parameter, previous_value, current_value, "COMPLIANCE_IMPACT",
                                   severity=control.severity, compliance_controls=controls)
        # Both compliant or both non-compliant, but the value still moved
        # (e.g. two different already-compliant SSH idle_timeout values) --
        # security-relevant field, no direction change, so it's flagged as
        # a config change with the control still attached for context.
        return ParameterDrift(parameter, previous_value, current_value, "CONFIGURATION_CHANGE",
                               severity=control.severity, compliance_controls=controls)

    section = parameter.split(".", 1)[0]
    if section in _SECURITY_SECTIONS:
        return ParameterDrift(parameter, previous_value, current_value, "UNKNOWN_IMPACT")
    return ParameterDrift(parameter, previous_value, current_value, "CONFIGURATION_CHANGE")


def diff_baselines(previous: SecurityBaselineModel, current: SecurityBaselineModel) -> List[ParameterDrift]:
    """Parameter-level diff of two flattened baselines. Only returns
    entries where something actually changed (NO_CHANGE rows are dropped
    here, not by the caller, so callers never have to remember to filter)."""
    prev_flat = previous.flatten()
    cur_flat = current.flatten()
    drifts: List[ParameterDrift] = []
    for parameter in sorted(set(prev_flat) | set(cur_flat)):
        if parameter in _EXCLUDED_PARAMETERS:
            continue
        prev_value = prev_flat.get(parameter)
        cur_value = cur_flat.get(parameter)
        drift = classify_parameter(parameter, prev_value, cur_value)
        if drift.drift_type != "NO_CHANGE":
            drifts.append(drift)
    return drifts


async def _correlate_with_opa(previous: SecurityBaselineModel, current: SecurityBaselineModel,
                               drifts: List[ParameterDrift]) -> None:
    """Attaches authoritative before/after PASS/FAIL state from OPA onto
    each drift's `compliance_controls`, in place. Never raises -- a failed
    OPA call just leaves `compliance_state` unset on the affected entries
    (Part 5 correlation is enrichment; OPA's fail-closed behavior belongs
    to the scan pipeline, not to reporting on a drift that already
    happened)."""
    controlled = [d for d in drifts if d.compliance_controls]
    if not controlled:
        return
    try:
        result = await opa_service.evaluate_change(
            scan_id="drift-correlation",
            device={"vendor": current.device.vendor, "os": current.device.os,
                    "model": current.device.model, "hostname": current.device.hostname},
            vendor=current.device.vendor or "Unknown",
            framework="ALL",
            before_baseline=previous.flatten(),
            after_baseline=current.flatten(),
        )
    except Exception as e:  # noqa: BLE001 -- correlation is best-effort enrichment
        logger.warning("OPA drift correlation unavailable: %s", e)
        return

    by_control = {f["control_id"]: "FAIL" for f in result.get("newly_failing", [])}
    by_control.update({f["control_id"]: "PASS" for f in result.get("newly_passing", [])})
    for f in result.get("unchanged", []):
        by_control.setdefault(f["control_id"], f.get("result"))

    for drift in controlled:
        states = {cid: by_control[cid] for cid in drift.compliance_controls if cid in by_control}
        if states:
            # One representative state pair for the finding; per-control
            # detail is still recoverable from `compliance_controls` + a
            # fresh OPA query if ever needed.
            newly_failing_ids = {f["control_id"] for f in result.get("newly_failing", [])}
            newly_passing_ids = {f["control_id"] for f in result.get("newly_passing", [])}
            if set(drift.compliance_controls) & newly_failing_ids:
                drift.compliance_state = {"previous": "PASS", "current": "FAIL"}
            elif set(drift.compliance_controls) & newly_passing_ids:
                drift.compliance_state = {"previous": "FAIL", "current": "PASS"}


async def record_security_drift(
    db: Session, tenant_id: str, device_id: str, previous_scan: Optional[Scan], current_scan: Scan,
    correlate_opa: bool = True,
) -> List[SecurityDriftFinding]:
    """Diffs `current_scan.baseline_json` against `previous_scan` (if any)
    and persists one SecurityDriftFinding per changed parameter. Returns
    an empty list (no rows persisted) when there's no previous scan to
    compare against -- a device's first-ever baseline is not drift."""
    if previous_scan is None or not previous_scan.baseline_json or not current_scan.baseline_json:
        return []

    previous = SecurityBaselineModel.model_validate(previous_scan.baseline_json)
    current = SecurityBaselineModel.model_validate(current_scan.baseline_json)
    drifts = diff_baselines(previous, current)
    if not drifts:
        return []

    if correlate_opa:
        await _correlate_with_opa(previous, current, drifts)

    rows: List[SecurityDriftFinding] = []
    for d in drifts:
        row = SecurityDriftFinding(
            tenant_id=tenant_id,
            device_id=device_id,
            previous_scan_id=previous_scan.id,
            current_scan_id=current_scan.id,
            baseline_parameter=d.parameter,
            previous_value=d.previous_value,
            current_value=d.current_value,
            drift_type=d.drift_type,
            severity=d.severity,
            compliance_controls=d.compliance_controls or None,
            evidence_reference=current_scan.raw_config_path,
            detected_at=datetime.utcnow(),
            status="OPEN",
        )
        db.add(row)
        rows.append(row)
    db.commit()
    for row in rows:
        db.refresh(row)
    return rows


def to_dict(finding: SecurityDriftFinding) -> dict:
    return {
        "drift_id": finding.drift_id,
        "tenant_id": finding.tenant_id,
        "device_id": finding.device_id,
        "previous_scan_id": finding.previous_scan_id,
        "current_scan_id": finding.current_scan_id,
        "baseline_parameter": finding.baseline_parameter,
        "previous_value": finding.previous_value,
        "current_value": finding.current_value,
        "drift_type": finding.drift_type,
        "severity": finding.severity,
        "compliance_controls": finding.compliance_controls or [],
        "evidence_reference": finding.evidence_reference,
        "detected_at": finding.detected_at.isoformat() if finding.detected_at else None,
        "status": finding.status,
    }