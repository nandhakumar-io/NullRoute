"""
Correlation layer: the single place the final PASS/REVIEW/BLOCK decision is
produced, per the fixed precedence in the problem statement (section 9):

    SYNTAX ERROR                        -> BLOCK
    OPA CRITICAL FAIL                   -> BLOCK
    BATFISH CRITICAL SECURITY VIOLATION -> BLOCK
    OPA REVIEW                          -> REVIEW
    BATFISH UNSUPPORTED (if required)   -> REVIEW
    RISK HIGH/CRITICAL                  -> REVIEW/BLOCK (configurable)
    everything passes                   -> PASS

An AI result is never a legal input to this function — there is no
parameter for one. Batfish is optional (this deployment phase doesn't wire
batfish_service.py yet): when omitted, this function neither treats that as
a violation nor as a pass — it just doesn't contribute to the decision, and
the "batfish_status" field is explicit about that so nothing downstream can
mistake silence for a clean bill of health (RULE 13).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.services.opa_service import OPADecision
from app.services.risk_engine import RiskResult

BATFISH_REQUIRED = os.getenv("BATFISH_REQUIRED", "false").strip().lower() == "true"

# Once risk crosses these thresholds it can escalate the final decision even
# if OPA alone only said REVIEW. Configurable rather than hardcoded because
# different deployments may want risk to only ever *inform*, not escalate.
RISK_BLOCK_THRESHOLD = int(os.getenv("RISK_BLOCK_THRESHOLD", "90"))
RISK_REVIEW_THRESHOLD = int(os.getenv("RISK_REVIEW_THRESHOLD", "50"))

VALID_BATFISH_STATUSES = (
    "BATFISH_PASS", "BATFISH_FAIL", "BATFISH_UNSUPPORTED",
    "BATFISH_UNAVAILABLE", "BATFISH_ERROR", "NOT_INTEGRATED",
)


@dataclass
class ComplianceDecision:
    decision: str  # PASS | REVIEW | BLOCK
    reason: str
    syntax_status: str
    opa_status: str
    batfish_status: str
    risk_score: int
    risk_level: str
    contributing: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "syntax_status": self.syntax_status,
            "opa_status": self.opa_status,
            "batfish_status": self.batfish_status,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "contributing": self.contributing,
        }


def correlate(
    syntax_ok: bool,
    opa_decision: OPADecision,
    risk: RiskResult,
    batfish_status: str = "NOT_INTEGRATED",
    batfish_critical_violation: bool = False,
    syntax_error_detail: Optional[str] = None,
) -> ComplianceDecision:
    if batfish_status not in VALID_BATFISH_STATUSES:
        raise ValueError(f"Unknown batfish_status: {batfish_status!r}")

    contributing: List[str] = []

    # 1. Syntax errors block outright — nothing downstream can be trusted.
    if not syntax_ok:
        return ComplianceDecision(
            decision="BLOCK",
            reason=f"Configuration failed deterministic parsing: {syntax_error_detail or 'syntax error'}",
            syntax_status="SYNTAX_ERROR",
            opa_status=opa_decision.decision,
            batfish_status=batfish_status,
            risk_score=risk.risk_score,
            risk_level=risk.risk_level,
            contributing=["Syntax error short-circuits evaluation"],
        )

    # 2. OPA CRITICAL FAIL -> BLOCK (OPA_UNAVAILABLE also surfaces as BLOCK
    #    here because opa_service.fail_closed_decision() already encodes
    #    that as decision="BLOCK" per OPA_FAIL_MODE=block).
    if opa_decision.decision == "BLOCK":
        critical = [v for v in opa_decision.violations if v.get("severity") == "CRITICAL"]
        contributing.append(f"OPA BLOCK ({len(critical)} CRITICAL violation(s))")
        return ComplianceDecision(
            decision="BLOCK", reason="OPA policy evaluation returned BLOCK.",
            syntax_status="OK", opa_status=opa_decision.decision, batfish_status=batfish_status,
            risk_score=risk.risk_score, risk_level=risk.risk_level, contributing=contributing,
        )

    # 3. Batfish CRITICAL behavioral violation -> BLOCK. Only meaningful
    #    once batfish_service.py is wired; today this is always False.
    if batfish_status == "BATFISH_FAIL" and batfish_critical_violation:
        contributing.append("Batfish CRITICAL behavioral violation")
        return ComplianceDecision(
            decision="BLOCK", reason="Batfish detected a CRITICAL network-behavior violation.",
            syntax_status="OK", opa_status=opa_decision.decision, batfish_status=batfish_status,
            risk_score=risk.risk_score, risk_level=risk.risk_level, contributing=contributing,
        )

    # 4. Risk CRITICAL band can independently escalate to BLOCK.
    if risk.risk_score >= RISK_BLOCK_THRESHOLD:
        contributing.append(f"Risk score {risk.risk_score} >= BLOCK threshold {RISK_BLOCK_THRESHOLD}")
        return ComplianceDecision(
            decision="BLOCK", reason=f"Deterministic risk score {risk.risk_score} exceeds the BLOCK threshold.",
            syntax_status="OK", opa_status=opa_decision.decision, batfish_status=batfish_status,
            risk_score=risk.risk_score, risk_level=risk.risk_level, contributing=contributing,
        )

    review_reasons: List[str] = []
    if opa_decision.decision == "REVIEW":
        review_reasons.append("OPA policy evaluation returned REVIEW.")
    if batfish_status == "BATFISH_UNSUPPORTED" and BATFISH_REQUIRED:
        review_reasons.append("Batfish behavioral analysis is required by policy but unsupported for this vendor/feature.")
    if batfish_status in ("BATFISH_UNAVAILABLE", "BATFISH_ERROR") and BATFISH_REQUIRED:
        review_reasons.append(f"Batfish is required by policy but returned {batfish_status}.")
    if risk.risk_score >= RISK_REVIEW_THRESHOLD:
        review_reasons.append(f"Risk score {risk.risk_score} >= REVIEW threshold {RISK_REVIEW_THRESHOLD}.")

    if review_reasons:
        contributing.extend(review_reasons)
        return ComplianceDecision(
            decision="REVIEW", reason=" ".join(review_reasons),
            syntax_status="OK", opa_status=opa_decision.decision, batfish_status=batfish_status,
            risk_score=risk.risk_score, risk_level=risk.risk_level, contributing=contributing,
        )

    contributing.append("OPA PASS, no unresolved risk/behavioral escalation")
    return ComplianceDecision(
        decision="PASS", reason="All deterministic checks passed.",
        syntax_status="OK", opa_status=opa_decision.decision, batfish_status=batfish_status,
        risk_score=risk.risk_score, risk_level=risk.risk_level, contributing=contributing,
    )
