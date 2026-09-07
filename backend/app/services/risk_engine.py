"""
Deterministic risk engine.

RULE 10 (problem statement): risk must be deterministic, and the AI must
never directly choose risk_score. This module is pure, input -> output,
weighted-sum arithmetic — no LLM call anywhere in this file.

Inputs are OPA findings (always available) and, optionally, Batfish
behavioral findings (folded in once backend/app/services/batfish_service.py
exists — until then callers simply omit `batfish_findings` and this engine
scores on the OPA/static-policy signal alone, never fabricating a
network-behavior risk component it has no evidence for).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Points contributed per FAIL finding, by severity. Tuned so a single
# CRITICAL alone lands solidly in the CRITICAL risk band, matching the
# demo scenario (telnet + default SNMP + guest->mgmt reachability => CRITICAL).
_SEVERITY_WEIGHT = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 3}

# A confirmed Batfish behavioral violation (e.g. guest -> management
# reachable) is weighted heavily: it's proof of an *actual* exploitable
# path, not just a misconfigured setting.
_BATFISH_VIOLATION_WEIGHT = 35

_RISK_BANDS = (
    (75, "CRITICAL"),
    (50, "HIGH"),
    (25, "MEDIUM"),
    (0, "LOW"),
)


@dataclass
class RiskResult:
    risk_score: int
    risk_level: str
    contributing_factors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "contributing_factors": self.contributing_factors,
        }


def _risk_level(score: int) -> str:
    for threshold, level in _RISK_BANDS:
        if score >= threshold:
            return level
    return "LOW"  # unreachable, but keeps the function total


def calculate_risk(
    opa_findings: List[Dict[str, Any]],
    batfish_findings: Optional[List[Dict[str, Any]]] = None,
    unknown_syntax_count: int = 0,
    affected_device_count: int = 1,
) -> RiskResult:
    """
    opa_findings: full finding list from an OPADecision (PASS/FAIL/NOT_APPLICABLE).
    batfish_findings: list of behavioral-violation dicts (severity, control_id, ...),
        or None if Batfish was not run for this scan — never treated as "no risk".
    unknown_syntax_count: lines the parser/AI could not confidently normalize;
        unresolved unknowns are themselves a (small, capped) risk contributor —
        never a compliance FAIL, just visibility that the picture is incomplete.
    affected_device_count: blast radius multiplier for fleet-wide findings
        (e.g. a shared SNMP community across many devices).
    """
    score = 0
    factors: List[str] = []

    fails = [f for f in opa_findings if f.get("result") == "FAIL"]
    for f in fails:
        weight = _SEVERITY_WEIGHT.get(f.get("severity"), 0)
        score += weight
        factors.append(f"{f.get('control_id')} ({f.get('severity')}) FAIL: +{weight}")

    if batfish_findings:
        for bf in batfish_findings:
            if bf.get("result") != "FAIL":
                continue
            weight = _BATFISH_VIOLATION_WEIGHT if bf.get("severity") == "CRITICAL" else _BATFISH_VIOLATION_WEIGHT // 2
            score += weight
            factors.append(f"Batfish {bf.get('control_id', bf.get('type', 'behavioral'))}: +{weight}")

    if unknown_syntax_count:
        unknown_penalty = min(unknown_syntax_count * 2, 15)  # capped; unknowns aren't proof of a problem
        score += unknown_penalty
        factors.append(f"{unknown_syntax_count} unresolved unknown configuration line(s): +{unknown_penalty}")

    if affected_device_count > 1:
        blast_multiplier = min(1 + 0.1 * (affected_device_count - 1), 2.0)
        pre_multiplier_score = score
        score = round(score * blast_multiplier)
        factors.append(
            f"Blast radius x{blast_multiplier:.2f} across {affected_device_count} devices "
            f"({pre_multiplier_score} -> {score})"
        )

    score = max(0, min(100, round(score)))
    return RiskResult(risk_score=score, risk_level=_risk_level(score), contributing_factors=factors)
