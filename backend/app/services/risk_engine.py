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

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://ollama:11434")
LLM_MODEL = os.getenv("OLLAMA_MODEL", "llama")

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


# ---------------------------------------------------------------------------
# Drift risk analysis.
#
# Same RULE 10 boundary as calculate_risk() above: risk_score here is pure
# weighted-sum arithmetic over pattern matches against the diff text -- no
# LLM ever chooses it. An LLM (Ollama, same pattern as
# app.services.remediation_service) is optionally used only for
# `ai_summary`, a human-readable explanation of what changed -- and if that
# call fails or is unavailable, we fall back to a deterministic summary
# built from the same findings, so detect_drift() never breaks because the
# LLM is down.

# Security-relevant line patterns that can show up on either side of a
# unified diff. A pattern appearing on a "-" (removed) line usually means a
# protection was taken away (weighted heavier); the same pattern on a "+"
# (added) line usually means something risky was introduced. A handful of
# patterns are risky either way (e.g. a plaintext/weak secret appearing).
_DRIFT_PATTERNS: list[tuple[str, str, int, int]] = [
    # (regex, description, weight_if_removed, weight_if_added)
    (r"\bno\s+ip\s+access-group\b", "ACL removed from interface", 30, 0),
    (r"\baccess-list\s+\d+\s+deny\b", "ACL deny rule removed", 25, 0),
    (r"\bpermit\s+ip\s+any\s+any\b", "Overly permissive 'permit any any' rule added", 0, 30),
    (r"\btelnet\b", "Telnet (unencrypted management) present", 0, 25),
    (r"\bno\s+service\s+password-encryption\b", "Password encryption disabled", 0, 20),
    (r"^\s*enable\s+password\s+\S", "Weak 'enable password' (vs. secret) in use", 0, 20),
    (r"\bsnmp-server\s+community\s+\S+\s+rw\b", "Read-write SNMP community added", 0, 30),
    (r"\bno\s+aaa\b", "AAA authentication/accounting removed", 35, 0),
    (r"\bno\s+login\b", "Login requirement removed from a line", 25, 0),
    (r"\bno\s+logging\b", "Logging disabled", 15, 0),
    (r"\bno\s+ntp\s+authenticate\b", "NTP authentication disabled", 15, 0),
    (r"\bshutdown\b", "Interface administratively shut down", 10, 10),
    (r"\bno\s+shutdown\b", "Interface administratively enabled", 0, 5),
    (r"\bip\s+http\s+server\b", "Unencrypted HTTP management server enabled", 0, 15),
]

_MAX_PATTERN_SCORE = 100


@dataclass
class DriftAnalysis:
    risk_score: int
    findings: List[str] = field(default_factory=list)
    ai_summary: str = ""
    cli_diff: List[str] = field(default_factory=list)
    llm_applied: bool = False
    llm_error: Optional[str] = None


def _extract_cli_diff(diff_text: str) -> List[str]:
    """Just the changed CLI lines (no unified-diff headers/context), each
    still prefixed with its +/- so the caller can render it as a compact
    "what changed" list."""
    lines = []
    for line in diff_text.splitlines():
        if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
            continue
        if line.startswith("+") or line.startswith("-"):
            stripped = line[1:].strip()
            if stripped:
                lines.append(line)
    return lines


def _pattern_findings(diff_text: str) -> tuple[int, List[str]]:
    score = 0
    findings: List[str] = []
    for line in diff_text.splitlines():
        if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
            continue
        is_added = line.startswith("+")
        is_removed = line.startswith("-")
        if not (is_added or is_removed):
            continue
        content = line[1:]
        for pattern, description, weight_removed, weight_added in _DRIFT_PATTERNS:
            if not re.search(pattern, content, re.IGNORECASE):
                continue
            weight = weight_removed if is_removed else weight_added
            if weight <= 0:
                continue
            score += weight
            findings.append(f"{description} ({'removed' if is_removed else 'added'}): +{weight}")
    return score, findings


def _fallback_drift_summary(findings: List[str], added: int, removed: int) -> str:
    if not findings:
        return f"{added} line(s) added, {removed} line(s) removed. No significant risk patterns detected."
    top = "; ".join(f.split(" (+")[0] for f in findings[:5])
    return f"{added} line(s) added, {removed} line(s) removed. Notable changes: {top}."


def _llm_drift_summary(diff_text: str, findings: List[str]) -> tuple[Optional[str], Optional[str]]:
    """Best-effort natural-language summary of a config diff via the local
    Ollama model. Never used to set risk_score or severity -- purely
    explanatory text for a human reviewer. Returns (summary, error)."""
    try:
        findings_text = "\n".join(f"- {f}" for f in findings) or "- none flagged by pattern rules"
        prompt = (
            "Summarize this network device configuration drift for a security "
            "operator in 2-3 plain-English sentences. Do not invent facts not "
            "present in the diff.\n\n"
            f"Diff:\n{diff_text[:4000]}\n\nFlagged patterns:\n{findings_text}\n\n"
            "Output ONLY the summary text, no preamble, no markdown."
        )
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(
                f"{OLLAMA_HOST}/generate",
                json={"model": LLM_MODEL, "prompt": prompt, "stream": False},
            )
            resp.raise_for_status()
            text = resp.json().get("response", "").strip()
            if not text:
                return None, "LLM returned an empty response"
            return text, None
    except Exception as exc:  # noqa: BLE001 - any failure here is non-fatal
        return None, f"{type(exc).__name__}: {exc}"


def analyze_drift(
    live_config: str,
    baseline_config: str,
    diff_text: str,
    added: int,
    removed: int,
) -> DriftAnalysis:
    """Deterministically scores how risky a drifted config is (RULE 10:
    same weighted-rule philosophy as calculate_risk, just driven off diff
    patterns instead of OPA findings), and attaches a best-effort AI
    summary of the change on top.

    Called by app.services.advanced_drift_service.detect_drift().
    """
    pattern_score, findings = _pattern_findings(diff_text)

    # Small, capped contribution from sheer size of the change -- a huge
    # rewrite is inherently riskier to reason about even with no single
    # flagged pattern, but this should never dominate the pattern score.
    size_penalty = min((added + removed) // 10, 15)
    score = max(0, min(_MAX_PATTERN_SCORE, pattern_score + size_penalty))

    if not findings:
        findings = ["No significant risk patterns detected"]

    cli_diff = _extract_cli_diff(diff_text)

    summary, llm_error = _llm_drift_summary(diff_text, findings) if (added or removed) else (None, None)
    llm_applied = summary is not None
    if not summary:
        summary = _fallback_drift_summary(findings, added, removed)

    return DriftAnalysis(
        risk_score=score,
        findings=findings,
        ai_summary=summary,
        cli_diff=cli_diff,
        llm_applied=llm_applied,
        llm_error=llm_error,
    )
