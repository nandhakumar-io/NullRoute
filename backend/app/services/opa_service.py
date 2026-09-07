"""
OPA integration — the authoritative deterministic policy engine.

CRITICAL DESIGN RULE (problem statement, rules 2 and 14): OPA decides
PASS/FAIL/REVIEW/BLOCK for the deterministic-policy layer. If OPA is
unreachable or returns something we can't parse, we do NOT silently fall
back to a Python re-implementation of the rules — we fail closed
(OPA_UNAVAILABLE -> BLOCK or REVIEW, per OPA_FAIL_MODE) and surface that
fact all the way to the UI and the evidence record.

This module talks to OPA's REST Data API at:
    POST {OPA_URL}/v1/data/compliance/evaluate

against the policy bundle in policies/ (see policies/baseline.rego for the
decision entrypoint and policies/common, policies/security, policies/
frameworks, policies/network, policies/metadata for the rest of the bundle).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx

OPA_URL = os.getenv("OPA_URL", "http://opa:8181")
OPA_TIMEOUT = float(os.getenv("OPA_TIMEOUT", "5.0"))
OPA_FAIL_MODE = os.getenv("OPA_FAIL_MODE", "block").strip().lower()  # "block" | "review"

if OPA_FAIL_MODE not in ("block", "review"):
    raise ValueError(f"OPA_FAIL_MODE must be 'block' or 'review', got {OPA_FAIL_MODE!r}")

# Parameter-name / key-name fragments that must never leave the backend and
# reach OPA's input document. Applied case-insensitively against every
# dotted key in the flattened baseline (see sanitize_baseline()).
_SENSITIVE_KEY_FRAGMENTS = (
    "password", "secret", "token", "community_string_value", "private_key",
    "ssh_key", "api_key", "apikey", "credential", "passphrase", "bearer",
)


class OPAUnavailableError(Exception):
    """Raised when OPA cannot be reached or returns a non-2xx / network error."""


class OPAMalformedResponseError(Exception):
    """Raised when OPA responds but the payload doesn't match the expected shape."""


@dataclass
class OPADecision:
    decision: str  # PASS | REVIEW | BLOCK | OPA_UNAVAILABLE
    findings: List[Dict[str, Any]] = field(default_factory=list)
    violations: List[Dict[str, Any]] = field(default_factory=list)
    evaluated_controls: List[str] = field(default_factory=list)
    policy_version: str = "unknown"
    decision_id: str = ""
    source: str = "opa"  # "opa" | "fail_closed"
    raw: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision,
            "findings": self.findings,
            "violations": self.violations,
            "evaluated_controls": self.evaluated_controls,
            "policy_version": self.policy_version,
            "decision_id": self.decision_id,
            "source": self.source,
        }


def sanitize_baseline(flattened: Dict[str, Any]) -> Dict[str, Any]:
    """Strip anything that looks like a secret before it is ever sent to OPA.

    OPA input must never contain passwords, SNMP community *values*, SSH
    keys, API tokens, Keycloak tokens, or OpenBao secrets (problem statement
    section 3). The Security Baseline Model only stores booleans/enums about
    *whether* a secret-bearing feature is configured (e.g.
    `snmp.community_strings_default: bool`), never the secret value itself —
    this is a defense-in-depth filter in case extra_parameters/AI
    normalization ever introduces a literal secret value into the baseline.
    """
    import datetime as _dt

    clean: Dict[str, Any] = {}
    for key, value in flattened.items():
        lowered = key.lower()
        if lowered.startswith("password_policy."):
            clean[key] = value
            continue
        elif any(frag in lowered for frag in _SENSITIVE_KEY_FRAGMENTS):
            continue
        # OPA input must be valid JSON; datetimes (e.g. normalized_at) are
        # not JSON-serializable by default, so normalize to ISO 8601 here
        # rather than letting httpx raise deep inside the request builder.
        if isinstance(value, (_dt.datetime, _dt.date)):
            value = value.isoformat()
        clean[key] = value
    return clean


def _decision_id(policy_version: str, scan_id: str, findings: List[Dict[str, Any]]) -> str:
    """Deterministic decision id: same inputs -> same id, so re-running an
    unchanged scan against an unchanged policy is idempotent and auditable."""
    payload = json.dumps(
        {"policy_version": policy_version, "scan_id": scan_id, "findings": findings},
        sort_keys=True, default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


def normalize_opa_result(raw: Dict[str, Any], scan_id: str) -> OPADecision:
    """Turn the raw `/v1/data/compliance/evaluate` JSON body into an
    OPADecision, validating the shape we depend on. Raises
    OPAMalformedResponseError rather than guessing at defaults for a
    security-critical decision."""
    result = raw.get("result")
    if not isinstance(result, dict):
        raise OPAMalformedResponseError("OPA response missing 'result' object")

    decision = result.get("decision")
    findings = result.get("findings")
    if decision not in ("PASS", "REVIEW", "BLOCK"):
        raise OPAMalformedResponseError(f"OPA returned an unrecognized decision: {decision!r}")
    if not isinstance(findings, list):
        raise OPAMalformedResponseError("OPA response 'findings' must be a list")

    violations = result.get("violations", [f for f in findings if f.get("result") == "FAIL"])
    evaluated_controls = result.get("evaluated_controls", [f.get("control_id") for f in findings])
    policy_version = result.get("policy_version", "unknown")

    return OPADecision(
        decision=decision,
        findings=findings,
        violations=violations,
        evaluated_controls=evaluated_controls,
        policy_version=policy_version,
        decision_id=_decision_id(policy_version, scan_id, findings),
        source="opa",
        raw=raw,
    )


def fail_closed_decision(scan_id: str, reason: str) -> OPADecision:
    """Never silently fall back to the Python rule engine (RULE 14). Instead
    produce an explicit OPA_UNAVAILABLE decision that the correlation layer
    turns into BLOCK or REVIEW per OPA_FAIL_MODE, and that is visible as such
    in the UI and evidence record."""
    decision = "BLOCK" if OPA_FAIL_MODE == "block" else "REVIEW"
    finding = {
        "control_id": "OPA-AVAILABILITY",
        "framework": "SYSTEM",
        "title": "OPA policy engine unavailable",
        "severity": "CRITICAL",
        "parameter": None,
        "expected": "OPA reachable",
        "actual": "OPA_UNAVAILABLE",
        "result": "FAIL",
        "reason": reason,
        "remediation": "Restore connectivity to the OPA service; no policy decision could be computed.",
    }
    return OPADecision(
        decision=decision,
        findings=[finding],
        violations=[finding],
        evaluated_controls=[],
        policy_version="unknown",
        decision_id=_decision_id("unknown", scan_id, [finding]),
        source="fail_closed",
        raw=None,
    )


async def health_check() -> Dict[str, Any]:
    """GET {OPA_URL}/health — used by the UI's OPA status indicator."""
    start = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=OPA_TIMEOUT) as client:
            resp = await client.get(f"{OPA_URL}/health", params={"bundle": "true"})
        latency_ms = round((time.monotonic() - start) * 1000, 1)
        return {"healthy": resp.status_code == 200, "latency_ms": latency_ms, "status_code": resp.status_code}
    except Exception as e:
        return {"healthy": False, "latency_ms": None, "error": str(e)}


async def get_policy_version() -> str:
    """GET {OPA_URL}/v1/data/compliance/metadata/version"""
    try:
        async with httpx.AsyncClient(timeout=OPA_TIMEOUT) as client:
            resp = await client.get(f"{OPA_URL}/v1/data/compliance/metadata/version")
        resp.raise_for_status()
        return resp.json().get("result", "unknown")
    except Exception:
        return "unknown"


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (datetime,)):
        return value.isoformat()
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    if isinstance(value, tuple):
        return [_json_safe(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if hasattr(value, "model_dump"):
        return _json_safe(value.model_dump())
    if hasattr(value, "dict"):
        return _json_safe(value.dict())
    if isinstance(value, set):
        return [_json_safe(v) for v in sorted(value, key=str)]
    return str(value)


async def _post_evaluate(input_doc: Dict[str, Any]) -> Dict[str, Any]:
    try:
        payload = _json_safe(input_doc)
        print("OPA_IN_PAYLOAD:", json.dumps(payload))
        async with httpx.AsyncClient(timeout=OPA_TIMEOUT) as client:
            resp = await client.post(f"{OPA_URL}/v1/data/compliance/evaluate", json={"input": payload})
        resp.raise_for_status()
        print("OPA_OUT_RAW:", resp.text[:1000])
        return resp.json()
    except httpx.HTTPError as e:
        raise OPAUnavailableError(str(e)) from e
    except json.JSONDecodeError as e:
        raise OPAMalformedResponseError(f"OPA response was not valid JSON: {e}") from e


async def evaluate_baseline(
    scan_id: str,
    device: Dict[str, Any],
    vendor: str,
    framework: str,
    flattened_baseline: Dict[str, Any],
    metadata: Optional[Dict[str, Any]] = None,
) -> OPADecision:
    """Evaluate a full baseline against OPA. Raises OPAUnavailableError /
    OPAMalformedResponseError on failure — callers MUST catch these and use
    fail_closed_decision(), never a Python re-implementation, per RULE 14."""
    sanitized = sanitize_baseline(flattened_baseline)
    input_doc = {
        "scan_id": scan_id,
        "device": device,
        "vendor": vendor,
        "framework": framework or "ALL",
        "baseline": sanitized,
        "metadata": metadata or {},
    }
    raw = await _post_evaluate(input_doc)
    return normalize_opa_result(raw, scan_id)


async def evaluate_security_policy(
    scan_id: str, device: Dict[str, Any], vendor: str, framework: str,
    flattened_baseline: Dict[str, Any], metadata: Optional[Dict[str, Any]] = None,
) -> OPADecision:
    """Alias for evaluate_baseline — kept as a distinct name because the
    problem statement lists it as a required entrypoint; today it evaluates
    the same policy set. Split out if/when policy scoping needs to diverge
    (e.g. a narrower "security policy only" bundle)."""
    return await evaluate_baseline(scan_id, device, vendor, framework, flattened_baseline, metadata)


async def evaluate_control(
    scan_id: str, control_id: str, device: Dict[str, Any], vendor: str,
    flattened_baseline: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Evaluate the full baseline and return just the finding for one
    control_id. (OPA doesn't expose a cheaper single-control endpoint given
    the current bundle shape, so this evaluates everything and filters —
    fine at this scale; revisit if the control catalog grows large.)"""
    decision = await evaluate_baseline(scan_id, device, vendor, "ALL", flattened_baseline)
    for f in decision.findings:
        if f.get("control_id") == control_id:
            return f
    return None


async def evaluate_change(
    scan_id: str, device: Dict[str, Any], vendor: str, framework: str,
    before_baseline: Dict[str, Any], after_baseline: Dict[str, Any],
) -> Dict[str, Any]:
    """Policy-level (static) comparison of a candidate change against the
    current baseline: which controls newly fail, which newly pass, which are
    unchanged. This is NOT the same as Batfish's network-behavior change
    analysis (reachability before/after) — it's the deterministic-policy
    equivalent, useful even when Batfish is unavailable/unsupported for a
    vendor."""
    before = await evaluate_baseline(f"{scan_id}-before", device, vendor, framework, before_baseline)
    after = await evaluate_baseline(f"{scan_id}-after", device, vendor, framework, after_baseline)

    before_by_id = {f["control_id"]: f for f in before.findings}
    after_by_id = {f["control_id"]: f for f in after.findings}

    newly_failing, newly_passing, unchanged = [], [], []
    for control_id, after_finding in after_by_id.items():
        before_finding = before_by_id.get(control_id)
        before_result = before_finding["result"] if before_finding else None
        after_result = after_finding["result"]
        if before_result != "FAIL" and after_result == "FAIL":
            newly_failing.append(after_finding)
        elif before_result == "FAIL" and after_result != "FAIL":
            newly_passing.append(after_finding)
        else:
            unchanged.append(after_finding)

    return {
        "scan_id": scan_id,
        "before_decision": before.decision,
        "after_decision": after.decision,
        "newly_failing": newly_failing,
        "newly_passing": newly_passing,
        "unchanged": unchanged,
    }
