"""Blast radius for a proposed ChangeRequest -- the three questions a
reviewer actually has to answer before approving a commit:

    1. Does this config turn on something dangerous that wasn't on before?
       (new vulnerability exposure)
    2. Does it break a compliance control?      (OPA / Batfish violations)
    3. Does it cut something off the network?   (reachability severance)

Everything here is DERIVED from analysis this codebase already ran at
change-request validation time (services/change_request_service.py:
`validation_detail.opa_findings`, `validation_detail.batfish_findings`,
and `snapshot_diff` from `batfish_service.compare_network_snapshots`).

RULE 11/13: this module is NOT a second compliance authority. It never
re-runs OPA, never re-runs Batfish, and never computes its own PASS/FAIL
verdict -- it reads the verdicts already recorded on the ChangeRequest and
reshapes them for the topology canvas. The one thing it computes directly
is the protocol-exposure scan in `_protocol_exposure()`, which is a
lexical diff of the two config texts and is reported as `source:
"config_diff"` so it is never confused with a Batfish dataplane result.

Fidelity: when the underlying analysis didn't run (Batfish disabled, no
prior config to diff against, validation errored), the corresponding
section reports `status: "NOT_ANALYZED"` with a reason. It never reports
an empty list as "no risk found" -- "we didn't look" and "we looked and
found nothing" are different answers, and conflating them is how a
reviewer approves a lockout.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

from app.models.db import ChangeRequest, Device

logger = logging.getLogger("blast_radius_service")


# Protocols/settings whose *introduction* materially widens attack surface.
# Each entry: (regex, label, severity, why). Matched against config lines
# present in PROPOSED but absent from CURRENT.
_RISKY_PROTOCOL_PATTERNS: List[tuple] = [
    (
        re.compile(r"(?i)^\s*transport\s+input\s+.*\btelnet\b"),
        "Telnet enabled on VTY lines",
        "CRITICAL",
        "Telnet transmits credentials in cleartext. Any observer on-path recovers the login.",
    ),
    (
        re.compile(r"(?i)^\s*(no\s+)?ip\s+telnet\b(?!.*\bdisable\b)"),
        "Telnet service enabled",
        "CRITICAL",
        "Cleartext management protocol reachable on the device.",
    ),
    (
        re.compile(r"(?i)^\s*ip\s+http\s+server\s*$"),
        "HTTP management server enabled (non-TLS)",
        "HIGH",
        "Unencrypted web management exposes session tokens and credentials.",
    ),
    (
        re.compile(r"(?i)^\s*snmp-server\s+community\s+\S+"),
        "SNMP v1/v2c community string configured",
        "HIGH",
        "v1/v2c community strings are cleartext and act as a shared password.",
    ),
    (
        re.compile(r"(?i)^\s*ip\s+ssh\s+version\s+1\b"),
        "SSH version 1 permitted",
        "HIGH",
        "SSHv1 has known integrity weaknesses and is deprecated.",
    ),
    (
        re.compile(r"(?i)^\s*no\s+service\s+password-encryption\b"),
        "Password encryption disabled",
        "MEDIUM",
        "Stored passwords become recoverable from the configuration file.",
    ),
    (
        re.compile(r"(?i)^\s*enable\s+password\s+(?!secret)"),
        "Enable password stored with reversible encoding",
        "MEDIUM",
        "Type-7 encoding is trivially reversible; `enable secret` should be used.",
    ),
    (
        re.compile(r"(?i)^\s*permit\s+ip\s+any\s+any\b"),
        "Permit-any-any ACL entry introduced",
        "HIGH",
        "Defeats the purpose of the ACL it's attached to.",
    ),
    (
        re.compile(r"(?i)^\s*no\s+(ip\s+)?access-group\b"),
        "Access-group binding removed from an interface",
        "HIGH",
        "Traffic that was previously filtered is no longer inspected.",
    ),
]

# Lines whose REMOVAL is itself the risk (controls being switched off).
_PROTECTIVE_REMOVAL_PATTERNS: List[tuple] = [
    (
        re.compile(r"(?i)^\s*ip\s+access-group\b"),
        "Interface ACL binding removed",
        "HIGH",
        "An interface that was filtered is now unfiltered.",
    ),
    (
        re.compile(r"(?i)^\s*service\s+password-encryption\b"),
        "Password encryption removed",
        "MEDIUM",
        "Previously-encrypted stored passwords become readable.",
    ),
    (
        re.compile(r"(?i)^\s*login\s+(local|authentication)\b"),
        "VTY authentication requirement removed",
        "CRITICAL",
        "Management access may no longer require credentials.",
    ),
]


def _normalized_lines(config: Optional[str]) -> List[str]:
    if not config:
        return []
    out = []
    for raw in config.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("!") or stripped.startswith("#"):
            continue
        out.append(line)
    return out


def _protocol_exposure(
    current_config: Optional[str], proposed_config: Optional[str]
) -> Dict[str, Any]:
    """Lexical diff for newly-enabled dangerous protocols and newly-removed
    protective controls. Reported as source="config_diff" -- this is a text
    comparison, NOT a Batfish dataplane verdict."""
    if proposed_config is None:
        return {
            "status": "NOT_ANALYZED",
            "reason": "Proposed configuration could not be retrieved from object storage.",
            "items": [],
        }
    if current_config is None:
        return {
            "status": "NOT_ANALYZED",
            "reason": (
                "No prior configuration is archived for this device, so "
                "newly-introduced settings cannot be distinguished from "
                "pre-existing ones."
            ),
            "items": [],
        }

    current_lines = set(_normalized_lines(current_config))
    proposed_lines = _normalized_lines(proposed_config)

    added = [l for l in proposed_lines if l not in current_lines]
    proposed_set = set(proposed_lines)
    removed = [l for l in _normalized_lines(current_config) if l not in proposed_set]

    items: List[Dict[str, Any]] = []
    for line in added:
        for pattern, label, severity, why in _RISKY_PROTOCOL_PATTERNS:
            if pattern.search(line):
                items.append({
                    "label": label, "severity": severity, "why": why,
                    "change": "added", "config_line": line.strip(),
                    "source": "config_diff",
                })
                break

    for line in removed:
        for pattern, label, severity, why in _PROTECTIVE_REMOVAL_PATTERNS:
            if pattern.search(line):
                items.append({
                    "label": label, "severity": severity, "why": why,
                    "change": "removed", "config_line": line.strip(),
                    "source": "config_diff",
                })
                break

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    items.sort(key=lambda i: order.get(i["severity"], 9))

    return {
        "status": "ANALYZED",
        "reason": None,
        "items": items,
        "added_line_count": len(added),
        "removed_line_count": len(removed),
    }


def _compliance_violations(cr: ChangeRequest) -> Dict[str, Any]:
    """OPA + Batfish findings as already recorded at validation time."""
    detail = cr.validation_detail or {}
    if not detail:
        return {
            "status": "NOT_ANALYZED",
            "reason": (
                "Validation has not completed for this change request "
                f"(syntax_status={cr.syntax_status!r}, status={cr.status!r})."
            ),
            "items": [],
        }

    items: List[Dict[str, Any]] = []
    for f in detail.get("opa_findings") or []:
        if not isinstance(f, dict):
            continue
        items.append({
            "label": f.get("title") or f.get("control_id") or "OPA policy violation",
            "control_id": f.get("control_id"),
            "severity": (f.get("severity") or "MEDIUM").upper(),
            "why": f.get("detail") or f.get("message"),
            "source": "opa",
        })
    for f in detail.get("batfish_findings") or []:
        if not isinstance(f, dict):
            continue
        items.append({
            "label": f.get("title") or f.get("control_id") or "Batfish behavioral violation",
            "control_id": f.get("control_id"),
            "severity": (f.get("severity") or "MEDIUM").upper(),
            "why": f.get("detail") or f.get("message"),
            "source": "batfish",
        })

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    items.sort(key=lambda i: order.get(i["severity"], 9))

    return {
        "status": "ANALYZED",
        "reason": None,
        "items": items,
        "opa_decision": cr.opa_decision,
        "batfish_status": cr.batfish_status,
    }


def _reachability_severance(cr: ChangeRequest) -> Dict[str, Any]:
    """Flows that were REACHABLE before the change and are not after, plus
    nodes that disappear from the proposed snapshot entirely.

    Read straight off `snapshot_diff` as produced by
    batfish_service.compare_network_snapshots(). Never recomputed here."""
    diff = cr.snapshot_diff or {}
    status = diff.get("status")

    if not diff:
        return {
            "status": "NOT_ANALYZED",
            "reason": (
                "No CURRENT-vs-PROPOSED snapshot comparison was run. This happens "
                "when Batfish is disabled, the vendor is unsupported, or the device "
                "has no previously-archived configuration to compare against."
            ),
            "items": [], "isolated_nodes": [],
        }
    if status in ("BATFISH_ERROR", "BATFISH_UNSUPPORTED", "NOT_INTEGRATED"):
        return {
            "status": "NOT_ANALYZED",
            "reason": (
                f"Snapshot comparison did not produce a dataplane result "
                f"(status={status}). {diff.get('detail') or ''}".strip()
            ),
            "items": [], "isolated_nodes": [],
        }

    items: List[Dict[str, Any]] = []
    isolated: List[str] = []

    for flow in diff.get("flow_diffs") or []:
        if not isinstance(flow, dict):
            continue
        before = str(flow.get("before") or flow.get("current") or "").upper()
        after = str(flow.get("after") or flow.get("proposed") or "").upper()
        # Only severance (was reachable, now not). Newly-permitted flows are
        # an exposure concern, surfaced by the compliance/OPA section.
        if "REACH" in before and "REACH" not in after:
            items.append({
                "label": f"{flow.get('source') or '?'} → {flow.get('destination') or '?'}",
                "before": before, "after": after,
                "severity": "CRITICAL" if flow.get("management") else "HIGH",
                "why": flow.get("detail") or "Flow reachable before the change, not after.",
                "source": "batfish",
            })

    node_delta = diff.get("node_delta") or {}
    for node in node_delta.get("removed") or []:
        isolated.append(node)
        items.append({
            "label": f"Node '{node}' absent from proposed snapshot",
            "before": "PRESENT", "after": "ABSENT",
            "severity": "CRITICAL",
            "why": "Device no longer parses into the network model after this change.",
            "source": "batfish",
        })

    diff_reach = diff.get("differential_reachability") or {}

    return {
        "status": "ANALYZED",
        "reason": None,
        "items": items,
        "isolated_nodes": isolated,
        "changed_flow_count": diff_reach.get("changed_flow_count", len(items)),
        "route_delta": diff.get("route_delta") or {},
    }


def _node_states(
    cr: ChangeRequest,
    device: Optional[Device],
    severance: Dict[str, Any],
    compliance: Dict[str, Any],
    exposure: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Per-device risk state consumed by the topology canvas to colour nodes.

    `state` is one of: "isolated" (red, pulsing), "violating" (amber,
    pulsing), "exposed" (amber), "ok" (normal), "unknown" (not analyzed).
    """
    states: List[Dict[str, Any]] = []
    target_id = cr.device_id
    hostname = device.hostname if device else None

    reasons: List[str] = []
    state = "ok"

    unanalyzed = [
        s for s in (severance, compliance, exposure) if s.get("status") == "NOT_ANALYZED"
    ]

    if severance.get("isolated_nodes") or any(
        i.get("severity") == "CRITICAL" for i in severance.get("items", [])
    ):
        state = "isolated"
        reasons.append("Projected to lose reachability after this change.")
    elif any(i.get("severity") in ("CRITICAL", "HIGH") for i in compliance.get("items", [])):
        state = "violating"
        reasons.append("Projected to violate one or more compliance controls.")
    elif any(i.get("severity") in ("CRITICAL", "HIGH") for i in exposure.get("items", [])):
        state = "exposed"
        reasons.append("Introduces a high-risk protocol or removes a protective control.")
    elif len(unanalyzed) == 3:
        state = "unknown"
        reasons.append("No pre/post analysis is available for this change request.")

    states.append({
        "device_id": target_id,
        "hostname": hostname,
        "state": state,
        "reasons": reasons,
        "is_change_target": True,
    })

    # Nodes Batfish named as removed but that aren't the CR's own device --
    # matched by hostname, since the snapshot model is hostname-keyed.
    for node in severance.get("isolated_nodes", []):
        if hostname and node == hostname:
            continue
        states.append({
            "device_id": None,
            "hostname": node,
            "state": "isolated",
            "reasons": ["Absent from the proposed snapshot."],
            "is_change_target": False,
        })

    return states


def build(
    cr: ChangeRequest,
    device: Optional[Device],
    current_config: Optional[str],
    proposed_config: Optional[str],
) -> Dict[str, Any]:
    """Assemble the full blast-radius payload for one ChangeRequest."""
    exposure = _protocol_exposure(current_config, proposed_config)
    compliance = _compliance_violations(cr)
    severance = _reachability_severance(cr)
    node_states = _node_states(cr, device, severance, compliance, exposure)

    all_items = (
        exposure.get("items", []) + compliance.get("items", []) + severance.get("items", [])
    )
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for i in all_items:
        sev = i.get("severity", "MEDIUM")
        if sev in counts:
            counts[sev] += 1

    analyzed_sections = [
        name for name, sec in
        (("vulnerability_exposure", exposure), ("compliance_violations", compliance),
         ("reachability_severance", severance))
        if sec.get("status") == "ANALYZED"
    ]

    return {
        "change_request_id": cr.id,
        "device_id": cr.device_id,
        "hostname": device.hostname if device else None,
        "cr_status": cr.status,
        "final_decision": cr.final_decision,
        "final_reason": cr.final_reason,
        "risk_score": cr.risk_score,
        "risk_level": cr.risk_level,
        # The three requested sections.
        "vulnerability_exposure": exposure,
        "compliance_violations": compliance,
        "reachability_severance": severance,
        # Canvas colouring.
        "node_states": node_states,
        "summary": {
            "total_items": len(all_items),
            "severity_counts": counts,
            "analyzed_sections": analyzed_sections,
            # True when NOTHING could be analyzed -- the UI must say "unknown",
            # not "safe".
            "fully_unanalyzed": len(analyzed_sections) == 0,
        },
    }