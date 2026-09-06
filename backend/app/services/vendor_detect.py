"""Heuristic vendor/OS fingerprinting for uploaded configuration files.

This runs before parsing. Detection is weighted-evidence based rather than
first-match: every vendor has a table of (pattern, evidence label, weight)
signatures. All patterns are checked against every vendor, scores are
normalized against that vendor's maximum possible weight, and the
highest-scoring vendor wins IF it clears CONFIDENCE_THRESHOLD.

Falling below the threshold (or matching nothing) is not "pick the least-bad
guess" — it is reported as UNKNOWN_VENDOR / REVIEW so the config gets routed
to the full AI/RAG normalization path with no parser shortcuts, instead of
being silently mis-parsed against the wrong vendor's grammar.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

CONFIDENCE_THRESHOLD = 0.5

# (compiled pattern, evidence label, weight)
Signature = Tuple[re.Pattern, str, float]


def _sig(pattern: str, label: str, weight: float, flags: int = re.M) -> Signature:
    return (re.compile(pattern, flags), label, weight)


# Each vendor's signature list is independent — its own weights, its own
# evidence vocabulary. Adding a new detection heuristic for a vendor is a
# matter of appending a tuple here; the scoring/threshold logic below never
# has to change.
VENDOR_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "Cisco": {
        "os_family": "ios",
        "signatures": [
            _sig(r"^hostname\s+\S+", "hostname directive", 1.0),
            _sig(r"^interface\s+(GigabitEthernet|TenGigabitEthernet|FastEthernet|Loopback|Vlan)\S*", "interface naming convention", 2.0),
            _sig(r"^ip\s+access-list\b", "IOS access-list syntax", 1.5),
            _sig(r"^!\s*$", "IOS section delimiter ('!')", 0.5),
            _sig(r"^version\s+\d+\.\d+\b", "version command syntax", 1.5),
            _sig(r"^enable\s+secret\b", "IOS-specific directives", 1.0),
            _sig(r"^ip\s+ssh\s+version\s+\d", "IOS-specific directives", 1.0),
            _sig(r"^line\s+vty\b", "IOS-specific directives", 1.0),
            _sig(r"^spanning-tree\s+mode\b", "IOS-specific directives", 0.5),
        ],
    },
    "Arista": {
        "os_family": "eos",
        "signatures": [
            _sig(r"^hostname\s+\S+", "hostname directive", 0.5),
            _sig(r"^management\s+api\s+http-commands\b", "EOS management-API syntax", 2.5),
            _sig(r"^no\s+platform\s+.*\bcisco\b", "EOS platform disclaimer", 2.0),
            _sig(r"^interface\s+Ethernet\d", "EOS interface naming (no 'GigabitEthernet')", 1.5),
            _sig(r"^!\s*$", "IOS-style section delimiter ('!')", 0.5),
        ],
    },
    "Juniper": {
        "os_family": "junos",
        "signatures": [
            _sig(r"^set\s+system\s+host-name\s+\S+", "Junos 'set system host-name'", 2.0),
            _sig(r"^set\s+system\s+services\b", "Junos 'set system services' syntax", 1.5),
            _sig(r"^set\s+interfaces\s+\S+", "Junos 'set interfaces' syntax", 1.5),
            _sig(r"^set\s+security\s+\S+", "Junos 'set security' syntax", 1.0),
            _sig(r"^set\s+routing-options\b", "Junos 'set routing-options' syntax", 1.0),
        ],
    },
    "Fortinet": {
        "os_family": "fortios",
        "signatures": [
            _sig(r"^config\s+system\s+global\b", "FortiOS 'config system global' block", 2.5),
            _sig(r"^edit\s+system\b", "FortiOS 'edit system' block", 1.0),
            _sig(r"^config\s+firewall\b", "FortiOS 'config firewall' block", 1.5),
            _sig(r"^set\s+hostname\s+", "FortiOS hostname directive", 1.0),
            _sig(r"^\s*next\s*$", "FortiOS 'next' block terminator", 0.5),
            _sig(r"^\s*end\s*$", "FortiOS 'end' block terminator", 0.5),
        ],
    },
    "Palo Alto Networks": {
        "os_family": "panos",
        "signatures": [
            _sig(r"^set\s+deviceconfig\s+system\b", "PAN-OS 'set deviceconfig system' syntax", 2.5),
            _sig(r"^set\s+network\s+interface\b", "PAN-OS 'set network interface' syntax", 1.5),
            _sig(r"^set\s+rulebase\b", "PAN-OS 'set rulebase' syntax", 1.5),
            _sig(r"^set\s+shared\s+log-settings\b", "PAN-OS shared log-settings syntax", 1.0),
            _sig(r"^set\s+mgt-config\b", "PAN-OS mgt-config syntax", 1.0),
        ],
    },
    "SONiC": {
        "os_family": "sonic",
        "signatures": [
            _sig(r'"ACL_TABLE"', "SONiC config_db ACL_TABLE key", 1.5, re.M),
            _sig(r'"PORTCHANNEL"', "SONiC config_db PORTCHANNEL key", 1.0, re.M),
            _sig(r'"VLAN_MEMBER"', "SONiC config_db VLAN_MEMBER key", 1.0, re.M),
            _sig(r'"DEVICE_METADATA"', "SONiC config_db DEVICE_METADATA key", 2.0, re.M),
            _sig(r'"MGMT_INTERFACE"', "SONiC config_db MGMT_INTERFACE key", 1.5, re.M),
            _sig(r'"SYSLOG_SERVER"', "SONiC config_db SYSLOG_SERVER key", 1.0, re.M),
            _sig(r'^\s*\{', "JSON document structure", 0.5, re.M),
        ],
    },
}


@dataclass
class VendorGuess:
    vendor: str
    os_family: str
    confidence: float
    detection_evidence: List[str] = field(default_factory=list)
    status: str = "DETECTED"  # "DETECTED" or "REVIEW"

    # Backwards-compatible alias — earlier callers (routers/scans.py,
    # services/pipeline.py) read `.os`; keep it working.
    @property
    def os(self) -> str:
        return self.os_family

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vendor": self.vendor.lower() if self.vendor != "Unknown" else "unknown",
            "confidence": round(self.confidence, 2),
            "os_family": self.os_family,
            "detection_evidence": self.detection_evidence,
            "status": self.status,
        }


def _score_vendor(raw_text: str, sig_table: List[Signature]) -> Tuple[float, List[str]]:
    matched_weight = 0.0
    total_weight = sum(weight for _, _, weight in sig_table)
    evidence: List[str] = []
    for pattern, label, weight in sig_table:
        if pattern.search(raw_text):
            matched_weight += weight
            evidence.append(label)
    if total_weight <= 0:
        return 0.0, evidence
    return min(matched_weight / total_weight, 1.0), evidence


def detect_vendor(raw_text: str) -> VendorGuess:
    best_vendor = "Unknown"
    best_os_family = "unknown"
    best_score = 0.0
    best_evidence: List[str] = []

    for vendor, spec in VENDOR_SIGNATURES.items():
        score, evidence = _score_vendor(raw_text, spec["signatures"])
        if score > best_score:
            best_vendor, best_os_family, best_score, best_evidence = vendor, spec["os_family"], score, evidence

    if best_score >= CONFIDENCE_THRESHOLD:
        # Raw match-ratio scores cluster near 1.0 for any decent match, so
        # remap into a confidence band that still respects ordering without
        # implying near-certainty from a couple of matched signatures.
        confidence = 0.5 + best_score / 2
        return VendorGuess(
            vendor=best_vendor,
            os_family=best_os_family,
            confidence=round(min(confidence, 1.0), 2),
            detection_evidence=best_evidence,
            status="DETECTED",
        )

    # UNKNOWN_VENDOR -> REVIEW. Never guess past the threshold — an
    # incorrectly assumed vendor grammar silently corrupts every downstream
    # parsed parameter.
    return VendorGuess(
        vendor="Unknown",
        os_family="unknown",
        confidence=round(best_score, 2),
        detection_evidence=best_evidence,
        status="REVIEW",
    )