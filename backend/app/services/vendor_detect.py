"""Heuristic vendor/OS fingerprinting for uploaded configuration files.

This runs before parsing. It uses ordered regex signatures unique enough to
each vendor's config grammar. Falls back to 'unknown' -> triggers the full
AI/RAG normalization path with no parser shortcuts.

Vendor detection answers "who produced this configuration?" — it is NOT AI
intent classification (see app/ai/*). A guess below REVIEW_CONFIDENCE_THRESHOLD
must never be silently treated as a confident vendor match by callers: it is
surfaced as `review_required=True` and callers (services/pipeline.py,
routers/scans.py) must branch on that flag rather than only on `.vendor`.
"""
import re
from dataclasses import dataclass, field
from typing import List

# Below this confidence, a vendor guess is not trustworthy enough to drive
# deterministic parsing on its own; the scan must be flagged for review and
# the config routed toward the unknown/AI-interpretation path instead of a
# vendor-specific parser that may silently misparse it.
REVIEW_CONFIDENCE_THRESHOLD = 0.75


@dataclass
class VendorGuess:
    vendor: str
    platform: str
    confidence: float
    detection_method: str
    evidence: List[str] = field(default_factory=list)
    review_required: bool = False

    def __post_init__(self):
        # Defensive: even if a call site constructs this directly, the
        # review flag always reflects the threshold — it can never be
        # bypassed by omission.
        if self.confidence < REVIEW_CONFIDENCE_THRESHOLD or self.vendor == "Unknown":
            self.review_required = True

    @property
    def os(self) -> str:
        """Backwards-compatible alias — existing callers read `.os`;
        the spec's canonical field name is `platform`."""
        return self.platform


SIGNATURES = [
    (r"^!\s*$", r"\bip\s+access-list\b|\binterface\s+GigabitEthernet\b|\bversion\s+\d+\.\d+\b.*\n!", "Cisco", "IOS-XE"),
    (r"^set\s+system\s+", r"^set\s+interfaces\s+|^set\s+security\s+", "Juniper", "Junos"),
    (r"^config\s+system\s+global", r"^edit\s+system|^config\s+firewall", "Fortinet", "FortiOS"),
    (r"^set\s+deviceconfig\s+system", r"^set\s+network\s+interface|^set\s+rulebase", "Palo Alto Networks", "PAN-OS"),
    (r"^!\s*$", r"\bmanagement\s+api\s+http-commands\b|\bno\s+platform\s+.*\bcisco\b", "Arista", "EOS"),
    (r"\"ACL_TABLE\"|\"PORTCHANNEL\"", r"\"VLAN\"|\"MGMT_INTERFACE\"", "SONiC", "SONiC"),
]

QUICK_HINTS = [
    (re.compile(r"\bhostname\s+\S+.*\n!.*\ninterface\s+GigabitEthernet", re.I | re.S), "Cisco", "IOS-XE"),
    (re.compile(r"^set\s+system\s+host-name", re.I | re.M), "Juniper", "Junos"),
    (re.compile(r"^config\s+system\s+global", re.I | re.M), "Fortinet", "FortiOS"),
    (re.compile(r"^set\s+deviceconfig\s+system", re.I | re.M), "Palo Alto Networks", "PAN-OS"),
    (re.compile(r"management\s+api\s+http-commands", re.I | re.M), "Arista", "EOS"),
    (re.compile(r'"ACL_TABLE"|"PORTCHANNEL"|"VLAN_MEMBER"|"DEVICE_METADATA"', re.I), "SONiC", "SONiC"),
    (re.compile(r"^enable\s+secret|^ip\s+ssh\s+version", re.I | re.M), "Cisco", "IOS-XE"),
    # Cloud-native
    (re.compile(r'"AWSTemplateFormatVersion"|"AWS::EC2::SecurityGroup"', re.I), "AWS", "AWS-CloudFormation"),
    (re.compile(r'"Microsoft\.Network\/networkSecurityGroups"', re.I), "Azure", "Azure-ARM"),
    (re.compile(r'"compute#firewall"', re.I), "GCP", "GCP-API"),
    # MikroTik RouterOS
    (re.compile(r"^/ip\s+firewall\s+filter|^/ip\s+address|^/interface\s+ethernet", re.I | re.M), "MikroTik", "RouterOS"),
    # CheckPoint Gaia
    (re.compile(r"^set\s+hostname\s+\S+\s*$", re.I | re.M), "CheckPoint", "Gaia"),  # Gaia uses `set hostname` without sub-stanzas
    (re.compile(r"^set\s+interface\s+eth\d+\s+ipv4-address", re.I | re.M), "CheckPoint", "Gaia"),
    # SonicWall
    (re.compile(r"<SonicWALLconfig|<SonicOS", re.I), "SonicWall", "SonicOS"),
    # Ubiquiti EdgeOS / VyOS
    (re.compile(r"^set\s+firewall\s+name\s+\S+\s+default-action", re.I | re.M), "Ubiquiti", "EdgeOS"),
    (re.compile(r"^set\s+system\s+host-name|^set\s+interfaces\s+ethernet\s+eth\d+\s+address", re.I | re.M), "Ubiquiti", "EdgeOS"),
    # HPE Aruba AOS-CX
    (re.compile(r"^vlan\s+\d+\s*$", re.I | re.M), "Aruba", "AOS-CX"),
    (re.compile(r"^ip\s+route\s+vrf\s+|^interface\s+vlan\s+\d+", re.I | re.M), "Aruba", "AOS-CX"),
    # Huawei VRP
    (re.compile(r"^sysname\s+\S+|^acl\s+number\s+\d+", re.I | re.M), "Huawei", "VRP"),
    # pfSense / OPNsense
    (re.compile(r"<pfsense>|<opnsense>", re.I), "pfSense", "pfSense-XML"),
    # Sophos XGS
    (re.compile(r"^set\s+device-access-profile\s+name\s+\S+", re.I | re.M), "Sophos", "XGS"),
]


# Vendors the demonstration target explicitly supports as first-class,
# high-confidence parser targets (spec section 4). Anything else detected by
# QUICK_HINTS (cloud templates, other NOS families, etc.) is a real, useful
# guess for provenance/UX but is NOT one of these seven, so it always carries
# review_required=True regardless of confidence — there is no deterministic
# parser for it yet and it must flow through the unknown-block/AI path.
SUPPORTED_VENDORS = {"Cisco", "Juniper", "Fortinet", "Palo Alto Networks", "Arista", "SONiC"}


def detect_vendor(raw_text: str) -> VendorGuess:
    for pattern, vendor, platform in QUICK_HINTS:
        if pattern.search(raw_text):
            evidence = [m.group(0)[:120] for m in [pattern.search(raw_text)] if m]
            guess = VendorGuess(
                vendor=vendor,
                platform=platform,
                confidence=0.95,
                detection_method=f"regex_signature:{pattern.pattern[:60]}",
                evidence=evidence,
            )
            if vendor not in SUPPORTED_VENDORS:
                guess.review_required = True
            return guess

    # Weak fallback heuristics — confidence intentionally below
    # REVIEW_CONFIDENCE_THRESHOLD so __post_init__ always marks these for
    # human/AI review rather than letting them pass as a confident match.
    if "interface Vlan" in raw_text or "spanning-tree mode" in raw_text:
        hit = "interface Vlan" if "interface Vlan" in raw_text else "spanning-tree mode"
        return VendorGuess(
            "Cisco", "IOS-XE", 0.6,
            detection_method="weak_keyword_heuristic",
            evidence=[hit],
        )
    if raw_text.strip().startswith("{") or '"TABLE"' in raw_text:
        return VendorGuess(
            "SONiC", "SONiC", 0.5,
            detection_method="weak_keyword_heuristic",
            evidence=['"TABLE"' if '"TABLE"' in raw_text else raw_text.strip()[:40]],
        )

    if raw_text.strip().startswith("{"):
        return VendorGuess(
            "Unknown", "JSON/Cloud", 0.4,
            detection_method="weak_keyword_heuristic",
            evidence=[raw_text.strip()[:40]],
        )

    return VendorGuess("Unknown", "Unknown", 0.0, detection_method="no_signature_matched", evidence=[])