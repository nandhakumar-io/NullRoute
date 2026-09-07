"""Heuristic vendor/OS fingerprinting for uploaded configuration files.

This runs before parsing. It uses ordered regex signatures unique enough to
each vendor's config grammar. Falls back to 'unknown' -> triggers the full
AI/RAG normalization path with no parser shortcuts.
"""
import re
from dataclasses import dataclass


@dataclass
class VendorGuess:
    vendor: str
    os: str
    confidence: float


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
    (re.compile(r"\"AWSTemplateFormatVersion\"|\"AWS::EC2::SecurityGroup\"", re.I), "AWS", "AWS"),
    (re.compile(r"\"Microsoft\.Network\/networkSecurityGroups\"", re.I), "Azure", "Azure"),
    (re.compile(r"\"compute#firewall\"", re.I), "GCP", "GCP"),
]


def detect_vendor(raw_text: str) -> VendorGuess:
    for pattern, vendor, os_name in QUICK_HINTS:
        if pattern.search(raw_text):
            return VendorGuess(vendor=vendor, os=os_name, confidence=0.95)

    # Weak fallback heuristics
    if "interface Vlan" in raw_text or "spanning-tree mode" in raw_text:
        return VendorGuess("Cisco", "IOS-XE", 0.6)
    if raw_text.strip().startswith("{") or '"TABLE"' in raw_text:
        return VendorGuess("SONiC", "SONiC", 0.5)

    if raw_text.strip().startswith("{"):
        return VendorGuess("Unknown", "JSON/Cloud", 0.4)

    return VendorGuess("Unknown", "Unknown", 0.0)
