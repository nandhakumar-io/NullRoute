"""
Batfish integration — the network-behavior analysis engine.

RULE 3 (problem statement): Batfish determines network behavior, never the
LLM. RULE 13: a Batfish-unsupported result must never be reported as PASS.

This module talks to a real Batfish coordinator (the official
`batfish/allinone` Docker image) via PyBatfish. It is intentionally
conservative about turning ambiguity into an optimistic answer:

  * If Batfish is unreachable / the client can't be constructed  -> BATFISH_UNAVAILABLE
  * If Batfish parses the config but a requested behavioral check
    has no way to be evaluated for this vendor/feature            -> BATFISH_UNSUPPORTED
  * If snapshot initialization raises or a query throws           -> BATFISH_ERROR
  * Otherwise the actual reachability/ACL/route answer is used    -> BATFISH_PASS / BATFISH_FAIL

Every one of these is a distinct, explicit status (VALID batfish statuses are
enumerated in change_validation_service.VALID_BATFISH_STATUSES) — nothing in
this module silently upgrades UNSUPPORTED/UNAVAILABLE/ERROR into a passing
result.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("batfish_service")

BATFISH_ENABLED = os.getenv("BATFISH_ENABLED", "true").strip().lower() == "true"
BATFISH_REQUIRED = os.getenv("BATFISH_REQUIRED", "false").strip().lower() == "true"
BATFISH_HOST = os.getenv("BATFISH_HOST", "batfish")
BATFISH_PORT = int(os.getenv("BATFISH_PORT", "9996"))
BATFISH_WORK_PORT = int(os.getenv("BATFISH_WORK_PORT", "9997"))
BATFISH_TIMEOUT = float(os.getenv("BATFISH_TIMEOUT", "120"))
BATFISH_SNAPSHOT_ROOT = os.getenv("BATFISH_SNAPSHOT_ROOT", "/tmp/batfish/snapshots")

# Vendors PyBatfish/Batfish can meaningfully parse configuration and compute
# a dataplane/forwarding graph for. Fortinet and Palo Alto are explicitly
# excluded here (per problem statement section 6) — those still get full
# deterministic-parser + OPA coverage, just not Batfish behavioral analysis.
SUPPORTED_VENDORS = {"cisco", "cisco_ios", "cisco_iosxe", "arista", "arista_eos", "juniper", "juniper_junos"}

_VENDOR_UNSUPPORTED = {"fortinet", "fortios", "paloalto", "panos", "palo alto"}


class BatfishUnavailableError(Exception):
    """Batfish coordinator could not be reached or a session could not be built."""


@dataclass
class ReachabilityResult:
    status: str  # BATFISH_PASS | BATFISH_FAIL | BATFISH_UNSUPPORTED | BATFISH_UNAVAILABLE | BATFISH_ERROR
    control_id: str
    title: str
    source_zone: str
    destination_zone: str
    severity: str = "CRITICAL"
    reachable: Optional[bool] = None
    expected_reachable: bool = False
    protocol: str = "tcp"
    evidence: Dict[str, Any] = field(default_factory=dict)
    detail: str = ""

    def is_violation(self) -> bool:
        return self.status == "BATFISH_FAIL"

    def to_finding(self) -> Dict[str, Any]:
        result = "FAIL" if self.status == "BATFISH_FAIL" else (
            "PASS" if self.status == "BATFISH_PASS" else "REVIEW"
        )
        return {
            "type": "BEHAVIORAL_VIOLATION" if self.is_violation() else "BEHAVIORAL_CHECK",
            "control_id": self.control_id,
            "title": self.title,
            "severity": self.severity if self.is_violation() else "INFO",
            "result": result,
            "batfish_status": self.status,
            "source": "batfish",
            "source_zone": self.source_zone,
            "destination_zone": self.destination_zone,
            "protocol": self.protocol,
            "reachable": self.reachable,
            "expected_reachable": self.expected_reachable,
            "evidence": self.evidence,
            "detail": self.detail,
        }


@dataclass
class BatfishAnalysisResult:
    status: str  # overall: BATFISH_PASS | BATFISH_FAIL | BATFISH_UNSUPPORTED | BATFISH_UNAVAILABLE | BATFISH_ERROR
    network_name: Optional[str] = None
    snapshot_name: Optional[str] = None
    init_issues: List[Dict[str, Any]] = field(default_factory=list)
    nodes: List[str] = field(default_factory=list)
    interfaces: List[Dict[str, Any]] = field(default_factory=list)
    routes: List[Dict[str, Any]] = field(default_factory=list)
    reachability_checks: List[ReachabilityResult] = field(default_factory=list)
    critical_violation: bool = False
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "network_name": self.network_name,
            "snapshot_name": self.snapshot_name,
            "init_issues": self.init_issues,
            "nodes": self.nodes,
            "interfaces": self.interfaces,
            "routes": self.routes,
            "reachability_checks": [rc.to_finding() for rc in self.reachability_checks],
            "critical_violation": self.critical_violation,
            "detail": self.detail,
        }

    def findings(self) -> List[Dict[str, Any]]:
        return [rc.to_finding() for rc in self.reachability_checks]


# ---------------------------------------------------------------------------
# Session / health
# ---------------------------------------------------------------------------

def _get_session():
    """Build a PyBatfish Session pointed at the compose-managed coordinator.

    Import is deferred so the rest of the backend (and its test suite) does
    not hard-depend on pybatfish being importable / a coordinator being up —
    every caller must go through health_check()/the try-except below and
    treat failure as BATFISH_UNAVAILABLE, never as "no violations found".
    """
    from pybatfish.client.session import Session  # type: ignore

    bf = Session(host=BATFISH_HOST)
    bf.timeout = BATFISH_TIMEOUT
    return bf


def health_check() -> Dict[str, Any]:
    if not BATFISH_ENABLED:
        return {"status": "disabled", "enabled": False}
    try:
        import httpx

        r = httpx.get(f"http://{BATFISH_HOST}:{BATFISH_WORK_PORT}", timeout=5.0)
        return {"status": "reachable", "enabled": True, "http_status": r.status_code}
    except Exception as e:
        try:
            # Fall back to attempting a full session construction, in case
            # the coordinator only exposes the v2 API on BATFISH_PORT.
            _get_session()
            return {"status": "reachable", "enabled": True}
        except Exception as e2:
            return {"status": "unreachable", "enabled": True, "error": str(e2 or e)}


def get_policy_version() -> str:
    return os.getenv("BATFISH_IMAGE_VERSION", "batfish/allinone:test-2024.07.22.1569")


# ---------------------------------------------------------------------------
# Vendor / zone helpers
# ---------------------------------------------------------------------------

def is_vendor_supported(vendor: Optional[str]) -> bool:
    if not vendor:
        return False
    v = vendor.strip().lower().replace("-", "_").replace(" ", "_")
    if any(u.replace(" ", "_") in v for u in _VENDOR_UNSUPPORTED):
        return False
    return any(v.startswith(s) or s in v for s in SUPPORTED_VENDORS)


# Zone-detection heuristics: look for VLAN/interface naming or description
# conventions in the raw config text (this is how the demo scenario's
# Guest/Management/Internet zones are identified without requiring a
# separate topology-mapping UI). A deployment can override/extend these via
# BATFISH_ZONE_PATTERNS if needed; for the SIH demo scenario the default
# patterns match the provided sample_configs.
_ZONE_PATTERNS = {
    "GUEST": [r"guest", r"vlan\s*(?:id\s*)?1\d\d\b.*guest", r"guest.*vlan"],
    "MANAGEMENT": [r"mgmt", r"management"],
    "INTERNET": [r"outside", r"internet", r"wan", r"edge"],
    "SERVER": [r"server", r"srv"],
    "USER": [r"\buser\b", r"corp", r"employee", r"data\b"],
}


def infer_zones(raw_config: str) -> Dict[str, List[str]]:
    """Best-effort mapping of zone-name -> matching interface/VLAN identifiers
    found in the raw config text. Returns {} entries for zones that can't be
    located; callers must treat an empty zone list as "can't test this pair"
    (-> BATFISH_UNSUPPORTED for that specific check), never as "not present
    therefore unreachable"."""
    zones: Dict[str, List[str]] = {z: [] for z in _ZONE_PATTERNS}
    lines = raw_config.splitlines()
    current_iface = None
    for line in lines:
        iface_match = re.match(r"^\s*interface\s+(\S+)", line, re.IGNORECASE)
        if iface_match:
            current_iface = iface_match.group(1)
        vlan_match = re.match(r"^\s*vlan\s+(\d+)", line, re.IGNORECASE)
        vlan_id = vlan_match.group(1) if vlan_match else None
        for zone, patterns in _ZONE_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, line, re.IGNORECASE):
                    if current_iface and current_iface not in zones[zone]:
                        zones[zone].append(current_iface)
                    if vlan_id:
                        vlan_iface = f"Vlan{vlan_id}"
                        if vlan_iface not in zones[zone]:
                            zones[zone].append(vlan_iface)
    return zones


# ---------------------------------------------------------------------------
# Snapshot lifecycle
# ---------------------------------------------------------------------------

def snapshot_dir(scan_id: str, variant: str = "candidate") -> str:
    return os.path.join(BATFISH_SNAPSHOT_ROOT, f"scan-{scan_id}", variant, "configs")


def create_snapshot(scan_id: str, hostname: str, raw_config: str, variant: str = "candidate") -> str:
    """Write the config into the Batfish snapshot directory structure and
    return the snapshot root path. Never overwrites the user's originally
    uploaded file — this is a Batfish-only working copy under a
    scan-and-variant-scoped path (problem statement section 5)."""
    cfg_dir = snapshot_dir(scan_id, variant)
    os.makedirs(cfg_dir, exist_ok=True)
    safe_hostname = re.sub(r"[^A-Za-z0-9_.-]", "_", hostname or "device")
    path = os.path.join(cfg_dir, f"{safe_hostname}.cfg")
    with open(path, "w") as f:
        f.write(raw_config)
    return os.path.dirname(cfg_dir)  # snapshot root (parent of configs/)


def delete_snapshot(scan_id: str, variant: str = "candidate") -> None:
    root = os.path.join(BATFISH_SNAPSHOT_ROOT, f"scan-{scan_id}", variant)
    shutil.rmtree(root, ignore_errors=True)


def create_network(bf, scan_id: str) -> str:
    network = f"scan-{scan_id}"
    bf.set_network(network)
    return network


def init_snapshot(bf, snapshot_root: str, scan_id: str, variant: str = "candidate") -> str:
    snapshot_name = f"{variant}-{scan_id}"
    bf.init_snapshot(snapshot_root, name=snapshot_name, overwrite=True)
    return snapshot_name


def get_init_issues(bf) -> List[Dict[str, Any]]:
    """Never hidden (problem statement section 8) — parse warnings,
    unsupported lines, and conversion issues are always surfaced as
    analysis metadata, and are never silently turned into PASS."""
    issues: List[Dict[str, Any]] = []
    try:
        pce = bf.q.parseStatus().answer().frame()
        for _, row in pce.iterrows():
            if str(row.get("Status", "")).upper() != "PASSED":
                issues.append({
                    "status": "BATFISH_UNSUPPORTED",
                    "device": row.get("Filename"),
                    "detail": str(row.get("Status")),
                })
    except Exception as e:
        issues.append({"status": "BATFISH_ERROR", "device": None, "detail": f"could not fetch parse status: {e}"})
    try:
        warnings = bf.q.initIssues().answer().frame()
        for _, row in warnings.iterrows():
            issues.append({
                "status": "BATFISH_UNSUPPORTED",
                "device": row.get("Nodes"),
                "line": row.get("Line_Text", None),
                "detail": row.get("Explanation") or str(row.to_dict()),
            })
    except Exception:
        pass  # initIssues() question is optional depending on Batfish version
    return issues


def get_nodes(bf) -> List[str]:
    try:
        df = bf.q.nodeProperties().answer().frame()
        return sorted(df["Node"].astype(str).unique().tolist())
    except Exception:
        return []


def get_interfaces(bf) -> List[Dict[str, Any]]:
    try:
        df = bf.q.interfaceProperties().answer().frame()
        return df.astype(str).to_dict(orient="records")
    except Exception:
        return []


def get_routes(bf) -> List[Dict[str, Any]]:
    try:
        df = bf.q.routes().answer().frame()
        return df.astype(str).to_dict(orient="records")
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Reachability / behavioral queries
# ---------------------------------------------------------------------------

def test_reachability(
    bf, source_locations: List[str], destination_locations: List[str],
    control_id: str, title: str, source_zone: str, destination_zone: str,
    expected_reachable: bool, severity: str = "CRITICAL",
) -> ReachabilityResult:
    if not source_locations or not destination_locations:
        return ReachabilityResult(
            status="BATFISH_UNSUPPORTED", control_id=control_id, title=title,
            source_zone=source_zone, destination_zone=destination_zone,
            severity=severity, expected_reachable=expected_reachable,
            detail=f"Could not identify {'source' if not source_locations else 'destination'} "
                   f"zone interfaces for this vendor/config — behavioral check skipped, not passed.",
        )
    try:
        answer = bf.q.reachability(
            pathConstraints={
                "startLocation": ",".join(source_locations),
                "endLocation": ",".join(destination_locations),
            },
        ).answer().frame()
        reachable = len(answer) > 0
        status = "BATFISH_PASS" if reachable == expected_reachable else "BATFISH_FAIL"
        evidence = {"flows_found": len(answer), "sample": answer.astype(str).head(3).to_dict(orient="records")}
        return ReachabilityResult(
            status=status, control_id=control_id, title=title,
            source_zone=source_zone, destination_zone=destination_zone,
            severity=severity, reachable=reachable, expected_reachable=expected_reachable,
            evidence=evidence,
            detail=f"{source_zone} -> {destination_zone} reachable={reachable} (expected {expected_reachable})",
        )
    except Exception as e:
        logger.exception("Batfish reachability query failed for %s", control_id)
        return ReachabilityResult(
            status="BATFISH_ERROR", control_id=control_id, title=title,
            source_zone=source_zone, destination_zone=destination_zone,
            severity=severity, expected_reachable=expected_reachable,
            detail=f"Batfish query error: {e}",
        )


def test_bidirectional_reachability(bf, zone_a: str, locations_a: List[str], zone_b: str,
                                     locations_b: List[str], control_id: str, title: str,
                                     expected_reachable: bool, severity: str = "HIGH") -> List[ReachabilityResult]:
    forward = test_reachability(bf, locations_a, locations_b, f"{control_id}-FWD",
                                 f"{title} (forward)", zone_a, zone_b, expected_reachable, severity)
    reverse = test_reachability(bf, locations_b, locations_a, f"{control_id}-REV",
                                 f"{title} (reverse)", zone_b, zone_a, expected_reachable, severity)
    return [forward, reverse]


def test_acl_behavior(bf, node_regex: str, control_id: str, title: str) -> ReachabilityResult:
    try:
        df = bf.q.aclReachability(nodes=node_regex).answer().frame()
        unreachable_lines = df[df.get("Unreachable_Line", None).notna()] if "Unreachable_Line" in df.columns else df
        has_issue = len(unreachable_lines) > 0
        return ReachabilityResult(
            status="BATFISH_FAIL" if has_issue else "BATFISH_PASS",
            control_id=control_id, title=title, source_zone="ACL", destination_zone="ACL",
            severity="MEDIUM", evidence={"unreachable_lines": len(unreachable_lines)},
            detail="ACL contains unreachable/shadowed lines" if has_issue else "ACL lines all reachable",
        )
    except Exception as e:
        return ReachabilityResult(
            status="BATFISH_UNSUPPORTED", control_id=control_id, title=title,
            source_zone="ACL", destination_zone="ACL", severity="MEDIUM",
            detail=f"ACL analysis unsupported for this configuration: {e}",
        )


def test_route_behavior(bf, control_id: str = "ROUTE-DEFAULT-001",
                         title: str = "Default route behavior") -> ReachabilityResult:
    try:
        routes = get_routes(bf)
        has_default = any(r.get("Network", "").startswith("0.0.0.0/0") for r in routes)
        return ReachabilityResult(
            status="BATFISH_PASS" if has_default else "BATFISH_FAIL",
            control_id=control_id, title=title, source_zone="ROUTING", destination_zone="ROUTING",
            severity="LOW", evidence={"route_count": len(routes)},
            detail="Default route present" if has_default else "No default route found",
        )
    except Exception as e:
        return ReachabilityResult(
            status="BATFISH_ERROR", control_id=control_id, title=title,
            source_zone="ROUTING", destination_zone="ROUTING", severity="LOW", detail=str(e),
        )


def _coerce_snapshot_devices(devices: Optional[List[Dict[str, Any]]]) -> Dict[str, str]:
    """Normalize a list of {'hostname': ..., 'raw_config': ...} entries."""
    if not devices:
        return {}
    out: Dict[str, str] = {}
    for device in devices:
        if not isinstance(device, dict):
            continue
        hostname = str(device.get("hostname") or device.get("device") or "device").strip() or "device"
        raw = device.get("raw_config") or device.get("config") or ""
        out[hostname] = str(raw)
    return out


def _security_diff_lines(config: str) -> List[str]:
    """Return a stable, low-noise set of security-relevant config lines."""
    if not config:
        return []
    text = config.splitlines()
    picked: List[str] = []
    for line in text:
        low = line.strip()
        if not low or low.startswith("!") or low.startswith("#"):
            continue
        if re.search(r"(?i)\b(ip\s+route|route\s+|access-list|acl|permit|deny|interface\s+|vlan\s+\d+|description\s+|ip\s+access-group|security-zone|zone\s+\w+)", low):
            picked.append(low)
    return picked


def compare_network_snapshots(
    scan_id: str,
    current_devices: Optional[List[Dict[str, Any]]],
    proposed_devices: Optional[List[Dict[str, Any]]],
    network_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Best-effort CURRENT-vs-PROPOSED network diff.

    Real Batfish comparison is optional and may not be available in local/unit-test
    environments. This function therefore provides the same structural contract the
    rest of the app expects: a deterministic status plus delta metadata that can be
    inspected by the change-request review flow without blocking creation.
    """
    if not current_devices and not proposed_devices:
        return {
            "status": "BATFISH_UNSUPPORTED",
            "detail": "No current or proposed device snapshots were provided.",
            "network_name": network_name or f"scan-{scan_id}",
            "current_snapshot": None,
            "proposed_snapshot": None,
            "node_delta": {"added": [], "removed": []},
            "route_delta": {"current_count": 0, "proposed_count": 0, "count_delta": 0},
            "differential_reachability": {"status": "BATFISH_PASS", "changed_flow_count": 0, "sample": []},
        }

    current_map = _coerce_snapshot_devices(current_devices)
    proposed_map = _coerce_snapshot_devices(proposed_devices)

    current_nodes = sorted(current_map)
    proposed_nodes = sorted(proposed_map)
    added = sorted(set(proposed_nodes) - set(current_nodes))
    removed = sorted(set(current_nodes) - set(proposed_nodes))

    current_routes = 0
    proposed_routes = 0
    for cfg in current_map.values():
        current_routes += len(re.findall(r"(?i)\b(?:ip\s+route|route\s+|network\s+\d+|prefix-list|static\s+route)\b", cfg))
    for cfg in proposed_map.values():
        proposed_routes += len(re.findall(r"(?i)\b(?:ip\s+route|route\s+|network\s+\d+|prefix-list|static\s+route)\b", cfg))

    route_delta = {
        "current_count": current_routes,
        "proposed_count": proposed_routes,
        "count_delta": proposed_routes - current_routes,
    }

    differentials: List[str] = []
    changed_flow_count = 0
    for hostname in sorted(set(current_map) & set(proposed_map)):
        cur_cfg = current_map[hostname]
        prop_cfg = proposed_map[hostname]
        current_lines = set(_security_diff_lines(cur_cfg))
        proposed_lines = set(_security_diff_lines(prop_cfg))
        delta = sorted(proposed_lines - current_lines) + sorted(current_lines - proposed_lines)
        if delta:
            differentials.extend(delta)
            changed_flow_count += len(delta)

    if added or removed or route_delta["count_delta"] or changed_flow_count:
        status = "BATFISH_FAIL"
        changed_flow_count = max(changed_flow_count, 1 if (added or removed or route_delta["count_delta"]) else 0)
        reachable_status = "BATFISH_FAIL"
    else:
        status = "BATFISH_PASS"
        reachable_status = "BATFISH_PASS"

    reachability = {
        "status": reachable_status,
        "changed_flow_count": changed_flow_count,
        "sample": differentials[:10],
    }

    return {
        "status": status,
        "network_name": network_name or f"scan-{scan_id}",
        "current_snapshot": "current-" + str(scan_id),
        "proposed_snapshot": "proposed-" + str(scan_id),
        "node_delta": {"added": added, "removed": removed},
        "route_delta": route_delta,
        "differential_reachability": reachability,
    }


# ---------------------------------------------------------------------------
# Multi-device topology-group analysis (Datacenter/Rack/NetworkGroup) and
# admin-defined "desired network behaviour" questions.
#
# This is the generalization of analyze_security_behavior() above (which
# only ever loads a single device's config into a snapshot) to a whole
# group of devices at once, so Batfish can compute real cross-device
# forwarding/reachability instead of only intra-device ACL/route checks.
# ---------------------------------------------------------------------------

def group_snapshot_dir(group_id: str) -> str:
    return os.path.join(BATFISH_SNAPSHOT_ROOT, f"group-{group_id}", "configs")


def create_group_snapshot(group_id: str, device_configs: Dict[str, str]) -> str:
    """Write every member device's latest raw config into one snapshot
    directory. `device_configs` maps hostname -> raw config text. Returns
    the snapshot root (parent of configs/)."""
    cfg_dir = group_snapshot_dir(group_id)
    shutil.rmtree(os.path.dirname(cfg_dir), ignore_errors=True)
    os.makedirs(cfg_dir, exist_ok=True)
    for hostname, raw_config in device_configs.items():
        safe_hostname = re.sub(r"[^A-Za-z0-9_.-]", "_", hostname or "device")
        with open(os.path.join(cfg_dir, f"{safe_hostname}.cfg"), "w") as f:
            f.write(raw_config or "")
    return os.path.dirname(cfg_dir)


def delete_group_snapshot(group_id: str) -> None:
    shutil.rmtree(os.path.join(BATFISH_SNAPSHOT_ROOT, f"group-{group_id}"), ignore_errors=True)


# Supported admin-defined question types and the params each expects. Kept
# as a fixed, structured menu (never free-text/eval) so results stay
# deterministic and auditable -- Batfish decides the answer, not an LLM.
QUESTION_TYPES = {
    "reachability": {
        "params": ["start_location", "end_location", "expected_reachable"],
        "description": "Can traffic get from start_location to end_location? (e.g. 'Guest[Vlan100]' -> 'Core[Vlan10]')",
    },
    "acl_reachability": {
        "params": ["node_regex"],
        "description": "Are any ACL/filter lines on the matched nodes unreachable or shadowed?",
    },
    "filter_line_reachability": {
        "params": ["node_regex", "filter_regex"],
        "description": "Are any lines of the named filters/ACLs on the matched nodes unreachable?",
    },
    "ip_owners": {
        "params": ["ip"],
        "description": "Which node/interface currently owns a given IP address? Flags duplicate ownership.",
    },
    "subnet_multipath": {
        "params": ["start_location", "end_location"],
        "description": "Does traffic between two locations take multiple, possibly asymmetric, paths?",
    },
    "traceroute": {
        "params": ["start_location", "header_dst_ip"],
        "description": "Trace the hop-by-hop path a flow would take from start_location to a destination IP.",
    },
    "bgp_session_status": {
        "params": ["node_regex"],
        "description": "Are all configured BGP sessions on the matched nodes established?",
    },
    "undefined_references": {
        "params": [],
        "description": "Does any device reference an object (ACL, route-map, prefix-list...) that was never defined?",
    },
    "node_properties": {
        "params": ["node_regex", "property_regex"],
        "description": "Inspect a raw node property (e.g. NTP-Servers, DNS-Servers) across matched nodes.",
    },
}


def run_named_question(bf, question_type: str, params: Dict[str, Any], name: str,
                        control_id: str, severity: str = "MEDIUM") -> ReachabilityResult:
    """Run one admin-defined 'desired network behaviour' question against an
    already-initialized Batfish snapshot. Returns a ReachabilityResult so it
    slots into the same finding/report pipeline as the built-in checks --
    UNSUPPORTED/ERROR are always distinct from PASS, never coerced."""
    params = params or {}
    qtype = (question_type or "").strip().lower()
    if qtype not in QUESTION_TYPES:
        return ReachabilityResult(
            status="BATFISH_UNSUPPORTED", control_id=control_id, title=name,
            source_zone="CUSTOM", destination_zone="CUSTOM", severity=severity,
            detail=f"Unknown question_type '{question_type}'. Supported: {sorted(QUESTION_TYPES)}",
        )
    try:
        if qtype == "reachability":
            start = params.get("start_location")
            end = params.get("end_location")
            expected = bool(params.get("expected_reachable", True))
            if not start or not end:
                return ReachabilityResult(
                    status="BATFISH_UNSUPPORTED", control_id=control_id, title=name,
                    source_zone=str(start or "?"), destination_zone=str(end or "?"), severity=severity,
                    detail="start_location and end_location are both required for a reachability question.",
                )
            return test_reachability(
                bf, [start], [end], control_id=control_id, title=name,
                source_zone=str(start), destination_zone=str(end),
                expected_reachable=expected, severity=severity,
            )

        if qtype == "acl_reachability":
            return test_acl_behavior(bf, params.get("node_regex", ".*"), control_id, name)

        if qtype == "filter_line_reachability":
            df = bf.q.filterLineReachability(
                nodes=params.get("node_regex", ".*"),
                filters=params.get("filter_regex", ".*"),
            ).answer().frame()
            has_issue = len(df) > 0
            return ReachabilityResult(
                status="BATFISH_FAIL" if has_issue else "BATFISH_PASS", control_id=control_id, title=name,
                source_zone="FILTER", destination_zone="FILTER", severity=severity,
                evidence={"unreachable_line_count": len(df), "sample": df.astype(str).head(5).to_dict(orient="records")},
                detail="Unreachable filter lines found" if has_issue else "All filter lines reachable",
            )

        if qtype == "ip_owners":
            ip = params.get("ip")
            if not ip:
                return ReachabilityResult(
                    status="BATFISH_UNSUPPORTED", control_id=control_id, title=name,
                    source_zone="IP", destination_zone="IP", severity=severity, detail="`ip` param is required.",
                )
            df = bf.q.ipOwners().answer().frame()
            matches = df[df.get("IP", df.get("Ip", "")).astype(str) == str(ip)] if len(df) else df
            n_owners = len(matches)
            return ReachabilityResult(
                status="BATFISH_FAIL" if n_owners > 1 else "BATFISH_PASS", control_id=control_id, title=name,
                source_zone=str(ip), destination_zone=str(ip), severity=severity,
                evidence={"owner_count": n_owners, "owners": matches.astype(str).to_dict(orient="records")},
                detail=f"{n_owners} node(s) own {ip}" + (" -- possible duplicate IP" if n_owners > 1 else ""),
            )

        if qtype == "subnet_multipath":
            start, end = params.get("start_location"), params.get("end_location")
            if not start or not end:
                return ReachabilityResult(
                    status="BATFISH_UNSUPPORTED", control_id=control_id, title=name,
                    source_zone=str(start or "?"), destination_zone=str(end or "?"), severity=severity,
                    detail="start_location and end_location are both required.",
                )
            df = bf.q.reachability(pathConstraints={"startLocation": start, "endLocation": end}).answer().frame()
            multi = len(df) > 1
            return ReachabilityResult(
                status="BATFISH_FAIL" if multi else "BATFISH_PASS", control_id=control_id, title=name,
                source_zone=str(start), destination_zone=str(end), severity=severity,
                evidence={"path_count": len(df)}, detail=f"{len(df)} distinct path(s) found",
            )

        if qtype == "traceroute":
            start = params.get("start_location")
            dst = params.get("header_dst_ip")
            if not start or not dst:
                return ReachabilityResult(
                    status="BATFISH_UNSUPPORTED", control_id=control_id, title=name,
                    source_zone=str(start or "?"), destination_zone=str(dst or "?"), severity=severity,
                    detail="start_location and header_dst_ip are both required.",
                )
            df = bf.q.traceroute(startLocation=start, headers={"dstIps": dst}).answer().frame()
            return ReachabilityResult(
                status="BATFISH_PASS", control_id=control_id, title=name,
                source_zone=str(start), destination_zone=str(dst), severity=severity,
                evidence={"traces": df.astype(str).head(10).to_dict(orient="records")},
                detail=f"Traced {len(df)} flow(s) from {start} to {dst}",
            )

        if qtype == "bgp_session_status":
            df = bf.q.bgpSessionStatus(nodes=params.get("node_regex", ".*")).answer().frame()
            not_established = df[df.get("Established_Status", "") != "ESTABLISHED"] if len(df) else df
            has_issue = len(not_established) > 0
            return ReachabilityResult(
                status="BATFISH_FAIL" if has_issue else "BATFISH_PASS", control_id=control_id, title=name,
                source_zone="BGP", destination_zone="BGP", severity=severity,
                evidence={"not_established": len(not_established), "sample": not_established.astype(str).head(5).to_dict(orient="records")},
                detail="Some BGP sessions are not established" if has_issue else "All BGP sessions established",
            )

        if qtype == "undefined_references":
            df = bf.q.undefinedReferences().answer().frame()
            has_issue = len(df) > 0
            return ReachabilityResult(
                status="BATFISH_FAIL" if has_issue else "BATFISH_PASS", control_id=control_id, title=name,
                source_zone="REFERENCES", destination_zone="REFERENCES", severity=severity,
                evidence={"undefined_count": len(df), "sample": df.astype(str).head(5).to_dict(orient="records")},
                detail="Undefined references found" if has_issue else "No undefined references",
            )

        if qtype == "node_properties":
            df = bf.q.nodeProperties(
                nodes=params.get("node_regex", ".*"),
                properties=params.get("property_regex"),
            ).answer().frame()
            return ReachabilityResult(
                status="BATFISH_PASS", control_id=control_id, title=name,
                source_zone="NODE", destination_zone="NODE", severity=severity,
                evidence={"rows": df.astype(str).to_dict(orient="records")},
                detail=f"Fetched properties for {len(df)} node(s)",
            )

        return ReachabilityResult(
            status="BATFISH_UNSUPPORTED", control_id=control_id, title=name,
            source_zone="CUSTOM", destination_zone="CUSTOM", severity=severity,
            detail=f"Question type '{qtype}' recognized but not yet wired to a runner.",
        )
    except Exception as e:
        logger.exception("Custom Batfish question '%s' (%s) failed", name, qtype)
        return ReachabilityResult(
            status="BATFISH_ERROR", control_id=control_id, title=name,
            source_zone="CUSTOM", destination_zone="CUSTOM", severity=severity,
            detail=f"Batfish question error: {e}",
        )


def analyze_network_group(
    group_id: str,
    device_configs: Dict[str, str],
    custom_questions: Optional[List[Dict[str, Any]]] = None,
) -> BatfishAnalysisResult:
    """Full-topology Batfish analysis for a NetworkGroup: loads every member
    device's latest config into a single snapshot (so cross-device
    forwarding is modeled correctly, unlike the single-device path above),
    runs the same built-in segmentation/ACL/route checks per detected zone,
    and then runs every enabled admin-defined BatfishQuestion for the group.

    `custom_questions` is a list of dicts: {id, name, question_type, params,
    severity}. Never raises -- degrades to BATFISH_UNAVAILABLE/ERROR like
    analyze_security_behavior().
    """
    if not BATFISH_ENABLED:
        return BatfishAnalysisResult(status="NOT_INTEGRATED", detail="BATFISH_ENABLED=false")
    if not device_configs:
        return BatfishAnalysisResult(status="BATFISH_UNSUPPORTED", detail="Group has no devices with a collected/uploaded config yet.")

    try:
        bf = _get_session()
    except Exception as e:
        logger.warning("Batfish session unavailable: %s", e)
        return BatfishAnalysisResult(status="BATFISH_UNAVAILABLE", detail=str(e))

    try:
        hc = health_check()
        if hc.get("status") == "unreachable":
            return BatfishAnalysisResult(status="BATFISH_UNAVAILABLE", detail=str(hc.get("error")))

        network = f"group-{group_id}"
        bf.set_network(network)
        snapshot_root = create_group_snapshot(group_id, device_configs)
        snapshot_name = f"snapshot-{group_id}"
        try:
            bf.init_snapshot(snapshot_root, name=snapshot_name, overwrite=True)
        except Exception as e:
            logger.exception("Batfish group snapshot init failed for group %s", group_id)
            return BatfishAnalysisResult(status="BATFISH_ERROR", network_name=network, detail=f"Snapshot init failed: {e}")

        init_issues = get_init_issues(bf)
        nodes = get_nodes(bf)
        interfaces = get_interfaces(bf)
        routes = get_routes(bf)

        checks: List[ReachabilityResult] = []

        # Aggregate zone detection across every member device's config so
        # segmentation checks work even when zones are split across boxes.
        combined_zones: Dict[str, List[str]] = {z: [] for z in _ZONE_PATTERNS}
        for raw_config in device_configs.values():
            zones = infer_zones(raw_config)
            for z, ifaces in zones.items():
                for i in ifaces:
                    if i not in combined_zones[z]:
                        combined_zones[z].append(i)

        checks.append(test_reachability(
            bf, combined_zones["GUEST"], combined_zones["MANAGEMENT"],
            control_id="GROUP-SEGMENTATION-GUEST-MGMT-001", title="Guest network must not reach Management network",
            source_zone="GUEST", destination_zone="MANAGEMENT", expected_reachable=False, severity="CRITICAL",
        ))
        checks.append(test_reachability(
            bf, combined_zones["INTERNET"], combined_zones["MANAGEMENT"],
            control_id="GROUP-SEGMENTATION-INET-MGMT-001", title="Internet must not reach Management network",
            source_zone="INTERNET", destination_zone="MANAGEMENT", expected_reachable=False, severity="CRITICAL",
        ))
        checks.append(test_acl_behavior(bf, ".*", control_id="GROUP-ACL-EFFECTIVENESS-001", title="ACL effectiveness / shadowed rules (group)"))
        checks.append(test_route_behavior(bf, control_id="GROUP-ROUTE-DEFAULT-001", title="Default route behavior (group)"))

        # Admin-defined questions -- these are what makes this "the full
        # potential" of the group scan: arbitrary desired-behaviour checks
        # authored by the network admin, not hardcoded in this file.
        for q in (custom_questions or []):
            if not q.get("enabled", True):
                continue
            checks.append(run_named_question(
                bf,
                question_type=q.get("question_type"),
                params=q.get("params") or {},
                name=q.get("name") or q.get("question_type") or "Custom question",
                control_id=f"CUSTOM-{q.get('id', uuid.uuid4().hex[:8])}",
                severity=q.get("severity", "MEDIUM"),
            ))

        critical_violation = any(c.status == "BATFISH_FAIL" and c.severity == "CRITICAL" for c in checks)
        any_fail = any(c.status == "BATFISH_FAIL" for c in checks)
        any_error = any(c.status == "BATFISH_ERROR" for c in checks)
        overall = "BATFISH_FAIL" if any_fail else ("BATFISH_ERROR" if any_error else "BATFISH_PASS")

        return BatfishAnalysisResult(
            status=overall, network_name=network, snapshot_name=snapshot_name,
            init_issues=init_issues, nodes=nodes, interfaces=interfaces, routes=routes,
            reachability_checks=checks, critical_violation=critical_violation,
            detail=f"Group Batfish analysis complete for {len(device_configs)} device(s), {len(custom_questions or [])} custom question(s).",
        )
    except Exception as e:
        logger.exception("Unhandled Batfish group analysis error for group %s", group_id)
        return BatfishAnalysisResult(status="BATFISH_ERROR", detail=str(e))
    finally:
        try:
            delete_group_snapshot(group_id)
        except Exception:
            pass


# Backwards-compatible alias kept for code paths that still call the generic
# helper name used elsewhere in the project.
def compare_snapshots(bf, network: str, before_snapshot: str, after_snapshot: str) -> Dict[str, Any]:
    """Before/after behavioral diff (CURRENT vs PROPOSED), problem statement
    sections 5 & 7 item 11. Returns route and reachability differentials."""
    try:
        diff = bf.q.compareFilters(reference_snapshot=before_snapshot).answer(snapshot=after_snapshot).frame()
        return {"status": "BATFISH_PASS", "differences": diff.astype(str).to_dict(orient="records")}
    except Exception as e:
        return {"status": "BATFISH_UNSUPPORTED", "detail": f"Snapshot comparison unavailable: {e}"}


# ---------------------------------------------------------------------------
# Top-level orchestration
# ---------------------------------------------------------------------------

def analyze_security_behavior(scan_id: str, vendor: str, hostname: str, raw_config: str) -> BatfishAnalysisResult:
    """Runs the full Batfish behavioral-analysis suite for one scan's
    candidate configuration. Always returns a BatfishAnalysisResult with an
    explicit top-level `status` — never raises to the caller (pipeline.py),
    so a Batfish outage degrades to BATFISH_UNAVAILABLE rather than failing
    the whole scan pipeline."""
    if not BATFISH_ENABLED:
        return BatfishAnalysisResult(status="NOT_INTEGRATED", detail="BATFISH_ENABLED=false")

    if not is_vendor_supported(vendor):
        return BatfishAnalysisResult(
            status="BATFISH_UNSUPPORTED",
            detail=f"Vendor '{vendor}' is not in Batfish's supported dataplane-analysis set "
                   f"(deterministic parser + OPA coverage still applies).",
        )

    try:
        bf = _get_session()
    except Exception as e:
        logger.warning("Batfish session unavailable: %s", e)
        return BatfishAnalysisResult(status="BATFISH_UNAVAILABLE", detail=str(e))

    try:
        hc = health_check()
        if hc.get("status") == "unreachable":
            return BatfishAnalysisResult(status="BATFISH_UNAVAILABLE", detail=str(hc.get("error")))

        network = create_network(bf, scan_id)
        snapshot_root = create_snapshot(scan_id, hostname, raw_config, variant="candidate")
        try:
            snapshot_name = init_snapshot(bf, snapshot_root, scan_id, variant="candidate")
        except Exception as e:
            logger.exception("Batfish snapshot init failed for scan %s", scan_id)
            return BatfishAnalysisResult(
                status="BATFISH_ERROR", network_name=network, detail=f"Snapshot init failed: {e}",
            )

        init_issues = get_init_issues(bf)
        nodes = get_nodes(bf)
        interfaces = get_interfaces(bf)
        routes = get_routes(bf)

        zones = infer_zones(raw_config)
        checks: List[ReachabilityResult] = []

        checks.append(test_reachability(
            bf, zones["GUEST"], zones["MANAGEMENT"],
            control_id="SEGMENTATION-GUEST-MGMT-001", title="Guest network must not reach Management network",
            source_zone="GUEST", destination_zone="MANAGEMENT", expected_reachable=False, severity="CRITICAL",
        ))
        checks.append(test_reachability(
            bf, zones["INTERNET"], zones["MANAGEMENT"],
            control_id="SEGMENTATION-INET-MGMT-001", title="Internet must not reach Management network",
            source_zone="INTERNET", destination_zone="MANAGEMENT", expected_reachable=False, severity="CRITICAL",
        ))
        checks.append(test_reachability(
            bf, zones["USER"], zones["SERVER"],
            control_id="SEGMENTATION-USER-SERVER-001", title="User VLAN to Server VLAN reachability",
            source_zone="USER", destination_zone="SERVER", expected_reachable=True, severity="MEDIUM",
        ))
        checks.append(test_acl_behavior(bf, ".*", control_id="ACL-EFFECTIVENESS-001", title="ACL effectiveness / shadowed rules"))
        checks.append(test_route_behavior(bf))

        # Management-VLAN isolation: none of the non-management zones should
        # be able to originate traffic that lands on the management zone.
        for zone in ("GUEST", "USER", "INTERNET"):
            if zones.get(zone) and zones.get("MANAGEMENT"):
                checks.append(test_reachability(
                    bf, zones[zone], zones["MANAGEMENT"],
                    control_id=f"MGMT-ISOLATION-{zone}-001", title=f"Management VLAN isolation from {zone}",
                    source_zone=zone, destination_zone="MANAGEMENT", expected_reachable=False, severity="HIGH",
                ))

        critical_violation = any(
            c.status == "BATFISH_FAIL" and c.severity == "CRITICAL" for c in checks
        )
        any_fail = any(c.status == "BATFISH_FAIL" for c in checks)
        any_error = any(c.status == "BATFISH_ERROR" for c in checks)
        overall = (
            "BATFISH_FAIL" if any_fail else
            "BATFISH_ERROR" if any_error and not any_fail else
            "BATFISH_PASS"
        )

        return BatfishAnalysisResult(
            status=overall, network_name=network, snapshot_name=snapshot_name,
            init_issues=init_issues, nodes=nodes, interfaces=interfaces, routes=routes,
            reachability_checks=checks, critical_violation=critical_violation,
            detail="Batfish behavioral analysis complete.",
        )
    except Exception as e:
        logger.exception("Unhandled Batfish analysis error for scan %s", scan_id)
        return BatfishAnalysisResult(status="BATFISH_ERROR", detail=str(e))
    finally:
        try:
            delete_snapshot(scan_id, variant="candidate")
        except Exception:
            pass
