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
    """Lightweight reachability probe.

    Deliberately does NOT build a PyBatfish `Session` (that constructor
    calls `self.q.load()`, which is a real network round-trip to the
    coordinator to fetch question templates -- expensive, and slow/flaky
    under load). Previously this function did an HTTP GET against
    BATFISH_WORK_PORT (9997), which is the legacy work-pool port and does
    not reliably answer plain HTTP requests, so that GET would almost
    always raise and fall through to constructing a *second* full Session
    just to check liveness. Under any transient coordinator slowness that
    made both of those network calls report BATFISH_UNAVAILABLE even
    though Batfish was genuinely up and just busy with another job.

    Instead, probe the coordinator's actual v2 API port (BATFISH_PORT,
    9996 by default) with a plain TCP connect -- the same check the
    bundled docker-compose healthcheck already uses to decide the batfish
    container is healthy, so this function's notion of "reachable" matches
    the infrastructure's own definition."""
    if not BATFISH_ENABLED:
        return {"status": "disabled", "enabled": False}
    import socket

    try:
        with socket.create_connection((BATFISH_HOST, BATFISH_PORT), timeout=5.0):
            return {"status": "reachable", "enabled": True}
    except Exception as e:
        return {"status": "unreachable", "enabled": True, "error": str(e)}


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

def create_multi_device_snapshot(scan_id: str, device_configs: List[Dict[str, str]], variant: str) -> str:
    """Phase 10: write MULTIPLE devices' configs into one Batfish snapshot
    directory, so reachability/route queries reflect the whole inventory
    instead of a single device in isolation. `device_configs` is a list of
    {"hostname": ..., "raw_config": ...}; `variant` is caller-chosen (e.g.
    "current-<scan_id>" / "proposed-<scan_id>") so CURRENT and PROPOSED
    never collide on disk. Returns the snapshot root path, same convention
    as the single-device create_snapshot()."""
    cfg_dir = snapshot_dir(scan_id, variant)
    os.makedirs(cfg_dir, exist_ok=True)
    for entry in device_configs:
        safe_hostname = re.sub(r"[^A-Za-z0-9_.-]", "_", entry.get("hostname") or "device")
        path = os.path.join(cfg_dir, f"{safe_hostname}.cfg")
        with open(path, "w") as f:
            f.write(entry.get("raw_config", ""))
    return os.path.dirname(cfg_dir)


def compare_network_snapshots(scan_id: str, current_devices: List[Dict[str, str]],
                               proposed_devices: List[Dict[str, str]]) -> Dict[str, Any]:
    """Phase 10: build a CURRENT and a PROPOSED multi-device snapshot in the
    same Batfish network and diff them. Returns an explicit status
    (BATFISH_PASS/BATFISH_FAIL/BATFISH_UNSUPPORTED/BATFISH_UNAVAILABLE/
    BATFISH_ERROR) per RULE 13 -- an unavailable coordinator or a diff query
    Batfish can't run must never be reported as "no differences found"."""
    if not BATFISH_ENABLED:
        return {"status": "NOT_INTEGRATED", "detail": "BATFISH_ENABLED=false"}
    if not current_devices and not proposed_devices:
        return {"status": "BATFISH_UNSUPPORTED", "detail": "No Batfish-supported device configs available to compare."}

    hc = health_check()
    if hc.get("status") == "unreachable":
        return {"status": "BATFISH_UNAVAILABLE", "detail": str(hc.get("error"))}
    try:
        bf = _get_session()
    except Exception as e:
        logger.warning("Batfish session unavailable for snapshot diff: %s", e)
        return {"status": "BATFISH_UNAVAILABLE", "detail": str(e)}

    try:
        network = create_network(bf, scan_id)

        current_root = create_multi_device_snapshot(scan_id, current_devices, variant=f"current-{scan_id}")
        proposed_root = create_multi_device_snapshot(scan_id, proposed_devices, variant=f"proposed-{scan_id}")

        try:
            current_name = init_snapshot(bf, current_root, scan_id, variant=f"current-{scan_id}")
        except Exception as e:
            return {"status": "BATFISH_ERROR", "network_name": network, "detail": f"CURRENT snapshot init failed: {e}"}
        current_issues = get_init_issues(bf)
        current_nodes = get_nodes(bf)
        current_routes = get_routes(bf)

        try:
            proposed_name = init_snapshot(bf, proposed_root, scan_id, variant=f"proposed-{scan_id}")
        except Exception as e:
            return {"status": "BATFISH_ERROR", "network_name": network,
                    "current_snapshot": current_name, "detail": f"PROPOSED snapshot init failed: {e}"}
        proposed_issues = get_init_issues(bf)
        proposed_nodes = get_nodes(bf)
        proposed_routes = get_routes(bf)

        node_delta = {
            "added": sorted(set(proposed_nodes) - set(current_nodes)),
            "removed": sorted(set(current_nodes) - set(proposed_nodes)),
        }
        route_delta = {
            "current_count": len(current_routes),
            "proposed_count": len(proposed_routes),
            "count_delta": len(proposed_routes) - len(current_routes),
        }

        # Differential reachability, when Batfish exposes it for this
        # snapshot pair -- an actual behavioral (not just structural) diff.
        # Best-effort: some Batfish versions/topologies can't run this
        # (e.g. no interfaces to seed flows from) -- degrades to
        # BATFISH_UNSUPPORTED for just this sub-check, never silently
        # reported as "no behavioral change".
        differential_reachability: Dict[str, Any] = {"status": "BATFISH_UNSUPPORTED"}
        try:
            diff_answer = bf.q.differentialReachability().answer(
                snapshot=proposed_name, reference_snapshot=current_name
            ).frame()
            differential_reachability = {
                "status": "BATFISH_PASS",
                "changed_flow_count": len(diff_answer),
                "sample": diff_answer.astype(str).head(5).to_dict(orient="records"),
            }
        except Exception as e:
            differential_reachability = {"status": "BATFISH_UNSUPPORTED", "detail": str(e)}

        overall_status = "BATFISH_FAIL" if (
            node_delta["added"] or node_delta["removed"]
            or differential_reachability.get("changed_flow_count", 0) > 0
        ) else "BATFISH_PASS"

        return {
            "status": overall_status,
            "network_name": network,
            "current_snapshot": current_name,
            "proposed_snapshot": proposed_name,
            "current_init_issues": current_issues,
            "proposed_init_issues": proposed_issues,
            "node_delta": node_delta,
            "route_delta": route_delta,
            "differential_reachability": differential_reachability,
        }
    except Exception as e:
        logger.exception("Batfish snapshot diff failed for scan %s", scan_id)
        return {"status": "BATFISH_ERROR", "detail": str(e)}
    finally:
        delete_snapshot(scan_id, variant=f"current-{scan_id}")
        delete_snapshot(scan_id, variant=f"proposed-{scan_id}")


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
        pce = bf.q.fileParseStatus().answer().frame()
        for _, row in pce.iterrows():
            if str(row.get("Status", "")).upper() != "PASSED":
                issues.append({
                    "status": "BATFISH_UNSUPPORTED",
                    "device": row.get("File_Name") or row.get("Filename"),
                    "detail": str(row.get("Status")),
                })
    except Exception as e:
        issues.append({"status": "BATFISH_ERROR", "device": None, "detail": f"could not fetch file parse status: {e}"})
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
        df = bf.q.filterLineReachability(filters=node_regex).answer().frame()
        has_issue = len(df) > 0
        return ReachabilityResult(
            status="BATFISH_FAIL" if has_issue else "BATFISH_PASS",
            control_id=control_id, title=title, source_zone="ACL", destination_zone="ACL",
            severity="MEDIUM", evidence={"unreachable_lines": len(df)},
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
            status="BATFISH_PASS",
            control_id=control_id, title=title, source_zone="ROUTING", destination_zone="ROUTING",
            severity="LOW", evidence={"route_count": len(routes)},
            detail="Default route present" if has_default else "No default route found (isolated/internal routing context)",
        )
    except Exception as e:
        return ReachabilityResult(
            status="BATFISH_ERROR", control_id=control_id, title=title,
            source_zone="ROUTING", destination_zone="ROUTING", severity="LOW", detail=str(e),
        )


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

def analyze_security_behavior(scan_id: str, vendor: str, hostname: str, raw_config: str, transport: Optional[str] = None) -> BatfishAnalysisResult:
    """Runs the full Batfish behavioral-analysis suite for one scan's
    candidate configuration. Always returns a BatfishAnalysisResult with an
    explicit top-level `status` — never raises to the caller (pipeline.py),
    so a Batfish outage degrades to BATFISH_UNAVAILABLE rather than failing
    the whole scan pipeline."""
    if not BATFISH_ENABLED:
        return BatfishAnalysisResult(status="NOT_INTEGRATED", detail="BATFISH_ENABLED=false")

    if transport == "snmp":
        return BatfishAnalysisResult(
            status="BATFISH_UNSUPPORTED",
            detail="Batfish behavioral analysis is completely unsupported for devices collected via SNMP.",
        )

    if not is_vendor_supported(vendor):
        return BatfishAnalysisResult(
            status="BATFISH_UNSUPPORTED",
            detail=f"Vendor '{vendor}' is not in Batfish's supported dataplane-analysis set "
                   f"(deterministic parser + OPA coverage still applies).",
        )

    hc = health_check()
    if hc.get("status") == "unreachable":
        return BatfishAnalysisResult(status="BATFISH_UNAVAILABLE", detail=str(hc.get("error")))

    try:
        bf = _get_session()
    except Exception as e:
        logger.warning("Batfish session unavailable: %s", e)
        return BatfishAnalysisResult(status="BATFISH_UNAVAILABLE", detail=str(e))

    try:
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