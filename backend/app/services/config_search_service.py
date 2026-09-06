"""Config search — "grep across the fleet's latest configs, split by
compliance status".

The auditor's most common real question isn't "search everything" (that's
what devices.py/global_search already do) — it's "who still has telnet
turned on, and are the offenders already flagged non-compliant or did we
miss them?" That framing is what this module answers:

    "telnet"              -> every device whose latest config mentions
                              telnet, split into compliant / non-compliant
    "snmp community public" -> same, for a literal multi-word phrase

Two search passes, merged per device:
  1. Structured pass (fast, DB-only): Finding rows on each device's latest
     scan whose evidence_line/parameter/control_id/title contain the query.
     This is how "snmp community public" finds a device even if the exact
     phrase never appears verbatim (it matches the finding raised for it).
  2. Raw-text pass (MinIO): greps the actual stored configuration for
     devices the structured pass didn't already find a hit on, so syntax
     the parser didn't understand (or a literal string with no associated
     control) is still searchable. Best-effort and capped — a MinIO outage
     or a very large fleet degrades to structured-only results rather than
     failing the search.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.models.db import Device, Finding, Scan
from app.services import minio_service

# Cap on how many devices we'll do a live MinIO raw-config fetch for in a
# single search request, so one broad query on a large fleet can't turn
# into hundreds of blocking object-store round trips.
RAW_FETCH_CAP = 100
CONTEXT_RADIUS = 40  # characters of context on either side of a raw-text hit


@dataclass
class DeviceMatch:
    device_id: str
    hostname: Optional[str]
    vendor: Optional[str]
    scan_id: Optional[str]
    final_decision: Optional[str]  # PASS/REVIEW/BLOCK/None
    compliant: Optional[bool]  # True/False/None (None = not yet scanned/evaluated)
    match_source: str  # "finding" | "raw_config" | "finding+raw_config"
    match_count: int
    matched_controls: List[str] = field(default_factory=list)
    context_lines: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "device_id": self.device_id,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "scan_id": self.scan_id,
            "final_decision": self.final_decision,
            "compliant": self.compliant,
            "match_source": self.match_source,
            "match_count": self.match_count,
            "matched_controls": self.matched_controls,
            "context_lines": self.context_lines,
        }


@dataclass
class ConfigSearchResult:
    query: str
    total_devices_searched: int
    total_matches: int
    compliant_count: int
    non_compliant_count: int
    unscanned_count: int
    raw_config_search_truncated: bool
    devices: List[DeviceMatch]

    def to_dict(self) -> dict:
        return {
            "query": self.query,
            "total_devices_searched": self.total_devices_searched,
            "total_matches": self.total_matches,
            "compliant_count": self.compliant_count,
            "non_compliant_count": self.non_compliant_count,
            "unscanned_count": self.unscanned_count,
            "raw_config_search_truncated": self.raw_config_search_truncated,
            "devices": [d.to_dict() for d in self.devices],
        }


def _latest_scans_by_device(db: Session, tenant_id: str) -> Dict[str, Scan]:
    """One scan per device: the most recently created scan for that device."""
    latest_ids_subq = (
        db.query(Scan.device_id, func.max(Scan.created_at).label("max_created"))
        .filter(Scan.tenant_id == tenant_id)
        .group_by(Scan.device_id)
        .subquery()
    )
    scans = (
        db.query(Scan)
        .join(
            latest_ids_subq,
            (Scan.device_id == latest_ids_subq.c.device_id) & (Scan.created_at == latest_ids_subq.c.max_created),
        )
        .filter(Scan.tenant_id == tenant_id)
        .all()
    )
    # If a device has two scans with an identical max timestamp (rare, but
    # possible on fast test fixtures), keep the one with the higher id/last
    # seen rather than double-counting the device.
    out: Dict[str, Scan] = {}
    for s in scans:
        out[s.device_id] = s
    return out


def _compliance_bucket(scan: Optional[Scan]) -> Optional[bool]:
    if scan is None or not scan.final_decision:
        return None
    return scan.final_decision == "PASS"


def _find_context(raw_text: str, query: str) -> List[str]:
    lowered = raw_text.lower()
    q = query.lower()
    out: List[str] = []
    start = 0
    hits = 0
    while hits < 3:
        idx = lowered.find(q, start)
        if idx == -1:
            break
        lo = max(0, idx - CONTEXT_RADIUS)
        hi = min(len(raw_text), idx + len(query) + CONTEXT_RADIUS)
        snippet = raw_text[lo:hi].replace("\n", " ").strip()
        out.append(snippet)
        start = idx + len(query)
        hits += 1
    return out


def search_configs(db: Session, tenant_id: str, query: str, deep: bool = True) -> ConfigSearchResult:
    """Search every device's latest config/findings for `query`.

    `deep=False` skips the MinIO raw-config pass entirely (structured
    Finding search only) — useful for an instant-as-you-type UI, with the
    frontend re-issuing a deep=True search once the user stops typing.
    """
    query = (query or "").strip()
    devices_by_id: Dict[str, Device] = {d.id: d for d in db.query(Device).filter(Device.tenant_id == tenant_id).all()}
    latest_scan_by_device = _latest_scans_by_device(db, tenant_id)

    matches: Dict[str, DeviceMatch] = {}

    if query:
        # --- Pass 1: structured Finding search (cheap, always runs) -----
        scan_ids = [s.id for s in latest_scan_by_device.values()]
        if scan_ids:
            like = f"%{query}%"
            findings = (
                db.query(Finding)
                .filter(
                    Finding.scan_id.in_(scan_ids),
                    or_(
                        Finding.evidence_line.ilike(like),
                        Finding.parameter.ilike(like),
                        Finding.control_id.ilike(like),
                        Finding.title.ilike(like),
                    ),
                )
                .all()
            )
            scan_to_device = {s.id: dev_id for dev_id, s in latest_scan_by_device.items()}
            for f in findings:
                device_id = scan_to_device.get(f.scan_id)
                if not device_id:
                    continue
                scan = latest_scan_by_device[device_id]
                device = devices_by_id.get(device_id)
                dm = matches.get(device_id)
                if dm is None:
                    dm = DeviceMatch(
                        device_id=device_id,
                        hostname=device.hostname if device else None,
                        vendor=device.vendor if device else None,
                        scan_id=scan.id,
                        final_decision=scan.final_decision,
                        compliant=_compliance_bucket(scan),
                        match_source="finding",
                        match_count=0,
                    )
                    matches[device_id] = dm
                dm.match_count += 1
                if f.control_id and f.control_id not in dm.matched_controls:
                    dm.matched_controls.append(f.control_id)
                if f.evidence_line and f.evidence_line not in dm.context_lines:
                    dm.context_lines.append(f.evidence_line[:200])

        # --- Pass 2: raw-config grep (best-effort, capped) --------------
        truncated = False
        if deep:
            remaining = [
                (device_id, scan)
                for device_id, scan in latest_scan_by_device.items()
                if scan.raw_config_path and device_id not in matches
            ]
            # Devices already matched structurally still get a raw pass too,
            # up to the cap, so context lines are as useful as possible —
            # but unmatched devices take priority within the cap.
            also_check = [
                (device_id, scan)
                for device_id, scan in latest_scan_by_device.items()
                if scan.raw_config_path and device_id in matches
            ]
            ordered = remaining + also_check
            if len(ordered) > RAW_FETCH_CAP:
                truncated = True
                ordered = ordered[:RAW_FETCH_CAP]

            for device_id, scan in ordered:
                try:
                    raw_bytes = minio_service.get_object(scan.raw_config_path)
                except Exception:  # noqa: BLE001 - best-effort; a storage miss never fails the search
                    continue
                raw_text = raw_bytes.decode("utf-8", errors="replace")
                if query.lower() not in raw_text.lower():
                    continue
                device = devices_by_id.get(device_id)
                dm = matches.get(device_id)
                context = _find_context(raw_text, query)
                occurrence_count = raw_text.lower().count(query.lower())
                if dm is None:
                    matches[device_id] = DeviceMatch(
                        device_id=device_id,
                        hostname=device.hostname if device else None,
                        vendor=device.vendor if device else None,
                        scan_id=scan.id,
                        final_decision=scan.final_decision,
                        compliant=_compliance_bucket(scan),
                        match_source="raw_config",
                        match_count=occurrence_count,
                        context_lines=context,
                    )
                else:
                    dm.match_source = "finding+raw_config"
                    dm.match_count += occurrence_count
                    for c in context:
                        if c not in dm.context_lines:
                            dm.context_lines.append(c)
        else:
            truncated = False
    else:
        truncated = False

    device_matches = sorted(matches.values(), key=lambda d: (-(d.match_count), d.hostname or ""))
    compliant_count = sum(1 for d in device_matches if d.compliant is True)
    non_compliant_count = sum(1 for d in device_matches if d.compliant is False)
    unscanned_count = sum(1 for d in device_matches if d.compliant is None)

    return ConfigSearchResult(
        query=query,
        total_devices_searched=len(devices_by_id),
        total_matches=len(device_matches),
        compliant_count=compliant_count,
        non_compliant_count=non_compliant_count,
        unscanned_count=unscanned_count,
        raw_config_search_truncated=truncated,
        devices=device_matches,
    )