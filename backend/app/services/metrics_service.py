"""Phase 15 -- device metrics history, interface utilization, and
threshold-based alerting hooks.

`metrics_poller_worker.py` calls `poll_device()` on a fixed interval for
every enabled device; `record_snapshot()` is the single place a
DeviceMetricSnapshot row is written, so the on-demand
`gateway-get-health-metrics` endpoint (routers/device_gateway.py) and the
periodic poller both flow through the same persistence + utilization-calc
path (no second implementation, matching this codebase's existing RULE 11
convention).

Interface utilization is derived, never collected directly: SNMP only
exposes cumulative octet counters (ifHCInOctets/ifHCOutOctets), so percent-
of-link-speed utilization requires two samples and the elapsed time between
them: utilization_pct = (octet_delta * 8) / (elapsed_seconds * speed_bps) * 100.
The previous snapshot's raw `interface_counters` are always available in
the DB, so utilization can be recomputed for any two points in history, not
just consecutive polls.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.models.db import Device, DeviceMetricSnapshot

logger = logging.getLogger("metrics_service")

# Default alert thresholds; overridable per-tenant via
# /api/metrics/thresholds (see routers/metrics.py).
DEFAULT_THRESHOLDS = {
    "cpu_average_pct": 90.0,
    "memory_used_pct": 90.0,
    "interface_utilization_pct": 90.0,
    "interface_error_rate": 0.0,  # any nonzero delta in in/out errors trips this one
}


def _previous_snapshot(db: Session, device_id: str, before: datetime) -> Optional[DeviceMetricSnapshot]:
    return (
        db.query(DeviceMetricSnapshot)
        .filter(DeviceMetricSnapshot.device_id == device_id, DeviceMetricSnapshot.collected_at < before)
        .order_by(desc(DeviceMetricSnapshot.collected_at))
        .first()
    )


def _safe_int(v: Any) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def compute_interface_utilization(
    current_counters: List[Dict[str, Any]],
    previous_counters: List[Dict[str, Any]],
    elapsed_seconds: float,
    interface_speeds_bps: Optional[Dict[str, int]] = None,
) -> List[Dict[str, Any]]:
    """Diff two `interface_health`-shaped counter lists (from the SNMP
    collector's get_health_metrics) and return per-interface utilization.

    Robust to counter wraps/resets (negative or absurd deltas are dropped,
    not reported as-is) and to interfaces appearing/disappearing between
    polls (unmatched if_index rows are simply skipped).
    """
    if elapsed_seconds <= 0:
        return []
    prev_by_index = {row.get("if_index"): row for row in (previous_counters or [])}
    interface_speeds_bps = interface_speeds_bps or {}
    results: List[Dict[str, Any]] = []
    for row in current_counters or []:
        idx = row.get("if_index")
        prev = prev_by_index.get(idx)
        if not prev:
            continue
        in_delta = _safe_int(row.get("in_octets_hc"))
        out_delta = _safe_int(row.get("out_octets_hc"))
        prev_in = _safe_int(prev.get("in_octets_hc"))
        prev_out = _safe_int(prev.get("out_octets_hc"))
        if None in (in_delta, out_delta, prev_in, prev_out):
            continue
        in_delta -= prev_in
        out_delta -= prev_out
        # Counter wrap or device reset -> can't derive a meaningful rate, skip.
        if in_delta < 0 or out_delta < 0:
            continue
        in_bps = (in_delta * 8) / elapsed_seconds
        out_bps = (out_delta * 8) / elapsed_seconds
        speed = interface_speeds_bps.get(idx) or interface_speeds_bps.get(row.get("name"))
        in_util_pct = round(100.0 * in_bps / speed, 2) if speed else None
        out_util_pct = round(100.0 * out_bps / speed, 2) if speed else None

        def _err_delta(field: str) -> Optional[int]:
            cur_v, prev_v = _safe_int(row.get(field)), _safe_int(prev.get(field))
            if cur_v is None or prev_v is None or cur_v < prev_v:
                return None
            return cur_v - prev_v

        results.append({
            "if_index": idx,
            "name": row.get("name"),
            "in_bps": round(in_bps, 2),
            "out_bps": round(out_bps, 2),
            "in_utilization_pct": in_util_pct,
            "out_utilization_pct": out_util_pct,
            "in_errors_delta": _err_delta("in_errors"),
            "out_errors_delta": _err_delta("out_errors"),
            "in_discards_delta": _err_delta("in_discards"),
            "out_discards_delta": _err_delta("out_discards"),
        })
    return results


def record_snapshot(
    db: Session,
    device: Device,
    metrics: Dict[str, Any],
    source: str = "snmp",
    success: bool = True,
    error: Optional[str] = None,
    interface_speeds_bps: Optional[Dict[str, int]] = None,
) -> DeviceMetricSnapshot:
    """Persist one metrics sample and compute interface utilization against
    the immediately-preceding snapshot for this device, if any."""
    now = datetime.utcnow()
    prev = _previous_snapshot(db, device.id, now)
    utilization: List[Dict[str, Any]] = []
    if success and prev and prev.interface_counters:
        elapsed = (now - prev.collected_at).total_seconds()
        utilization = compute_interface_utilization(
            metrics.get("interface_health") or [],
            prev.interface_counters or [],
            elapsed,
            interface_speeds_bps,
        )

    snapshot = DeviceMetricSnapshot(
        tenant_id=device.tenant_id,
        device_id=device.id,
        collected_at=now,
        source=source,
        success=success,
        error=error,
        cpu_average_pct=metrics.get("cpu_average_pct"),
        memory_used_pct=metrics.get("memory_used_pct"),
        memory_total_bytes=metrics.get("memory_total_bytes"),
        memory_used_bytes=metrics.get("memory_used_bytes"),
        interface_counters=metrics.get("interface_health"),
        interface_utilization=utilization,
        environmental=metrics.get("environmental"),
    )
    db.add(snapshot)
    db.commit()
    db.refresh(snapshot)
    return snapshot


def evaluate_thresholds(snapshot: DeviceMetricSnapshot, thresholds: Optional[Dict[str, float]] = None) -> List[Dict[str, Any]]:
    """Return a list of breached-threshold findings for a snapshot -- used
    by the poller worker to raise alerts/events. Pure function so it's
    trivially unit-testable without a DB."""
    t = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    findings: List[Dict[str, Any]] = []
    if snapshot.cpu_average_pct is not None and snapshot.cpu_average_pct >= t["cpu_average_pct"]:
        findings.append({"metric": "cpu_average_pct", "value": snapshot.cpu_average_pct, "threshold": t["cpu_average_pct"]})
    if snapshot.memory_used_pct is not None and snapshot.memory_used_pct >= t["memory_used_pct"]:
        findings.append({"metric": "memory_used_pct", "value": snapshot.memory_used_pct, "threshold": t["memory_used_pct"]})
    for row in snapshot.interface_utilization or []:
        for direction in ("in_utilization_pct", "out_utilization_pct"):
            v = row.get(direction)
            if v is not None and v >= t["interface_utilization_pct"]:
                findings.append({
                    "metric": f"interface.{direction}", "interface": row.get("name") or row.get("if_index"),
                    "value": v, "threshold": t["interface_utilization_pct"],
                })
        for err_field in ("in_errors_delta", "out_errors_delta", "in_discards_delta", "out_discards_delta"):
            v = row.get(err_field)
            if v and v > t["interface_error_rate"]:
                findings.append({
                    "metric": f"interface.{err_field}", "interface": row.get("name") or row.get("if_index"),
                    "value": v, "threshold": t["interface_error_rate"],
                })
    return findings


def history(
    db: Session, device_id: str, tenant_id: str,
    since: Optional[datetime] = None, limit: int = 500,
) -> List[DeviceMetricSnapshot]:
    q = db.query(DeviceMetricSnapshot).filter(
        DeviceMetricSnapshot.device_id == device_id,
        DeviceMetricSnapshot.tenant_id == tenant_id,
    )
    if since:
        q = q.filter(DeviceMetricSnapshot.collected_at >= since)
    return q.order_by(desc(DeviceMetricSnapshot.collected_at)).limit(limit).all()