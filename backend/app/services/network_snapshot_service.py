"""
Phase 10 -- builds the CURRENT vs PROPOSED multi-device snapshot pair for one
scan's `/api/scans/{id}/snapshot-diff` and delegates the actual Batfish work
to services/batfish_service.compare_network_snapshots().

CURRENT  = every tenant device's most recent *other* completed scan's raw
           config (i.e. the state of the network right before this scan).
PROPOSED = the same set, with this scan's device substituted for the config
           being evaluated by this scan.

This never invents a config for a device that has no prior successful scan
-- such a device is simply omitted from both snapshots, and if that leaves
either snapshot empty (or the device this scan is for is Batfish-unsupported)
Batfish itself reports BATFISH_UNSUPPORTED rather than us fabricating a
result (RULE 13 / RULE 10).
"""
from __future__ import annotations

from typing import Any, Dict, List

from sqlalchemy.orm import Session

from app.models.db import Device, Scan
from app.services import batfish_service, minio_service


def _latest_raw_config(db: Session, device: Device, exclude_scan_id: str = None) -> Dict[str, str] | None:
    q = db.query(Scan).filter(Scan.device_id == device.id, Scan.raw_config_path.isnot(None))
    if exclude_scan_id:
        q = q.filter(Scan.id != exclude_scan_id)
    scan = q.order_by(Scan.created_at.desc()).first()
    if not scan or not scan.raw_config_path:
        return None
    try:
        raw = minio_service.get_object(scan.raw_config_path).decode("utf-8", errors="replace")
    except Exception:
        return None
    if not batfish_service.is_vendor_supported(device.vendor):
        return None
    return {"hostname": device.hostname or device.id, "raw_config": raw}


def build_snapshot_diff(db: Session, scan: Scan) -> Dict[str, Any]:
    device = db.query(Device).filter(Device.id == scan.device_id).first()
    if device is None:
        return {"status": "BATFISH_UNSUPPORTED", "detail": "Device for this scan no longer exists."}

    other_devices = (
        db.query(Device)
        .filter(Device.tenant_id == scan.tenant_id, Device.id != device.id)
        .all()
    )

    current_devices: List[Dict[str, str]] = []
    proposed_devices: List[Dict[str, str]] = []

    # This device's OWN pre-scan config (CURRENT) vs this scan's config
    # (PROPOSED). If there's no prior successful scan for this device, the
    # CURRENT side simply won't include it -- not fabricated as "unchanged".
    this_device_current = _latest_raw_config(db, device, exclude_scan_id=scan.id)
    if this_device_current is not None:
        current_devices.append(this_device_current)

    if batfish_service.is_vendor_supported(device.vendor) and scan.raw_config_path:
        try:
            proposed_raw = minio_service.get_object(scan.raw_config_path).decode("utf-8", errors="replace")
            proposed_devices.append({"hostname": device.hostname or device.id, "raw_config": proposed_raw})
        except Exception:
            pass

    for other in other_devices:
        cfg = _latest_raw_config(db, other)
        if cfg is not None:
            current_devices.append(cfg)
            proposed_devices.append(cfg)  # unchanged in the PROPOSED world

    if not proposed_devices:
        return {
            "status": "BATFISH_UNSUPPORTED",
            "detail": "No Batfish-supported configuration available for this scan's device "
                      "(unsupported vendor, or the raw configuration could not be retrieved).",
        }

    result = batfish_service.compare_network_snapshots(scan.id, current_devices, proposed_devices)
    result["device_id"] = device.id
    result["scan_id"] = scan.id
    result["devices_in_current"] = [d["hostname"] for d in current_devices]
    result["devices_in_proposed"] = [d["hostname"] for d in proposed_devices]
    return result