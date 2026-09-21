"""Inventory/topology endpoints (Phase 9).

Reads the real NetworkInterface/VLAN/VRF/NetworkRoute snapshots persisted
by services/topology_batfish_service (Batfish-modelled interfaces, VLAN
membership, VRFs, routes and L3 edges, refreshed by the scan pipeline, the
group scan and POST /api/topology/refresh; regex extractor fallback via
services/topology_service.refresh_device_topology()) and combines them with real SNMP/LLDP-observed
adjacency (services/topology_service.persist_observed_links(), populated by
POST /api/devices/{id}/gateway-get-neighbors) plus subnet-co-membership
inference for anything not directly observed
(services/topology_service.infer_links()).

Previously this router was a stub that fabricated a straight-line chain of
"mock-link" connections between devices regardless of real connectivity --
that has been replaced with the real data path below (RULE 10: never
fabricate a result).
"""
import os
import re
from typing import List, Optional

from fastapi import APIRouter, Body, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth.dependencies import CurrentUser, get_current_tenant, get_current_user, require_role
from app.db import get_db
from app.models.db import VLAN, VRF, Device, NetworkInterface, NetworkRoute, Scan, Tenant
from app.services import minio_service, topology_service
from app.services.vendor_detect import detect_vendor

router = APIRouter(tags=["topology"], dependencies=[Depends(get_current_user)])

MAX_BUILD_FILES = int(os.getenv("TOPOLOGY_BUILD_MAX_FILES", "50"))
MAX_BUILD_FILE_BYTES = 5 * 1024 * 1024


class InterfaceOut(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    ip_address: Optional[str] = None
    subnet_mask: Optional[str] = None
    vlan: Optional[str] = None
    vrf: Optional[str] = None
    admin_state: Optional[str] = None
    switchport_mode: Optional[str] = None
    allowed_vlans: Optional[str] = None
    source: Optional[str] = None

    class Config:
        from_attributes = True


class VlanOut(BaseModel):
    id: str
    vlan_id: str
    name: Optional[str] = None
    interfaces: Optional[List[str]] = None
    source: Optional[str] = None

    class Config:
        from_attributes = True


class RouteOut(BaseModel):
    id: str
    destination: str
    mask: Optional[str] = None
    next_hop: Optional[str] = None
    vrf: Optional[str] = None

    class Config:
        from_attributes = True


class BuildFileResult(BaseModel):
    filename: str
    device_id: str
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    vendor_review_required: bool = False
    family: Optional[str] = None
    interfaces: int = 0
    vlans: int = 0
    vrfs: int = 0
    routes: int = 0
    llm_fallback: dict
    unexplained_lines: int = 0
    total_lines: int = 0
    error: Optional[str] = None


class BuildTopologyOut(BaseModel):
    devices: List[BuildFileResult]
    group_id: Optional[str] = None
    group_name: Optional[str] = None


def _clean_hostname(name: str) -> str:
    name = re.sub(r"\.(cfg|conf|txt|config)$", "", name, flags=re.I)
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_") or "device"


@router.post("/api/topology/build", response_model=BuildTopologyOut,
             dependencies=[Depends(require_role("admin", "operator", "security_analyst"))])
async def build_topology(
    files: List[UploadFile] = File(...),
    group_name: Optional[str] = Form(None),
    use_llm_fallback: bool = Form(True),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    """Build an actual topology (interfaces, VLANs, VRFs, static routes)
    from uploaded configs -- structural parsing only, deterministic first
    (services/structure_parser.py) with genuinely unrecognized lines handed
    to the LLM fallback (services/topology_llm_fallback.py).

    Deliberately does NOT run the compliance-scan pipeline
    (scan_runner.start_scan_task / AI security-parameter normalization /
    OPA findings) -- that is what POST /api/topology/groups/{id}/scan is
    for. This endpoint only answers "what does this network look like",
    not "is it compliant". Each uploaded file becomes its own Device (never
    collapsed into one shared ad-hoc device), so multi-file uploads produce
    an actual multi-node topology instead of one device's snapshot
    overwriting another's.
    """
    if not files:
        raise HTTPException(400, "No files were uploaded")
    if len(files) > MAX_BUILD_FILES:
        raise HTTPException(413, f"Too many files: {len(files)} (max {MAX_BUILD_FILES} per batch)")

    results: List[BuildFileResult] = []
    device_ids: List[str] = []

    for f in files:
        filename = f.filename or "config"
        raw_bytes = await f.read(MAX_BUILD_FILE_BYTES + 1)
        if len(raw_bytes) > MAX_BUILD_FILE_BYTES:
            results.append(BuildFileResult(
                filename=filename, device_id="", llm_fallback={},
                error=f"File too large (max {MAX_BUILD_FILE_BYTES // (1024 * 1024)}MB)",
            ))
            continue
        raw_text = raw_bytes.decode("utf-8", errors="replace")

        guess = detect_vendor(raw_text)
        hostname_m = (
            re.search(r"^hostname\s+(\S+)", raw_text, re.M)
            or re.search(r"^sysname\s+(\S+)", raw_text, re.M)
            or re.search(r"^set system host-name\s+(\S+)", raw_text, re.M)
        )
        hostname = hostname_m.group(1) if hostname_m else _clean_hostname(filename)

        device = Device(
            tenant_id=tenant_id, hostname=hostname,
            vendor=None if guess.review_required else guess.vendor,
            os=None if guess.review_required else guess.os,
        )
        db.add(device)
        db.commit()
        db.refresh(device)

        # A lightweight Scan row purely so raw_config_path / scan_id linkage
        # (minio object key, NetworkInterface.scan_id FK) works the same way
        # it does for the compliance-scan upload path -- but never handed to
        # scan_runner, so no findings/AI-normalization pipeline runs.
        scan = Scan(
            tenant_id=tenant_id, device_id=device.id, framework="ALL",
            status="structural_only", source_filename=filename,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        try:
            key = minio_service.object_key(tenant_id, device.id, scan.id, filename)
            put = minio_service.put_object(key, raw_bytes, content_type="text/plain")
            if put:
                scan.raw_config_path = put.object_key
                db.commit()
        except Exception:  # noqa: BLE001 -- object store optional, extraction below doesn't depend on it
            db.rollback()
            db.add(scan)

        try:
            summary = await topology_service.refresh_device_topology_async(
                db, tenant_id=tenant_id, device_id=device.id, scan_id=scan.id,
                vendor=device.vendor, raw_text=raw_text, use_llm_fallback=use_llm_fallback,
            )
            results.append(BuildFileResult(
                filename=filename, device_id=device.id, hostname=hostname,
                vendor=device.vendor, vendor_review_required=guess.review_required,
                family=summary["family"],
                interfaces=summary["deterministic"]["interfaces"] + summary["llm_fallback"]["interfaces"],
                vlans=summary["deterministic"]["vlans"] + summary["llm_fallback"]["vlans"],
                vrfs=summary["deterministic"]["vrfs"] + summary["llm_fallback"]["vrfs"],
                routes=summary["deterministic"]["routes"] + summary["llm_fallback"]["routes"],
                llm_fallback=summary["llm_fallback"],
                unexplained_lines=summary["unexplained_lines"], total_lines=summary["total_lines"],
            ))
        except Exception as e:  # noqa: BLE001 -- one bad file must not sink the batch
            db.rollback()
            results.append(BuildFileResult(
                filename=filename, device_id=device.id, hostname=hostname, vendor=device.vendor,
                llm_fallback={}, error=str(e),
            ))
        device_ids.append(device.id)

    group_id = group_name_out = None
    if group_name and device_ids:
        from app.models.db import NetworkGroup, NetworkGroupMember
        g = NetworkGroup(tenant_id=tenant_id, name=group_name,
                          description="Auto-built from uploaded configs (POST /api/topology/build).")
        db.add(g)
        db.flush()
        for did in device_ids:
            db.add(NetworkGroupMember(group_id=g.id, device_id=did))
        db.commit()
        db.refresh(g)
        group_id, group_name_out = g.id, g.name

    return BuildTopologyOut(devices=results, group_id=group_id, group_name=group_name_out)


def _get_device_or_404(db: Session, device_id: str, tenant_id: str) -> Device:
    device = db.query(Device).filter(Device.id == device_id, Device.tenant_id == tenant_id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    return device


@router.get("/api/devices/{device_id}/interfaces", response_model=List[InterfaceOut])
def get_device_interfaces(
    device_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant),
):
    _get_device_or_404(db, device_id, tenant_id)
    return (
        db.query(NetworkInterface)
        .filter(NetworkInterface.device_id == device_id, NetworkInterface.tenant_id == tenant_id)
        .order_by(NetworkInterface.name)
        .all()
    )


@router.get("/api/devices/{device_id}/routes", response_model=List[RouteOut])
def get_device_routes(
    device_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant),
):
    _get_device_or_404(db, device_id, tenant_id)
    return (
        db.query(NetworkRoute)
        .filter(NetworkRoute.device_id == device_id, NetworkRoute.tenant_id == tenant_id)
        .all()
    )


@router.get("/api/devices/{device_id}/vlans", response_model=List[VlanOut])
def get_device_vlans(
    device_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant),
):
    _get_device_or_404(db, device_id, tenant_id)
    rows = db.query(VLAN).filter(VLAN.device_id == device_id, VLAN.tenant_id == tenant_id).all()
    return sorted(rows, key=lambda v: int(v.vlan_id) if str(v.vlan_id).isdigit() else 1 << 30)


@router.get("/api/topology/vlans")
def get_vlan_map(db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    """Network-wide VLAN map: each VLAN id with the devices that carry it, the
    member interfaces on each, and (from Batfish) which subnets/SVIs sit on it."""
    devices = {d.id: d for d in db.query(Device).filter(Device.tenant_id == tenant_id).all()}
    ifaces = db.query(NetworkInterface).filter(NetworkInterface.tenant_id == tenant_id).all()
    svi_ips: dict = {}
    for i in ifaces:
        if i.vlan and i.ip_address:
            svi_ips.setdefault((i.device_id, str(i.vlan)), []).append(
                {"interface": i.name, "ip_address": i.ip_address, "subnet_mask": i.subnet_mask})
    vmap: dict = {}
    for v in db.query(VLAN).filter(VLAN.tenant_id == tenant_id).all():
        d = devices.get(v.device_id)
        if d is None:
            continue
        entry = vmap.setdefault(str(v.vlan_id), {"vlan_id": str(v.vlan_id), "name": None, "devices": []})
        entry["name"] = entry["name"] or v.name
        entry["devices"].append({
            "device_id": d.id, "hostname": d.hostname, "interfaces": v.interfaces or [],
            "layer3": svi_ips.get((d.id, str(v.vlan_id)), []), "source": v.source,
        })
    out = sorted(vmap.values(), key=lambda e: int(e["vlan_id"]) if e["vlan_id"].isdigit() else 1 << 30)
    return {"count": len(out), "vlans": out}


@router.post("/api/topology/refresh", dependencies=[Depends(require_role("admin", "operator"))])
async def refresh_topology(
    device_ids: Optional[List[str]] = Body(default=None, embed=True),
    db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant),
):
    """Rebuild topology (interfaces, VLANs, VRFs, routes, L3 links) from the
    latest archived config of each device using Batfish -- regex fallback when
    Batfish is unavailable. Body: optional {"device_ids": [...]} (default: all)."""
    from app.services import minio_service, topology_batfish_service
    from app.models.db import Scan

    q = db.query(Device).filter(Device.tenant_id == tenant_id)
    if device_ids:
        q = q.filter(Device.id.in_(device_ids))
    devices_with_raw, scan_ids, skipped = [], {}, []
    for d in q.all():
        scan = (db.query(Scan).filter(Scan.device_id == d.id, Scan.raw_config_path.isnot(None))
                .order_by(Scan.created_at.desc()).first())
        raw = None
        if scan:
            try:
                raw = minio_service.get_object(scan.raw_config_path).decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                raw = None
        if not raw:
            skipped.append(d.hostname or d.id)
            continue
        devices_with_raw.append((d, raw))
        scan_ids[d.id] = scan.id
    result = await topology_batfish_service.refresh_topology(
        db, tenant_id=tenant_id, devices_with_raw=devices_with_raw, scan_ids=scan_ids, key=f"tenant-{tenant_id}",
    )
    result["skipped_devices"] = skipped
    return result


@router.get("/api/topology")
def get_topology(db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    devices = db.query(Device).filter(Device.tenant_id == tenant_id).all()
    interfaces = db.query(NetworkInterface).filter(NetworkInterface.tenant_id == tenant_id).all()

    iface_count: dict = {}
    vlan_count: dict = {d.id: 0 for d in devices}
    vrf_count: dict = {d.id: 0 for d in devices}
    for i in interfaces:
        iface_count[i.device_id] = iface_count.get(i.device_id, 0) + 1
    for v in db.query(VLAN).filter(VLAN.tenant_id == tenant_id).all():
        vlan_count[v.device_id] = vlan_count.get(v.device_id, 0) + 1
    for v in db.query(VRF).filter(VRF.tenant_id == tenant_id).all():
        vrf_count[v.device_id] = vrf_count.get(v.device_id, 0) + 1

    nodes = [
        {
            "id": d.id,
            "hostname": d.hostname,
            "vendor": d.vendor,
            "model": d.model,
            "management_address": d.management_address,
            "last_compliance_score": d.last_compliance_score,
            "interface_count": iface_count.get(d.id, 0),
            "vlan_count": vlan_count.get(d.id, 0),
            "vrf_count": vrf_count.get(d.id, 0),
        }
        for d in devices
    ]

    links = topology_service.get_topology_links(db, tenant_id, interfaces)

    return {
        "nodes": nodes,
        "links": links,
        # Lets the frontend distinguish "no topology data at all yet" (show
        # an empty state / prompt to scan or run discovery) from "scanned,
        # genuinely no adjacency found".
        "has_interface_data": len(interfaces) > 0,
        "observed_link_count": sum(1 for l in links if l.get("link_type") in ("lldp_observed", "batfish_l3")),
        "batfish_link_count": sum(1 for l in links if l.get("link_type") == "batfish_l3"),
        "inferred_link_count": sum(1 for l in links if l.get("link_type") not in ("lldp_observed", "batfish_l3")),
    }