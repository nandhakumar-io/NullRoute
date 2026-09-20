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
from typing import List, Optional

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_tenant, get_current_user, require_role
from app.db import get_db
from app.models.db import VLAN, VRF, Device, NetworkInterface, NetworkRoute
from app.services import topology_service

router = APIRouter(tags=["topology"], dependencies=[Depends(get_current_user)])


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