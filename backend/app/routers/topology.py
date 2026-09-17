"""Inventory/topology endpoints (Phase 9).

Reads the real NetworkInterface/VLAN/VRF/NetworkRoute snapshots persisted
by services/topology_service.refresh_device_topology() (populated from
config text via services/topology_extractor.py during the scan pipeline,
see services/pipeline.py) and combines them with real SNMP/LLDP-observed
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

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_tenant, get_current_user
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
        "observed_link_count": sum(1 for l in links if l.get("link_type") == "lldp_observed"),
        "inferred_link_count": sum(1 for l in links if l.get("link_type") != "lldp_observed"),
    }
