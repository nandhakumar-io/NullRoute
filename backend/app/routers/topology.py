"""Inventory/topology endpoints (Phase 9).

GET /api/topology                 -- devices as nodes + inferred links
GET /api/devices/{id}/interfaces  -- current interface snapshot for a device
GET /api/devices/{id}/routes      -- current static-route snapshot for a device

All tenant-scoped: filtering by tenant_id in the same query means another
tenant's device/interfaces/routes are indistinguishable from nonexistent
(404, never 403) -- consistent with every other router in this codebase.
"""
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.db import Device, NetworkInterface, NetworkRoute, VLAN, VRF
from app.services.topology_service import infer_links

from app.auth.dependencies import get_current_tenant, get_current_user

router = APIRouter(tags=["topology"], dependencies=[Depends(get_current_user)])


class InterfaceOut(BaseModel):
    id: str
    name: str
    description: str | None = None
    ip_address: str | None = None
    subnet_mask: str | None = None
    vlan: str | None = None
    vrf: str | None = None
    admin_state: str | None = None

    class Config:
        from_attributes = True


class RouteOut(BaseModel):
    id: str
    destination: str
    mask: str | None = None
    next_hop: str | None = None
    vrf: str | None = None

    class Config:
        from_attributes = True


def _get_device_or_404(db: Session, device_id: str, tenant_id: str) -> Device:
    device = db.query(Device).filter(Device.id == device_id, Device.tenant_id == tenant_id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    return device


@router.get("/api/devices/{device_id}/interfaces", response_model=List[InterfaceOut])
def get_device_interfaces(device_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    _get_device_or_404(db, device_id, tenant_id)
    return (
        db.query(NetworkInterface)
        .filter(NetworkInterface.device_id == device_id, NetworkInterface.tenant_id == tenant_id)
        .order_by(NetworkInterface.name)
        .all()
    )


@router.get("/api/devices/{device_id}/routes", response_model=List[RouteOut])
def get_device_routes(device_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    _get_device_or_404(db, device_id, tenant_id)
    return (
        db.query(NetworkRoute)
        .filter(NetworkRoute.device_id == device_id, NetworkRoute.tenant_id == tenant_id)
        .order_by(NetworkRoute.destination)
        .all()
    )


@router.get("/api/topology")
def get_topology(db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    devices = db.query(Device).filter(Device.tenant_id == tenant_id).all()
    interfaces = db.query(NetworkInterface).filter(NetworkInterface.tenant_id == tenant_id).all()
    vlans = db.query(VLAN).filter(VLAN.tenant_id == tenant_id).all()
    vrfs = db.query(VRF).filter(VRF.tenant_id == tenant_id).all()

    ifaces_by_device: dict = {}
    for i in interfaces:
        ifaces_by_device.setdefault(i.device_id, []).append(i)

    nodes = [
        {
            "id": d.id,
            "hostname": d.hostname,
            "vendor": d.vendor,
            "model": d.model,
            "management_address": d.management_address,
            "last_compliance_score": d.last_compliance_score,
            "interface_count": len(ifaces_by_device.get(d.id, [])),
            "vlan_count": sum(1 for v in vlans if v.device_id == d.id),
            "vrf_count": sum(1 for v in vrfs if v.device_id == d.id),
        }
        for d in devices
    ]

    # Links are inferred fresh from current interface IPs every call --
    # never persisted as fact (see topology_service.infer_links docstring).
    links = infer_links(interfaces)

    return {"nodes": nodes, "links": links}
