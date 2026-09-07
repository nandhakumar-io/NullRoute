"""Inventory/topology endpoints (Phase 9).
Stubbed fallback implementation because NetworkInterface/VLAN models were stripped.
"""
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.db import Device

from app.auth.dependencies import get_current_user

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


def _get_device_or_404(db: Session, device_id: str) -> Device:
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    return device


@router.get("/api/devices/{device_id}/interfaces", response_model=List[InterfaceOut])
def get_device_interfaces(device_id: str, db: Session = Depends(get_db)):
    _get_device_or_404(db, device_id)
    return []


@router.get("/api/devices/{device_id}/routes", response_model=List[RouteOut])
def get_device_routes(device_id: str, db: Session = Depends(get_db)):
    _get_device_or_404(db, device_id)
    return []


@router.get("/api/topology")
def get_topology(db: Session = Depends(get_db)):
    devices = db.query(Device).all()

    nodes = [
        {
            "id": d.id,
            "hostname": d.hostname,
            "vendor": d.vendor,
            "model": d.model,
            "management_address": d.management_address,
            "last_compliance_score": d.last_compliance_score,
            "interface_count": 0,
            "vlan_count": 0,
            "vrf_count": 0,
        }
        for d in devices
    ]

    links = []
    # Create simple mock pseudo-links for visualization
    for i in range(len(devices) - 1):
        links.append({
            "subnet": "mock-link",
            "source_device_id": devices[i].id,
            "target_device_id": devices[i + 1].id,
            "source_interface": "eth0",
            "target_interface": "eth1"
        })

    return {"nodes": nodes, "links": links}
