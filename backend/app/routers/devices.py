from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.db import Device, Tenant
from app.schemas import DeviceCreate, DeviceOut, DeviceUpdate

from app.auth.dependencies import get_current_user

router = APIRouter(prefix="/api/devices", tags=["devices"], dependencies=[Depends(get_current_user)])

DEMO_TENANT_NAME = "SIH-Demo"


def get_or_create_demo_tenant(db: Session) -> Tenant:
    tenant = db.query(Tenant).filter(Tenant.name == DEMO_TENANT_NAME).first()
    if not tenant:
        tenant = Tenant(name=DEMO_TENANT_NAME)
        db.add(tenant)
        db.commit()
        db.refresh(tenant)
    return tenant


@router.get("", response_model=List[DeviceOut])
def list_devices(db: Session = Depends(get_db)):
    return db.query(Device).order_by(Device.created_at.desc()).all()


@router.post("", response_model=DeviceOut)
def create_device(payload: DeviceCreate, db: Session = Depends(get_db)):
    tenant = get_or_create_demo_tenant(db)
    device = Device(tenant_id=tenant.id, **payload.model_dump())
    db.add(device)
    db.commit()
    db.refresh(device)
    return device


@router.get("/{device_id}", response_model=DeviceOut)
def get_device(device_id: str, db: Session = Depends(get_db)):
    device = db.query(Device).get(device_id)
    if not device:
        raise HTTPException(404, "Device not found")
    return device

@router.patch("/{device_id}", response_model=DeviceOut)
def update_device(device_id: str, payload: DeviceUpdate, db: Session = Depends(get_db)):
    device = db.query(Device).get(device_id)
    if not device:
        raise HTTPException(404, "Device not found")
        
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(device, key, value)
        
    db.commit()
    db.refresh(device)
    return device

@router.post("/{device_id}/test-connection")
def test_connection(device_id: str, db: Session = Depends(get_db)):
    device = db.query(Device).get(device_id)
    if not device:
        raise HTTPException(404, "Device not found")
        
    import time
    # Simulate ping / SSH verification phase for the demonstration topology.
    time.sleep(0.5)
    return {
        "success": True,
        "transport": device.protocol or "NETCONF",
        "duration_ms": 500
    }

@router.post("/{device_id}/collect")
def collect_configuration(device_id: str, db: Session = Depends(get_db)):
    device = db.query(Device).get(device_id)
    if not device:
        raise HTTPException(404, "Device not found")
        
    import time
    time.sleep(1.2)
    device.collection_status = "SUCCESS"
    db.commit()
    
    return {
        "success": True,
        "transport": "SSH",
        "duration_ms": 1200
    }

@router.post("/{device_id}/scan")
async def run_scan(device_id: str, framework: str = "ALL", db: Session = Depends(get_db)):
    from app.models.db import Scan, Finding
    from app.schemas import ScanDetailOut, ScanOut
    from app.services.pipeline import run_pipeline
    import os
    
    device = db.query(Device).get(device_id)
    if not device:
        raise HTTPException(404, "Device not found")
        
    cfg_path = "/home/kenpachi-zaraki/NetSecAuditor/sample_configs/demo_cisco_ios_xe.cfg"
    with open(cfg_path, "r") as f:
        raw_text = f.read()
        
    device.last_config_raw = raw_text
    
    scan = Scan(
        tenant_id=device.tenant_id,
        device_id=device.id,
        status="uploaded",
        framework=framework
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    # Run the real evaluation pipeline
    await run_pipeline(db, scan, raw_text, framework=framework)
    
    db.refresh(scan)
    db.refresh(device)
    
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    return ScanDetailOut(
        **ScanOut.model_validate(scan).model_dump(),
        baseline_json=scan.baseline_json,
        findings=findings,
        batfish_result=scan.batfish_result
    )
