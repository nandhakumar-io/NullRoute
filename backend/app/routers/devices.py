import anyio
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.db import Base, Device, Tenant
from app.schemas import DeviceCreate, DeviceOut, DeviceUpdate

from app.auth.dependencies import get_current_user, get_current_tenant
from app.services.collectors.registry import get_collector

router = APIRouter(prefix="/api/devices", tags=["devices"], dependencies=[Depends(get_current_user)])

DEMO_TENANT_NAME = "SIH-Demo"


class BulkDeviceIds(BaseModel):
    device_ids: List[str]


def get_or_create_demo_tenant(db: Session) -> Tenant:
    tenant = db.query(Tenant).filter(Tenant.name == DEMO_TENANT_NAME).first()
    if not tenant:
        tenant = Tenant(name=DEMO_TENANT_NAME)
        db.add(tenant)
        db.commit()
        db.refresh(tenant)
    return tenant


def _scoped_query(db: Session, tenant_id: str):
    """Every device read goes through here. RULE: cross-tenant isolation --
    a device row belonging to another tenant must never be visible, not
    even by guessing its id (see tests/test_cross_tenant_isolation_matrix.py).
    """
    return db.query(Device).filter(Device.tenant_id == tenant_id)


def _cascade_delete_device_rows(db: Session, device_id: str) -> None:
    """Delete every row in every table that references this device before
    deleting the device itself, so DELETE /api/devices/{id} never 500s with
    a ForeignKeyViolation once the device has scans/evidence/etc. attached.

    Generic over Base.metadata rather than a hand-maintained table list --
    devices.id is referenced from ~20 tables (scans, findings, evidence,
    deployment records, topology links, ...) and a static list silently
    drifts out of date as new FK'd tables are added. Column names that
    reference devices.id are device_id, source_device_id, or
    target_device_id (see NetworkLink); all three are covered.
    """
    from sqlalchemy import delete as sa_delete

    device_fk_cols = ("device_id", "source_device_id", "target_device_id")
    for table in Base.metadata.sorted_tables:
        if table.name == "devices":
            continue
        for col_name in device_fk_cols:
            col = table.columns.get(col_name)
            if col is not None and any(fk.column.table.name == "devices" for fk in col.foreign_keys):
                db.execute(sa_delete(table).where(col == device_id))


@router.get("", response_model=dict)
def list_devices(db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    items = _scoped_query(db, tenant_id).order_by(Device.created_at.desc()).all()
    return {"items": [DeviceOut.model_validate(d) for d in items], "count": len(items)}


@router.post("", response_model=DeviceOut)
def create_device(payload: DeviceCreate, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    if payload.management_address:
        existing = _scoped_query(db, tenant_id).filter(
            Device.management_address == payload.management_address
        ).first()
        if existing:
            raise HTTPException(
                409,
                f"Device with management_address {payload.management_address} already exists (id={existing.id})",
            )
    device = Device(tenant_id=tenant_id, **payload.model_dump())
    db.add(device)
    db.commit()
    db.refresh(device)
    return device


@router.get("/{device_id}", response_model=DeviceOut)
def get_device(device_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    device = _scoped_query(db, tenant_id).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    return device


@router.get("/{device_id}/collection-status")
def get_collection_status(device_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    device = _scoped_query(db, tenant_id).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    return {
        "device_id": device.id,
        "enabled": device.enabled,
        "collection_status": device.collection_status,
        "last_collected_at": device.last_collected_at,
        "last_collection_error": device.last_collection_error,
        "last_collection_transport": device.last_collection_transport,
    }


@router.patch("/{device_id}", response_model=DeviceOut)
def update_device(device_id: str, payload: DeviceUpdate, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    device = _scoped_query(db, tenant_id).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(404, "Device not found")

    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(device, key, value)

    db.commit()
    db.refresh(device)
    return device


@router.delete("/{device_id}", status_code=204)
def delete_device(device_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    device = _scoped_query(db, tenant_id).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    _cascade_delete_device_rows(db, device_id)
    db.delete(device)
    db.commit()
    return None


@router.post("/bulk/delete")
def bulk_delete_devices(payload: BulkDeviceIds, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    devices = _scoped_query(db, tenant_id).filter(Device.id.in_(payload.device_ids)).all()
    affected_ids = [d.id for d in devices]
    for device in devices:
        _cascade_delete_device_rows(db, device.id)
        db.delete(device)
    db.commit()
    return {"requested": len(payload.device_ids), "affected": len(affected_ids), "device_ids": affected_ids}


@router.post("/bulk/enable")
def bulk_enable_devices(payload: BulkDeviceIds, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    devices = _scoped_query(db, tenant_id).filter(Device.id.in_(payload.device_ids)).all()
    for device in devices:
        device.enabled = True
    db.commit()
    return {"requested": len(payload.device_ids), "affected": len(devices), "device_ids": [d.id for d in devices]}


@router.post("/bulk/disable")
def bulk_disable_devices(payload: BulkDeviceIds, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    devices = _scoped_query(db, tenant_id).filter(Device.id.in_(payload.device_ids)).all()
    for device in devices:
        device.enabled = False
    db.commit()
    return {"requested": len(payload.device_ids), "affected": len(devices), "device_ids": [d.id for d in devices]}


@router.post("/{device_id}/test-connection")
def test_connection(device_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    device = _scoped_query(db, tenant_id).filter(Device.id == device_id).first()
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
def collect_configuration(device_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    """Live-collect the device's running configuration over its resolved
    transport (SSH/NETCONF/RESTCONF/gNMI, per get_collector(vendor)) and
    archive the raw config + hash on the device row.

    Previously this endpoint was a demo stub (time.sleep + hardcoded
    SUCCESS) that never actually talked to a device or a credential
    store -- device.last_collection_error/collection_status were being
    set to values that didn't reflect reality. This wires it to the same
    collector registry and credential resolution path scans/deploys
    already use (RULE 11: no second collection implementation).
    """
    from app.services.deployment_service import _resolve_credentials
    from app.services import openbao_service

    device = _scoped_query(db, tenant_id).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(404, "Device not found")

    try:
        credentials = _resolve_credentials(db, device, tenant_id)
    except (ValueError, openbao_service.OpenBaoError) as e:
        device.collection_status = "FAILED"
        device.last_collection_error = f"Could not resolve device credentials: {e}"
        db.commit()
        raise HTTPException(400, f"Could not resolve device credentials: {e}")

    collector = get_collector(device.vendor, transport=device.protocol)
    result = collector.collect_config(device, credentials)

    device.collection_status = "SUCCESS" if result.success else "FAILED"
    device.last_collected_at = result.collected_at
    device.last_collection_error = None if result.success else result.error
    device.last_collection_transport = result.transport
    if result.success and result.raw_config:
        device.last_config_raw = result.raw_config
    db.commit()

    if not result.success:
        raise HTTPException(502, f"Collection failed over {result.transport}: {result.error}")

    return {
        "success": True,
        "transport": result.transport,
        "duration_ms": result.duration_ms,
        "config_hash": result.config_hash,
    }

@router.post("/{device_id}/scan")
async def run_scan(device_id: str, framework: str = "ALL", db: Session = Depends(get_db), current_user=Depends(get_current_user), tenant_id: str = Depends(get_current_tenant)):
    from app.models.db import Scan, Finding
    from app.schemas import ScanDetailOut, ScanOut
    from app.services.pipeline import run_pipeline
    from app.services.deployment_service import _resolve_credentials
    from app.services import openbao_service

    device = _scoped_query(db, tenant_id).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(404, "Device not found")

    # Collect the running config via the same collector the /collect endpoint
    # uses (RULE 11: no second collection implementation). The gateway job
    # queue path requires live MinIO + gateway infra; direct collection is
    # always available and is the correct lower-level primitive here.
    try:
        credentials = _resolve_credentials(db, device, tenant_id)
    except (ValueError, openbao_service.OpenBaoError) as e:
        raise HTTPException(400, f"Could not resolve device credentials: {e}")

    collector = get_collector(device.vendor, transport=device.protocol)
    result = await anyio.to_thread.run_sync(collector.collect_config, device, credentials)
    del credentials

    if not result.success or not result.raw_config:
        raise HTTPException(502, f"Collection failed: {result.error or 'no config returned'}")

    raw_text = result.raw_config
    device.last_config_raw = raw_text
    device.collection_status = "SUCCESS"
    device.last_collected_at = result.collected_at
    device.last_collection_transport = result.transport
    db.commit()

    scan = Scan(
        tenant_id=tenant_id,
        device_id=device.id,
        status="uploaded",
        framework=framework,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    await run_pipeline(db, scan, raw_text, framework=framework)
    db.refresh(scan)
    db.refresh(device)

    # Best-effort backup export -- never allowed to fail the scan.
    try:
        from app.services import backup_destination_service
        backup_destination_service.auto_export_after_scan(db, device, scan)
    except Exception:
        pass

    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    return ScanDetailOut(
        **ScanOut.model_validate(scan).model_dump(),
        baseline_json=scan.baseline_json,
        findings=findings,
        batfish_result=scan.batfish_result if hasattr(scan, "batfish_result") else None,
    )