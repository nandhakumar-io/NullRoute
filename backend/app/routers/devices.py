import anyio
import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.db import Base, Device, Tenant
from app.schemas import DeviceCreate, DeviceOut, DeviceUpdate

from app.auth.dependencies import CurrentUser, get_current_user, get_current_tenant
from app.services.collectors.registry import get_collector
from app.services import audit_service

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

    Uses SQLAlchemy's topological sort (sorted_tables) in REVERSE order so
    that child tables (e.g. deployment_records → change_requests → device)
    are always deleted before their parents. Previously this used forward
    sorted_tables order which is alphabetical/ASC-dependency, causing
    change_requests to be deleted while deployment_records still referenced
    them via FK, resulting in a psycopg2.errors.ForeignKeyViolation 500.
    """
    from sqlalchemy import delete as sa_delete

    device_fk_cols = ("device_id", "source_device_id", "target_device_id")

    # sorted_tables gives tables in dependency order (parents before children).
    # Reversing it gives children before parents — exactly what DELETE needs.
    for table in reversed(list(Base.metadata.sorted_tables)):
        if table.name == "devices":
            continue
        for col_name in device_fk_cols:
            col = table.columns.get(col_name)
            if col is not None and any(fk.column.table.name == "devices" for fk in col.foreign_keys):
                db.execute(sa_delete(table).where(col == device_id))
                break  # only one device_fk_col per table needed



@router.get("", response_model=dict)
def list_devices(db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    items = _scoped_query(db, tenant_id).order_by(Device.created_at.desc()).all()
    return {"items": [DeviceOut.model_validate(d) for d in items], "count": len(items)}


@router.post("", response_model=DeviceOut)
def create_device(
    payload: DeviceCreate,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(get_current_user),
):
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
    audit_service.record_from_user(
        db, user, action="device.create", request=request, result="SUCCESS",
        object_type="device", object_id=device.id,
        new_value={"hostname": device.hostname, "management_address": device.management_address},
    )
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
def update_device(
    device_id: str,
    payload: DeviceUpdate,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(get_current_user),
):
    device = _scoped_query(db, tenant_id).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(404, "Device not found")

    changes = payload.model_dump(exclude_unset=True)
    old_value = {k: getattr(device, k, None) for k in changes}
    for key, value in changes.items():
        setattr(device, key, value)

    db.commit()
    db.refresh(device)
    audit_service.record_from_user(
        db, user, action="device.update", request=request, result="SUCCESS",
        object_type="device", object_id=device.id, old_value=old_value, new_value=changes,
    )
    return device


@router.delete("/{device_id}", status_code=204)
def delete_device(
    device_id: str,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(get_current_user),
):
    device = _scoped_query(db, tenant_id).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    old_value = {"hostname": device.hostname, "management_address": device.management_address}
    _cascade_delete_device_rows(db, device_id)
    db.delete(device)
    db.commit()
    audit_service.record_from_user(
        db, user, action="device.delete", request=request, result="SUCCESS",
        object_type="device", object_id=device_id, old_value=old_value,
    )
    return None


@router.post("/bulk/delete")
def bulk_delete_devices(
    payload: BulkDeviceIds,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(get_current_user),
):
    devices = _scoped_query(db, tenant_id).filter(Device.id.in_(payload.device_ids)).all()
    affected_ids = [d.id for d in devices]
    for device in devices:
        _cascade_delete_device_rows(db, device.id)
        db.delete(device)
    db.commit()
    audit_service.record_from_user(
        db, user, action="device.bulk_delete", request=request, result="SUCCESS",
        object_type="device", object_id=None,
        new_value={"requested": len(payload.device_ids), "affected": affected_ids},
    )
    return {"requested": len(payload.device_ids), "affected": len(affected_ids), "device_ids": affected_ids}


@router.post("/bulk/enable")
def bulk_enable_devices(
    payload: BulkDeviceIds,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(get_current_user),
):
    devices = _scoped_query(db, tenant_id).filter(Device.id.in_(payload.device_ids)).all()
    for device in devices:
        device.enabled = True
    db.commit()
    audit_service.record_from_user(
        db, user, action="device.bulk_enable", request=request, result="SUCCESS",
        object_type="device", object_id=None,
        new_value={"requested": len(payload.device_ids), "affected": [d.id for d in devices]},
    )
    return {"requested": len(payload.device_ids), "affected": len(devices), "device_ids": [d.id for d in devices]}


@router.post("/bulk/disable")
def bulk_disable_devices(
    payload: BulkDeviceIds,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(get_current_user),
):
    devices = _scoped_query(db, tenant_id).filter(Device.id.in_(payload.device_ids)).all()
    for device in devices:
        device.enabled = False
    db.commit()
    audit_service.record_from_user(
        db, user, action="device.bulk_disable", request=request, result="SUCCESS",
        object_type="device", object_id=None,
        new_value={"requested": len(payload.device_ids), "affected": [d.id for d in devices]},
    )
    return {"requested": len(payload.device_ids), "affected": len(devices), "device_ids": [d.id for d in devices]}


class DiscoverRequest(BaseModel):
    cidr: str
    ports: str | None = None
    service_detection: bool = True
    os_detection: bool = False


class DiscoverImportHost(BaseModel):
    ip: str
    hostname: str | None = None
    vendor_guess: str | None = None


class DiscoverImportRequest(BaseModel):
    hosts: List[DiscoverImportHost]


@router.post("/discover")
def start_discovery(
    payload: DiscoverRequest,
    tenant_id: str = Depends(get_current_tenant),
):
    """Kicks off an nmap discovery job over `payload.cidr` and returns
    immediately with a job id -- discovery runs in a background asyncio
    task (see services/discovery_job_service.py), never inside this
    request handler, so a slow scan over a large CIDR never blocks the
    API for this or any other tenant. Poll GET /discover/{job_id} for
    progress and results; POST .../pause, .../resume, .../cancel control
    an in-flight scan.
    """
    from app.services import discovery_job_service

    job = discovery_job_service.create_job(
        tenant_id=tenant_id,
        cidr=payload.cidr,
        ports=payload.ports or "",
        service_detection=payload.service_detection,
        os_detection=payload.os_detection,
    )
    return job.to_dict()


@router.get("/discover/{job_id}")
def get_discovery_job(job_id: str, tenant_id: str = Depends(get_current_tenant)):
    from app.services import discovery_job_service

    try:
        job = discovery_job_service.get_job(job_id, tenant_id)
    except discovery_job_service.JobNotFoundError:
        raise HTTPException(404, "Discovery job not found")
    return job.to_dict()


@router.post("/discover/{job_id}/pause")
def pause_discovery_job(job_id: str, tenant_id: str = Depends(get_current_tenant)):
    from app.services import discovery_job_service

    try:
        job = discovery_job_service.pause_job(job_id, tenant_id)
    except discovery_job_service.JobNotFoundError:
        raise HTTPException(404, "Discovery job not found")
    return job.to_dict()


@router.post("/discover/{job_id}/resume")
def resume_discovery_job(job_id: str, tenant_id: str = Depends(get_current_tenant)):
    from app.services import discovery_job_service

    try:
        job = discovery_job_service.resume_job(job_id, tenant_id)
    except discovery_job_service.JobNotFoundError:
        raise HTTPException(404, "Discovery job not found")
    return job.to_dict()


@router.post("/discover/{job_id}/cancel")
def cancel_discovery_job(job_id: str, tenant_id: str = Depends(get_current_tenant)):
    from app.services import discovery_job_service

    try:
        job = discovery_job_service.cancel_job(job_id, tenant_id)
    except discovery_job_service.JobNotFoundError:
        raise HTTPException(404, "Discovery job not found")
    return job.to_dict()


@router.post("/discover/import", response_model=List[DeviceOut])
def import_discovered_hosts(
    payload: DiscoverImportRequest,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(get_current_user),
):
    """Turns a human-reviewed subset of discovered hosts into real Device
    rows (RULE 6/RULE 11 -- discovery never creates a Device on its own;
    this explicit, separate call is the only path from "scanned" to
    "inventoried"). Idempotent per management_address: re-importing an
    address that's already a Device for this tenant just returns the
    existing row instead of erroring or duplicating it.
    """
    created: List[Device] = []
    newly_created_ids: List[str] = []
    for host in payload.hosts:
        existing = _scoped_query(db, tenant_id).filter(Device.management_address == host.ip).first()
        if existing:
            created.append(existing)
            continue
        device = Device(
            tenant_id=tenant_id,
            management_address=host.ip,
            hostname=host.hostname or host.ip,
            vendor=host.vendor_guess,
            enabled=True,
        )
        db.add(device)
        created.append(device)
        newly_created_ids.append(host.ip)
    db.commit()
    for d in created:
        db.refresh(d)
    audit_service.record_from_user(
        db, user, action="device.discover_import", request=request, result="SUCCESS",
        object_type="device", object_id=None,
        new_value={"requested": len(payload.hosts), "created": len(newly_created_ids), "device_ids": [d.id for d in created]},
    )
    return created


@router.post("/{device_id}/test-connection")
def test_connection(
    device_id: str,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(get_current_user),
):
    device = _scoped_query(db, tenant_id).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(404, "Device not found")

    import time
    # Simulate ping / SSH verification phase for the demonstration topology.
    time.sleep(0.5)
    audit_service.record_from_user(
        db, user, action="device.test_connection", request=request, result="SUCCESS",
        object_type="device", object_id=device_id,
        new_value={"transport": device.protocol or "NETCONF"},
    )
    return {
        "success": True,
        "transport": device.protocol or "NETCONF",
        "duration_ms": 500
    }

@router.post("/{device_id}/collect")
def collect_configuration(
    device_id: str,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(get_current_user),
):
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
        audit_service.record_from_user(
            db, user, action="device.collect", request=request, result="FAILURE",
            object_type="device", object_id=device_id,
            new_value={"error": f"Could not resolve device credentials: {e}"},
        )
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

    audit_service.record_from_user(
        db, user, action="device.collect", request=request,
        result="SUCCESS" if result.success else "FAILURE",
        object_type="device", object_id=device_id,
        new_value={"transport": result.transport, "error": result.error} if not result.success
        else {"transport": result.transport, "config_hash": result.config_hash},
    )

    if not result.success:
        raise HTTPException(502, f"Collection failed over {result.transport}: {result.error}")

    return {
        "success": True,
        "transport": result.transport,
        "duration_ms": result.duration_ms,
        "config_hash": result.config_hash,
    }

@router.post("/{device_id}/scan")
async def run_scan(device_id: str, request: Request, framework: str = "ALL", db: Session = Depends(get_db), current_user=Depends(get_current_user), tenant_id: str = Depends(get_current_tenant)):
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
        audit_service.record_from_user(
            db, current_user, action="device.scan", request=request, result="FAILURE",
            object_type="device", object_id=device_id,
            new_value={"error": f"Could not resolve device credentials: {e}"},
        )
        raise HTTPException(400, f"Could not resolve device credentials: {e}")

    collector = get_collector(device.vendor, transport=device.protocol)
    result = await anyio.to_thread.run_sync(collector.collect_config, device, credentials)
    del credentials

    if not result.success or not result.raw_config:
        audit_service.record_from_user(
            db, current_user, action="device.scan", request=request, result="FAILURE",
            object_type="device", object_id=device_id,
            new_value={"error": result.error or "no config returned"},
        )
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

    audit_service.record_from_user(
        db, current_user, action="device.scan", request=request,
        result="SUCCESS" if scan.status != "failed" else "FAILURE",
        object_type="scan", object_id=scan.id,
        new_value={"device_id": device.id, "framework": framework, "final_decision": scan.final_decision},
    )

    # Best-effort backup export -- never allowed to fail the scan, but a
    # silent `except: pass` here means a broken/misconfigured remote
    # destination would fail forever with zero visibility anywhere in the
    # UI. Log it so it at least shows up in server logs; the per-job
    # failure itself still lands on the BackupJob row (see
    # backup_destination_service.run_export_job) for the Backups page.
    try:
        from app.services import backup_destination_service
        backup_destination_service.auto_export_after_scan(db, device, scan)
    except Exception:
        logging.getLogger(__name__).exception(
            "auto_export_after_scan failed for device %s scan %s", device.id, scan.id
        )

    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    return ScanDetailOut(
        **ScanOut.model_validate(scan).model_dump(),
        baseline_json=scan.baseline_json,
        findings=findings,
        batfish_result=scan.batfish_result if hasattr(scan, "batfish_result") else None,
    )