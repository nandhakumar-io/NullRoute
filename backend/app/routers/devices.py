from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
import anyio

from app.db import get_db
from app.services import observability
from app.models.db import Device, DeviceCredentialRef, DriftEvent, Finding, Scan, Tenant
from app.schemas import DeviceCreate, DeviceOut, ScanDetailOut, ScanOut
from app.services import alert_service, drift_service, openbao_service
from app.services.collectors.registry import get_collector
from app.services.pipeline import run_pipeline

from app.auth.dependencies import CurrentUser, get_current_tenant, get_current_user, require_role

router = APIRouter(prefix="/api/devices", tags=["devices"], dependencies=[Depends(get_current_user)])

DEMO_TENANT_NAME = "SIH-Demo"


def get_or_create_demo_tenant(db: Session) -> Tenant:
    """Retained only for the explicit AUTH_ENABLED=false local/offline demo
    mode (see app/auth/dependencies.py). Every authenticated code path uses
    get_current_tenant() instead -- tenant_id must come from the validated
    identity, never be derived here."""
    tenant = db.query(Tenant).filter(Tenant.name == DEMO_TENANT_NAME).first()
    if not tenant:
        tenant = Tenant(name=DEMO_TENANT_NAME)
        db.add(tenant)
        db.commit()
        db.refresh(tenant)
    return tenant


@router.get("", response_model=List[DeviceOut])
def list_devices(
    limit: int = 500,
    offset: int = 0,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    return (
        db.query(Device)
        .filter(Device.tenant_id == tenant_id)
        .order_by(Device.created_at.desc())
        .offset(offset)
        .limit(min(limit, 2000))
        .all()
    )


@router.post("", response_model=DeviceOut)
def create_device(
    payload: DeviceCreate,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    device = Device(tenant_id=tenant_id, **payload.model_dump())
    db.add(device)
    db.commit()
    db.refresh(device)
    return device


@router.get("/{device_id}", response_model=DeviceOut)
def get_device(
    device_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    # Filtering by tenant_id in the same query (rather than fetching by id
    # and checking after) means another tenant's device is indistinguishable
    # from a nonexistent one -- 404, never 403, so ids can't be enumerated.
    device = db.query(Device).filter(Device.id == device_id, Device.tenant_id == tenant_id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    return device


# ---------------------------------------------------------------------------
# Phase 11 -- configuration drift. Tenant-scoped the same way as
# get_device(): device must belong to this tenant or it's a 404, never a
# lookup-then-403 that would let ids be enumerated across tenants.
@router.get("/{device_id}/drift")
def get_device_drift(
    device_id: str,
    limit: int = 50,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    device = db.query(Device).filter(Device.id == device_id, Device.tenant_id == tenant_id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    events = (
        db.query(DriftEvent)
        .filter(DriftEvent.device_id == device_id, DriftEvent.tenant_id == tenant_id)
        .order_by(DriftEvent.created_at.desc())
        .limit(min(limit, 200))
        .all()
    )
    return {"device_id": device_id, "count": len(events), "events": [drift_service.to_dict(e) for e in events]}


# ---------------------------------------------------------------------------
# Phase 7 -- live device collection. Both /collect and /scan resolve a
# credential reference (Phase 6), pull the actual secret from OpenBao ONLY
# for the duration of this call, run the collector, and record the outcome
# on the Device row. Neither endpoint's response ever contains secret
# material or the raw collected configuration text -- /scan feeds it
# straight into the SAME run_pipeline() used by file uploads and returns
# only the resulting scan (RULE 11: no second compliance implementation).
# ---------------------------------------------------------------------------

class CollectionStatusOut(BaseModel):
    success: bool
    transport: str
    duration_ms: float
    config_hash: Optional[str] = None
    error: Optional[str] = None


class CollectRequest(BaseModel):
    credential_ref_id: Optional[str] = None  # defaults to the device's most recently created ref
    transport: Optional[str] = None  # ssh/netconf/restconf; defaults to the vendor's preferred transport


def _resolve_credentials(db: Session, device: Device, tenant_id: str, credential_ref_id: Optional[str]):
    query = db.query(DeviceCredentialRef).filter(
        DeviceCredentialRef.device_id == device.id, DeviceCredentialRef.tenant_id == tenant_id
    )
    if credential_ref_id:
        ref_row = query.filter(DeviceCredentialRef.id == credential_ref_id).first()
    else:
        ref_row = query.order_by(DeviceCredentialRef.created_at.desc()).first()
    if not ref_row:
        raise HTTPException(400, "No credential reference on file for this device (see /api/devices/{id}/credentials)")

    try:
        return ref_row, openbao_service.get_device_credentials(tenant_id, ref_row.credential_ref)
    except openbao_service.OpenBaoError as e:
        raise HTTPException(502, f"Could not resolve device credentials from OpenBao: {e}") from e


async def _run_collection(db: Session, device: Device, tenant_id: str, payload: CollectRequest):
    ref_row, credentials = _resolve_credentials(db, device, tenant_id, payload.credential_ref_id if payload else None)
    collector = get_collector(device.vendor, transport=payload.transport if payload else None)

    device.collection_status = "IN_PROGRESS"
    db.commit()

    # Collectors are blocking (paramiko/netmiko/ncclient/httpx sync client);
    # run off the event loop so one slow/unreachable device doesn't stall
    # the whole API process.
    result = await anyio.to_thread.run_sync(collector.collect_config, device, credentials)
    # `credentials` (and the closure holding it) goes out of scope here --
    # nothing beyond this point has access to the secret.

    device.collection_status = "SUCCESS" if result.success else "FAILED"
    device.last_collected_at = result.collected_at
    device.last_collection_error = result.error
    device.last_collection_transport = result.transport
    if result.success and result.vendor:
        device.vendor = device.vendor or result.vendor
    db.commit()
    db.refresh(device)
    observability.record_collection_result(success=result.success)
    if not result.success:
        try:
            await alert_service.alert_collection_failure(db, tenant_id, device.id, result.error)
        except Exception:  # noqa: BLE001 - alerting must never fail the collection response
            pass
    return result


@router.post("/{device_id}/collect", response_model=CollectionStatusOut)
async def collect_device_config(
    device_id: str,
    payload: CollectRequest = CollectRequest(),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_role("admin", "operator")),
):
    device = _get_device_or_404_local(db, device_id, tenant_id)
    result = await _run_collection(db, device, tenant_id, payload)
    return CollectionStatusOut(
        success=result.success,
        transport=result.transport,
        duration_ms=result.duration_ms,
        config_hash=result.config_hash,
        error=result.error,
    )


@router.post("/{device_id}/scan", response_model=ScanDetailOut)
async def collect_and_scan_device(
    device_id: str,
    payload: CollectRequest = CollectRequest(),
    framework: str = "ALL",
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_role("admin", "operator")),
):
    device = _get_device_or_404_local(db, device_id, tenant_id)
    result = await _run_collection(db, device, tenant_id, payload)
    if not result.success or not result.raw_config:
        raise HTTPException(502, f"Device collection failed: {result.error or 'no configuration returned'}")

    scan = Scan(tenant_id=tenant_id, device_id=device.id, framework=framework, status="uploaded")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    await run_pipeline(db, scan, result.raw_config, framework=framework)

    db.refresh(scan)
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    return ScanDetailOut(
        **ScanOut.model_validate(scan).model_dump(),
        baseline_json=scan.baseline_json,
        findings=findings,
    )


@router.get("/{device_id}/collection-status", response_model=DeviceOut)
def get_collection_status(
    device_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    return _get_device_or_404_local(db, device_id, tenant_id)


def _get_device_or_404_local(db: Session, device_id: str, tenant_id: str) -> Device:
    device = db.query(Device).filter(Device.id == device_id, Device.tenant_id == tenant_id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    return device


# ---------------------------------------------------------------------------
# Nmap-based network discovery -- a pre-ingestion step alongside config
# upload (Phase 1) and live SSH/NETCONF/RESTCONF/SNMP/gNMI collection
# (Phase 7). /discover only probes the network and reports what it finds;
# it never creates a Device or touches credentials. /discover/import is the
# explicit, human-triggered step that turns selected discovered hosts into
# Device rows -- same "no implicit trust of an unauthenticated scan
# result" boundary as everywhere else in this router.
# ---------------------------------------------------------------------------

from app.services import network_discovery


class DiscoverRequest(BaseModel):
    cidr: str  # e.g. "10.0.0.0/24" or a single host "10.0.0.5"
    ports: Optional[str] = None  # defaults to network_discovery.DEFAULT_PORTS
    service_detection: bool = True


class DiscoveredHostOut(BaseModel):
    ip: str
    hostname: Optional[str] = None
    state: str
    open_ports: List[int]
    transport_hints: List[str]
    vendor_guess: Optional[str] = None
    banner: Optional[str] = None


class DiscoverResponse(BaseModel):
    cidr: str
    host_count: int
    hosts: List[DiscoveredHostOut]


@router.post("/discover", response_model=DiscoverResponse)
async def discover_devices(
    payload: DiscoverRequest,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_role("admin", "operator")),
):
    """Runs an nmap scan of `cidr` and reports responding hosts with any
    management-protocol hints (SSH/Telnet/SNMP/NETCONF/RESTCONF/gNMI ports)
    and a best-effort vendor guess from service-detection banners. Read-only
    -- does not create devices or store anything."""
    try:
        hosts = await anyio.to_thread.run_sync(
            lambda: network_discovery.scan_network(
                payload.cidr,
                ports=payload.ports or network_discovery.DEFAULT_PORTS,
                service_detection=payload.service_detection,
            )
        )
    except network_discovery.NmapUnavailableError as e:
        raise HTTPException(503, str(e)) from e
    except Exception as e:  # noqa: BLE001 -- malformed CIDR, nmap arg errors, etc.
        raise HTTPException(400, f"Discovery scan failed: {e}") from e

    return DiscoverResponse(
        cidr=payload.cidr,
        host_count=len(hosts),
        hosts=[DiscoveredHostOut(**h.to_dict()) for h in hosts],
    )


class ImportDiscoveredHost(BaseModel):
    ip: str
    hostname: Optional[str] = None
    vendor_guess: Optional[str] = None


class ImportDiscoveredRequest(BaseModel):
    hosts: List[ImportDiscoveredHost]


@router.post("/discover/import", response_model=List[DeviceOut])
def import_discovered_devices(
    payload: ImportDiscoveredRequest,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_role("admin", "operator")),
):
    """Turns operator-selected discovery results into Device stubs
    (management_address set, vendor pre-filled from the scan's guess if
    any, collection_status left NEVER_COLLECTED). Skips any IP that is
    already a device's management_address for this tenant, so re-running
    discovery and re-importing is idempotent. A credential reference must
    still be added (see /api/devices/{id}/credentials) before /collect or
    /scan will work -- discovery never handles or infers credentials."""
    existing = {
        d.management_address
        for d in db.query(Device).filter(Device.tenant_id == tenant_id).all()
        if d.management_address
    }
    created: List[Device] = []
    for h in payload.hosts:
        if h.ip in existing:
            continue
        device = Device(
            tenant_id=tenant_id,
            hostname=h.hostname or h.ip,
            management_address=h.ip,
            vendor=h.vendor_guess,
            collection_status="NEVER_COLLECTED",
        )
        db.add(device)
        created.append(device)
        existing.add(h.ip)
    db.commit()
    for d in created:
        db.refresh(d)
    return created