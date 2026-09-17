"""Device Gateway-backed endpoints (Part 9 / Part 11).

These endpoints replace direct device connectivity in `routers/devices.py`
for the operations the gateway now serves: the API authenticates the user,
builds a signed job envelope carrying THAT identity, and hands it to the
Device Gateway (`app.gateway.publisher.submit_job`) instead of calling a
collector directly. `routers/devices.py`'s existing `/collect` and `/scan`
endpoints are left as-is (Part 14: don't break the existing system) but new
callers should prefer these.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth.dependencies import CurrentUser, get_current_tenant, get_current_user
from app.db import get_db
from app.gateway import metrics as gateway_metrics
from app.gateway.envelope import READ_ONLY_OPERATIONS
from app.gateway.publisher import submit_job
from app.models.db import Device
from app.services import audit_service

router = APIRouter(prefix="/api/devices", tags=["device-gateway"], dependencies=[Depends(get_current_user)])


class GatewayJobRequest(BaseModel):
    protocol: Optional[str] = None  # defaults to the vendor's preferred transport
    payload: Optional[Dict[str, Any]] = None


def _get_device(db: Session, device_id: str, tenant_id: str) -> Device:
    device = db.query(Device).filter(Device.id == device_id, Device.tenant_id == tenant_id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    return device


def _default_protocol(device: Device) -> str:
    from app.services.collectors.registry import preferred_transport
    return preferred_transport(device.vendor)


async def _run_operation(
    request: Request,
    device_id: str,
    operation: str,
    payload: Optional[GatewayJobRequest],
    db: Session,
    tenant_id: str,
    user: CurrentUser,
) -> dict:
    device = _get_device(db, device_id, tenant_id)
    protocol = (payload.protocol if payload else None) or _default_protocol(device)
    result = await submit_job(
        db,
        tenant_id=tenant_id,
        requester_id=getattr(user, "subject", None) or getattr(user, "username", "unknown"),
        device_id=device_id,
        operation=operation,
        protocol=protocol,
        payload=(payload.payload if payload else None),
    )
    audit_service.record_from_user(
        db, user, f"gateway.{operation.lower()}", request,
        result="SUCCESS" if result.get("success") else "FAILURE",
        object_type="device", object_id=device_id,
        new_value={"job_id": result.get("job_id"), "error_code": result.get("error_code")},
    )
    if not result.get("success"):
        # `detail` must always carry a plain, human-readable message under a
        # stable key -- every frontend caller reads `detail.error` first
        # (see DeviceDetail.tsx pollSnmp/discoverNeighbors). Returning the
        # raw job-result dict as `detail` (no top-level "error" key) meant
        # that lookup missed, fell through to `detail` itself, and a React
        # component ended up trying to render the whole object -- "Objects
        # are not valid as a React child" -- instead of the error message.
        raise HTTPException(
            502,
            detail={
                "error": result.get("error_message") or result.get("error_code") or "Gateway operation failed",
                **result,
            },
        )
    return result


@router.post("/{device_id}/audit")
async def audit_device(
    device_id: str,
    request: Request,
    payload: Optional[GatewayJobRequest] = None,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(get_current_user),
):
    return await _run_operation(request, device_id, "AUDIT", payload, db, tenant_id, user)


@router.post("/{device_id}/gateway-fetch-config")
async def fetch_config(
    device_id: str,
    request: Request,
    payload: Optional[GatewayJobRequest] = None,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(get_current_user),
):
    return await _run_operation(request, device_id, "FETCH_CONFIG", payload, db, tenant_id, user)


@router.post("/{device_id}/gateway-get-facts")
async def get_facts(
    device_id: str,
    request: Request,
    payload: Optional[GatewayJobRequest] = None,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(get_current_user),
):
    """Retrieve structured device identity facts (hostname, vendor, OS version,
    uptime) via the transport's native facts mechanism (e.g. SNMP MIB-II GET,
    SSH `show version`). Collectors that don't implement a dedicated facts hook
    fall back to collecting the full running config and deriving facts from it."""
    return await _run_operation(request, device_id, "GET_FACTS", payload, db, tenant_id, user)


@router.post("/{device_id}/gateway-get-interfaces")
async def get_interfaces(
    device_id: str,
    request: Request,
    payload: Optional[GatewayJobRequest] = None,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(get_current_user),
):
    """Retrieve structured per-interface state (name, admin/oper status, speed,
    IP address, MAC) via the transport's native interface table mechanism
    (e.g. SNMP IF-MIB walk, SSH `show ip interface brief`). Collectors that
    don't implement a dedicated interface hook fall back to collecting the full
    running config."""
    return await _run_operation(request, device_id, "GET_INTERFACES", payload, db, tenant_id, user)


@router.post("/{device_id}/gateway-get-health-metrics")
async def get_health_metrics(
    device_id: str,
    request: Request,
    payload: Optional[GatewayJobRequest] = None,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(get_current_user),
):
    """Retrieve live health/performance metrics -- CPU load, memory
    utilization, and per-interface traffic/error/discard counters --
    distinct from gateway-get-facts (static identity) and
    gateway-get-interfaces (admin/oper status only). Currently only the SNMP
    transport implements this (HOST-RESOURCES-MIB + IF-MIB high-capacity
    counters); other transports return a clear "not implemented" error via
    the collector's NotImplementedError fallback rather than fabricating
    zeros."""
    return await _run_operation(request, device_id, "GET_HEALTH_METRICS", payload, db, tenant_id, user)


@router.post("/{device_id}/gateway-get-neighbors")
async def get_neighbors(
    device_id: str,
    request: Request,
    payload: Optional[GatewayJobRequest] = None,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(get_current_user),
):
    """Retrieve this device's directly-observed Layer-2 neighbors (LLDP-MIB
    over SNMP today) -- local port to remote system/port identity -- and
    persist them as real NetworkLink rows so the topology page can draw
    actual discovered adjacency instead of only its subnet-co-membership
    inference. Collectors that don't implement neighbor discovery yet
    return a clear "not implemented" error rather than fabricating a link."""
    result = await _run_operation(request, device_id, "GET_NEIGHBORS", payload, db, tenant_id, user)
    neighbors = (result.get("normalized_data") or {}).get("neighbors", [])
    from app.services import topology_service
    stored = topology_service.persist_observed_links(db, tenant_id=tenant_id, device_id=device_id, neighbors=neighbors)
    result["links_stored"] = stored
    return result


@router.get("/gateway/metrics")
def gateway_metrics_endpoint():
    return gateway_metrics.snapshot()


@router.get("/gateway/operations")
def gateway_supported_operations():
    return {"read_only_operations": sorted(READ_ONLY_OPERATIONS)}