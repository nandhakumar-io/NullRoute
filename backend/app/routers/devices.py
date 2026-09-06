from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import text
import anyio

from app.db import get_db
from app.services import observability
from app.models.db import Device, DeviceCredentialRef, DriftEvent, Finding, Scan, Tenant
from app.schemas import (BulkDeviceRequest, BulkDeviceResult, DeviceCreate,
                          DeviceListOut, DeviceOut, DeviceUpdate, ScanDetailOut, ScanOut)
from app.services import alert_service, audit_service, drift_service, openbao_service
from app.services.collectors.registry import (credential_type_matches_transport,
                                                get_collector, preferred_transport)
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


DEVICE_SORT_COLUMNS = {
    "name": Device.name,
    "hostname": Device.hostname,
    "vendor": Device.vendor,
    "site": Device.site,
    "environment": Device.environment,
    "collection_status": Device.collection_status,
    "last_scan_at": Device.last_scan_at,
    "last_compliance_score": Device.last_compliance_score,
    "created_at": Device.created_at,
    "updated_at": Device.updated_at,
}


@router.get("", response_model=DeviceListOut)
def list_devices(
    limit: int = 50,
    offset: int = 0,
    search: Optional[str] = None,
    vendor: Optional[str] = None,
    site: Optional[str] = None,
    environment: Optional[str] = None,
    protocol: Optional[str] = None,
    enabled: Optional[bool] = None,
    collection_status: Optional[str] = None,
    sort_by: str = "created_at",
    sort_dir: str = "desc",
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    """List devices for the current tenant with search/filter/sort/pagination.

    `search` matches name/hostname/management_address/serial_number
    case-insensitively. All other filters are exact-match. `total` in the
    response is the filtered count (not the page size), so the UI can
    render real pagination controls rather than guessing from page length.
    """
    q = db.query(Device).filter(Device.tenant_id == tenant_id)

    if search:
        like = f"%{search.strip()}%"
        q = q.filter(
            (Device.name.ilike(like))
            | (Device.hostname.ilike(like))
            | (Device.management_address.ilike(like))
            | (Device.serial_number.ilike(like))
        )
    if vendor:
        q = q.filter(Device.vendor == vendor)
    if site:
        q = q.filter(Device.site == site)
    if environment:
        q = q.filter(Device.environment == environment)
    if protocol:
        q = q.filter(Device.protocol == protocol)
    if enabled is not None:
        q = q.filter(Device.enabled == enabled)
    if collection_status:
        q = q.filter(Device.collection_status == collection_status)

    total = q.count()

    sort_col = DEVICE_SORT_COLUMNS.get(sort_by, Device.created_at)
    sort_col = sort_col.asc() if sort_dir == "asc" else sort_col.desc()
    items = q.order_by(sort_col).offset(offset).limit(min(limit, 500)).all()

    return DeviceListOut(items=items, total=total, limit=limit, offset=offset)


@router.post("", response_model=DeviceOut)
def create_device(
    payload: DeviceCreate,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_role("admin", "operator")),
):
    # Guard against duplicate inventory entries: a re-submitted "Add Device"
    # click (double-click, retried request, or re-importing the same host)
    # must not silently create a second row for the same management IP.
    if payload.management_address:
        existing = (
            db.query(Device)
            .filter(
                Device.tenant_id == tenant_id,
                Device.management_address == payload.management_address,
            )
            .first()
        )
        if existing:
            raise HTTPException(
                409,
                f"A device with management address {payload.management_address} already exists "
                f"(id={existing.id}). Edit the existing device instead of creating a new one.",
            )

    device = Device(tenant_id=tenant_id, **payload.model_dump())
    db.add(device)
    db.commit()
    db.refresh(device)
    audit_service.record_from_user(
        db, user, "device.create", request,
        object_type="device", object_id=device.id,
        new_value={"hostname": device.hostname, "management_address": device.management_address},
    )
    return device


@router.patch("/{device_id}", response_model=DeviceOut)
def update_device(
    device_id: str,
    payload: DeviceUpdate,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_role("admin", "operator")),
):
    device = _get_device_or_404_local(db, device_id, tenant_id)
    changes = payload.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(device, field, value)
    db.commit()
    db.refresh(device)
    if changes:
        audit_service.record_from_user(
            db, user, "device.update", request,
            object_type="device", object_id=device.id, new_value=changes,
        )
    return device


@router.delete("/{device_id}", status_code=204)
def delete_device(
    device_id: str,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_role("admin")),
):
    """Admin-only: deletes the device row. Scan/finding/drift/evidence
    history is retained (foreign keys are not cascade-deleted here) so
    compliance evidence never disappears just because the device inventory
    entry was removed -- consistent with RULE 15 (historical rows are never
    destroyed)."""
    device = _get_device_or_404_local(db, device_id, tenant_id)
    # Manually cascade delete dependent rows to avoid PostgreSQL ForeignKeyViolations.
    # We do this directly via core SQL to bypass ORM cascade configurations.
    tables = [
        "ai_analyses", "alerts", "baseline_approvals", "change_requests",
        "compliance_exceptions", "deployment_records", "device_credential_refs",
        "drift_events", "gateway_jobs", "network_interfaces", "network_routes",
        "security_drift_findings", "vlans", "vrfs"
    ]
    for table_name in tables:
        db.execute(text(f"DELETE FROM {table_name} WHERE device_id = :id"), {"id": device.id})
    db.execute(text("DELETE FROM network_links WHERE source_device_id = :id OR target_device_id = :id"), {"id": device.id})
    # Also cascade delete any tables that reference scan_id
    scan_tables = [
        "batfish_analyses", "opa_analyses", "evidence_records", "findings",
        "report_artifacts",
    ]
    for table_name in scan_tables:
        db.execute(text(f"DELETE FROM {table_name} WHERE scan_id IN (SELECT id FROM scans WHERE device_id = :id)"), {"id": device.id})
    db.execute(text("DELETE FROM scans WHERE device_id = :id"), {"id": device.id})

    db.delete(device)
    db.commit()
    audit_service.record_from_user(
        db, user, "device.delete", request, object_type="device", object_id=device_id,
    )
    return None


@router.post("/bulk/enable", response_model=BulkDeviceResult)
def bulk_enable_devices(
    payload: BulkDeviceRequest,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_role("admin", "operator")),
):
    return _bulk_set_enabled(db, tenant_id, payload.device_ids, True, user, request)


@router.post("/bulk/disable", response_model=BulkDeviceResult)
def bulk_disable_devices(
    payload: BulkDeviceRequest,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_role("admin", "operator")),
):
    return _bulk_set_enabled(db, tenant_id, payload.device_ids, False, user, request)


@router.post("/bulk/delete", response_model=BulkDeviceResult)
def bulk_delete_devices(
    payload: BulkDeviceRequest,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_role("admin")),
):
    """The frontend (api.ts: bulkDeleteDevices) has always called this
    endpoint; it never existed on the backend, so every bulk-delete request
    404'd. Reuses the same cascade-delete logic as the single-device
    DELETE route so history/evidence retention stays consistent."""
    affected: List[str] = []
    for device_id in payload.device_ids:
        device = (
            db.query(Device)
            .filter(Device.id == device_id, Device.tenant_id == tenant_id)
            .first()
        )
        if not device:
            continue
        tables = [
            "ai_analyses", "alerts", "baseline_approvals", "change_requests",
            "compliance_exceptions", "deployment_records", "device_credential_refs",
            "drift_events", "gateway_jobs", "network_interfaces", "network_routes",
            "security_drift_findings", "vlans", "vrfs"
        ]
        for table_name in tables:
            db.execute(text(f"DELETE FROM {table_name} WHERE device_id = :id"), {"id": device.id})
        db.execute(text("DELETE FROM network_links WHERE source_device_id = :id OR target_device_id = :id"), {"id": device.id})
        scan_tables = [
            "batfish_analyses", "opa_analyses", "evidence_records", "findings",
            "report_artifacts",
        ]
        for table_name in scan_tables:
            db.execute(text(f"DELETE FROM {table_name} WHERE scan_id IN (SELECT id FROM scans WHERE device_id = :id)"), {"id": device.id})
        db.execute(text("DELETE FROM scans WHERE device_id = :id"), {"id": device.id})
        db.delete(device)
        affected.append(device_id)
    db.commit()
    for device_id in affected:
        audit_service.record_from_user(
            db, user, "device.delete", request, object_type="device", object_id=device_id,
        )
    return BulkDeviceResult(requested=len(payload.device_ids), affected=len(affected), device_ids=affected)


def _bulk_set_enabled(db, tenant_id, device_ids, enabled, user, request):
    devices = (
        db.query(Device)
        .filter(Device.id.in_(device_ids), Device.tenant_id == tenant_id)
        .all()
    )
    for d in devices:
        d.enabled = enabled
    db.commit()
    audit_service.record_from_user(
        db, user, "device.bulk_enable" if enabled else "device.bulk_disable", request,
        object_type="device", new_value={"device_ids": [d.id for d in devices]},
    )
    return BulkDeviceResult(requested=len(device_ids), affected=len(devices), device_ids=[d.id for d in devices])


# NOTE: the /bulk/* routes above must be registered before /{device_id}/*
# routes below -- Starlette matches path routes in registration order, and
# "/bulk/enable" would otherwise be captured by "/{device_id}/enable" with
# device_id="bulk".
@router.post("/{device_id}/enable", response_model=DeviceOut)
def enable_device(
    device_id: str,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_role("admin", "operator")),
):
    device = _get_device_or_404_local(db, device_id, tenant_id)
    device.enabled = True
    db.commit()
    db.refresh(device)
    audit_service.record_from_user(db, user, "device.enable", request, object_type="device", object_id=device_id)
    return device


@router.post("/{device_id}/disable", response_model=DeviceOut)
def disable_device(
    device_id: str,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_role("admin", "operator")),
):
    """Disabling a device excludes it from scheduled scans/audits (see
    services/scheduling_service.py) without deleting its history. It is
    the reversible alternative to DELETE."""
    device = _get_device_or_404_local(db, device_id, tenant_id)
    device.enabled = False
    db.commit()
    db.refresh(device)
    audit_service.record_from_user(db, user, "device.disable", request, object_type="device", object_id=device_id)
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
# Parts 2, 6, 7, 8, 9 -- configuration snapshots, golden/approved baseline,
# normalized security-baseline drift history, and compliance posture
# history. A `Scan` already carries everything a "configuration snapshot"
# needs (raw_config_path in MinIO, raw_config_hash, baseline_json, PostgreSQL
# metadata) per Part 14 ("reuse existing abstractions"/"don't create
# duplicate implementations") -- these endpoints expose that data under the
# snapshot/baseline/history vocabulary the spec asks for, rather than
# introducing a second config-storage model.
# ---------------------------------------------------------------------------
from app.models.db import BaselineApproval, SecurityDriftFinding  # noqa: E402
from app.services import security_baseline_drift  # noqa: E402
from app.services.evidence_service import PARSER_VERSION  # noqa: E402

NORMALIZATION_VERSION = "1.0.0"  # SecurityBaselineModel schema version (models/baseline.py)


def _snapshot_dict(scan: Scan, device: Device) -> dict:
    return {
        "snapshot_id": scan.id,
        "scan_id": scan.id,
        "tenant_id": scan.tenant_id,
        "device_id": scan.device_id,
        "vendor": device.vendor,
        "platform": device.os,
        "collected_at": scan.created_at.isoformat() if scan.created_at else None,
        "source": "device-gateway" if scan.raw_config_path and scan.status != "uploaded" else "upload",
        "configuration_hash": scan.raw_config_hash,
        "raw_config_reference": scan.raw_config_path,
        "parser_version": PARSER_VERSION,
        "normalization_version": NORMALIZATION_VERSION,
        "compliance_score": scan.compliance_score,
        "final_decision": scan.final_decision,
    }


def _get_device_or_404(db: Session, device_id: str, tenant_id: str) -> Device:
    device = db.query(Device).filter(Device.id == device_id, Device.tenant_id == tenant_id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    return device


def _get_snapshot_or_404(db: Session, device_id: str, tenant_id: str, snapshot_id: str) -> Scan:
    scan = (
        db.query(Scan)
        .filter(Scan.id == snapshot_id, Scan.device_id == device_id, Scan.tenant_id == tenant_id)
        .first()
    )
    if not scan:
        raise HTTPException(404, "Snapshot not found")
    return scan


@router.get("/{device_id}/snapshots")
def list_snapshots(
    device_id: str,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    device = _get_device_or_404(db, device_id, tenant_id)
    scans = (
        db.query(Scan)
        .filter(Scan.device_id == device_id, Scan.tenant_id == tenant_id)
        .order_by(Scan.created_at.desc())
        .offset(offset)
        .limit(min(limit, 200))
        .all()
    )
    current_approval = (
        db.query(BaselineApproval)
        .filter(BaselineApproval.device_id == device_id, BaselineApproval.tenant_id == tenant_id)
        .order_by(BaselineApproval.approved_at.desc())
        .first()
    )
    approved_scan_id = current_approval.scan_id if current_approval else None
    out = []
    for scan in scans:
        row = _snapshot_dict(scan, device)
        row["is_approved_baseline"] = scan.id == approved_scan_id
        out.append(row)
    return {"device_id": device_id, "count": len(out), "snapshots": out}


@router.get("/{device_id}/snapshots/{snapshot_id}")
def get_snapshot(
    device_id: str,
    snapshot_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    device = _get_device_or_404(db, device_id, tenant_id)
    scan = _get_snapshot_or_404(db, device_id, tenant_id, snapshot_id)
    approval = (
        db.query(BaselineApproval)
        .filter(BaselineApproval.device_id == device_id, BaselineApproval.tenant_id == tenant_id,
                BaselineApproval.scan_id == scan.id)
        .order_by(BaselineApproval.approved_at.desc())
        .first()
    )
    result = _snapshot_dict(scan, device)
    result["baseline"] = scan.baseline_json
    if approval:
        result["approval"] = {
            "approved_by": approval.approved_by,
            "approved_at": approval.approved_at.isoformat() if approval.approved_at else None,
            "approval_reason": approval.approval_reason,
        }
    return result


class BaselineApprovalRequest(BaseModel):
    approval_reason: Optional[str] = None


@router.post("/{device_id}/baselines/{snapshot_id}/approve")
def approve_baseline(
    device_id: str,
    snapshot_id: str,
    payload: BaselineApprovalRequest,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_role("admin", "operator")),
):
    """Part 6: sets `snapshot_id` (a Scan) as the device's approved golden
    baseline. Does NOT assume the latest configuration is automatically
    trusted -- an operator/admin must explicitly call this. History is kept
    (a new row per approval, never an update-in-place), and the *current*
    approved baseline is simply the row with the most recent approved_at,
    consistent with the read side above."""
    _get_device_or_404(db, device_id, tenant_id)
    scan = _get_snapshot_or_404(db, device_id, tenant_id, snapshot_id)

    approval = BaselineApproval(
        tenant_id=tenant_id,
        device_id=device_id,
        scan_id=scan.id,
        approved_by=getattr(user, "username", None) or getattr(user, "subject", "unknown"),
        approval_reason=payload.approval_reason,
    )
    db.add(approval)
    db.commit()
    db.refresh(approval)

    audit_service.record_from_user(
        db, user, "baseline.approve", request,
        object_type="device", object_id=device_id,
        new_value={"snapshot_id": scan.id, "approval_reason": payload.approval_reason},
    )

    return {
        "device_id": device_id,
        "snapshot_id": scan.id,
        "approved_by": approval.approved_by,
        "approved_at": approval.approved_at.isoformat() if approval.approved_at else None,
        "approval_reason": approval.approval_reason,
    }


@router.get("/{device_id}/drift/history")
def get_device_drift_history(
    device_id: str,
    limit: int = 100,
    drift_type: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    """Part 7/9: the normalized SecurityBaselineModel drift feed (severity +
    drift_type classification + OPA compliance correlation), distinct from
    the raw line-diff feed at GET /{device_id}/drift above."""
    _get_device_or_404(db, device_id, tenant_id)
    q = db.query(SecurityDriftFinding).filter(
        SecurityDriftFinding.device_id == device_id, SecurityDriftFinding.tenant_id == tenant_id,
    )
    if drift_type:
        q = q.filter(SecurityDriftFinding.drift_type == drift_type)
    if status:
        q = q.filter(SecurityDriftFinding.status == status)
    findings = q.order_by(SecurityDriftFinding.detected_at.desc()).limit(min(limit, 500)).all()
    return {
        "device_id": device_id,
        "count": len(findings),
        "findings": [security_baseline_drift.to_dict(f) for f in findings],
    }


@router.get("/{device_id}/compliance/history")
def get_device_compliance_history(
    device_id: str,
    limit: int = 100,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    """Part 8: historical compliance-score/finding-count series for a
    device, one entry per completed scan, oldest first, plus a plain-English
    delta between the two most recent points (e.g. "Compliance decreased by
    13 percentage points."), correlated against any normalized security
    drift detected between those same two scans."""
    _get_device_or_404(db, device_id, tenant_id)
    scans = (
        db.query(Scan)
        .filter(Scan.device_id == device_id, Scan.tenant_id == tenant_id, Scan.compliance_score.isnot(None))
        .order_by(Scan.created_at.asc())
        .limit(min(limit, 500))
        .all()
    )

    points = []
    for scan in scans:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in db.query(Finding).filter(Finding.scan_id == scan.id, Finding.result == "FAIL").all():
            if f.severity in counts:
                counts[f.severity] += 1
        points.append({
            "scan_id": scan.id,
            "scanned_at": scan.created_at.isoformat() if scan.created_at else None,
            "compliance_score": scan.compliance_score,
            "final_decision": scan.final_decision,
            "counts": counts,
        })

    summary = None
    correlated_drift = []
    if len(points) >= 2:
        prev_point, cur_point = points[-2], points[-1]
        delta = (cur_point["compliance_score"] or 0) - (prev_point["compliance_score"] or 0)
        direction = "increased" if delta > 0 else "decreased" if delta < 0 else "did not change"
        summary = (
            f"Compliance {direction} by {abs(round(delta, 1))} percentage points "
            f"between {prev_point['scanned_at']} and {cur_point['scanned_at']}."
            if delta != 0 else f"Compliance did not change between the two most recent scans."
        )
        correlated = (
            db.query(SecurityDriftFinding)
            .filter(
                SecurityDriftFinding.device_id == device_id,
                SecurityDriftFinding.tenant_id == tenant_id,
                SecurityDriftFinding.previous_scan_id == prev_point["scan_id"],
                SecurityDriftFinding.current_scan_id == cur_point["scan_id"],
                SecurityDriftFinding.drift_type.in_(("SECURITY_DEGRADATION", "SECURITY_IMPROVEMENT", "COMPLIANCE_IMPACT")),
            )
            .all()
        )
        correlated_drift = [security_baseline_drift.to_dict(f) for f in correlated]

    return {
        "device_id": device_id,
        "count": len(points),
        "history": points,
        "summary": summary,
        "correlated_drift": correlated_drift,
    }


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


def _resolve_credentials(db: Session, device: Device, tenant_id: str, credential_ref_id: Optional[str],
                          transport: Optional[str] = None):
    """Resolve the credential ref to use for a collection/test call.

    When `credential_ref_id` is given explicitly, it's used verbatim (the
    caller made a deliberate choice). Otherwise, if the device has more than
    one credential ref on file (e.g. both an `ssh_password` and a
    `snmp_community` row -- see Devices page "Authentication" section),
    the ref whose `credential_type` actually matches the transport being
    used is preferred. Without this, `.order_by(created_at.desc()).first()`
    would always return whichever credential was saved most recently,
    regardless of which transport the caller asked for -- e.g. selecting
    SNMP in the Ingestion UI but silently authenticating over SSH using the
    SNMP community string as a (nonexistent) username/password, which
    surfaces as a confusing paramiko "No authentication methods available"
    error. Falls back to most-recent if nothing matches, to preserve
    behavior for devices with only one credential ref on file.
    """
    query = db.query(DeviceCredentialRef).filter(
        DeviceCredentialRef.device_id == device.id, DeviceCredentialRef.tenant_id == tenant_id
    )
    if credential_ref_id:
        ref_row = query.filter(DeviceCredentialRef.id == credential_ref_id).first()
    else:
        candidates = query.order_by(DeviceCredentialRef.created_at.desc()).all()
        ref_row = None
        if transport:
            ref_row = next((c for c in candidates if credential_type_matches_transport(c.credential_type, transport)), None)
        if ref_row is None:
            ref_row = candidates[0] if candidates else None
    if not ref_row:
        raise HTTPException(400, "No credential reference on file for this device (see /api/devices/{id}/credentials)")

    try:
        return ref_row, openbao_service.get_device_credentials(tenant_id, ref_row.credential_ref)
    except openbao_service.OpenBaoError as e:
        raise HTTPException(502, f"Could not resolve device credentials from OpenBao: {e}") from e


async def _run_collection(db: Session, device: Device, tenant_id: str, payload: CollectRequest):
    transport = (payload.transport if payload else None) or preferred_transport(device.vendor)
    ref_row, credentials = _resolve_credentials(
        db, device, tenant_id, payload.credential_ref_id if payload else None, transport=transport,
    )
    collector = get_collector(device.vendor, transport=transport)

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


class TestConnectionRequest(BaseModel):
    credential_ref_id: Optional[str] = None
    transport: Optional[str] = None


@router.post("/{device_id}/test-connection", response_model=CollectionStatusOut)
async def test_device_connection(
    device_id: str,
    payload: TestConnectionRequest = TestConnectionRequest(),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_role("admin", "operator")),
):
    """Reachability/auth check only -- reuses the same collector transports
    as /collect, but does not persist collection_status/last_collected_at
    on the Device row (that's what distinguishes a "Test Connection" click
    from a real "Collect Configuration"/"Audit Now" action). Nothing beyond
    this function ever sees the resolved credentials."""
    device = _get_device_or_404_local(db, device_id, tenant_id)
    transport = payload.transport or preferred_transport(device.vendor)
    ref_row, credentials = _resolve_credentials(db, device, tenant_id, payload.credential_ref_id, transport=transport)
    collector = get_collector(device.vendor, transport=transport)
    result = await anyio.to_thread.run_sync(collector.collect_config, device, credentials)
    return CollectionStatusOut(
        success=result.success,
        transport=result.transport,
        duration_ms=result.duration_ms,
        config_hash=result.config_hash,
        error=result.error,
    )


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