"""Phase 14 -- Change Requests.

POST /api/change-requests               operator/admin: create + validate
GET  /api/change-requests                any authenticated tenant member
GET  /api/change-requests/{id}
POST /api/change-requests/{id}/approve   admin/security_analyst
POST /api/change-requests/{id}/reject    admin/security_analyst
"""
from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.auth.dependencies import (CurrentUser, get_current_tenant,
                                    get_current_user, require_permission, require_role)
from app.db import get_db
from app.models.db import ChangeRequest, Device, DeploymentRecord, RollbackRecord
from app.services import (alert_service, audit_service, blast_radius_service,
                          change_request_service, deployment_service, minio_service,
                          rollback_service)
from app.auth.rbac import Permission

logger = logging.getLogger("change_request_router")

router = APIRouter(prefix="/api/change-requests", tags=["change-requests"],
                    dependencies=[Depends(get_current_user)])


def _get_owned(db: Session, tenant_id: str, cr_id: str) -> ChangeRequest:
    cr = db.query(ChangeRequest).filter(
        ChangeRequest.id == cr_id, ChangeRequest.tenant_id == tenant_id,
    ).first()
    if not cr:
        raise HTTPException(404, "Change request not found")
    return cr


@router.post("/preview")
def preview_change_request(
    device_id: str = Body(...),
    snippet: str = Body(..., description="CLI remediation delta to merge onto the device's current config"),
    current_config: Optional[str] = Body(None, description="Override the device's last-known config as the merge base"),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    _user: CurrentUser = Depends(require_role("admin", "operator")),
):
    """Read-only preview of the merge engine's output for a CLI
    remediation delta -- shows the merged config, per-line applied-commands
    breakdown, and confidence/warnings, without creating anything. A
    reviewer previews, then POSTs the same device_id/snippet to `` (create)
    once satisfied."""
    device = db.query(Device).filter(Device.id == device_id, Device.tenant_id == tenant_id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    return change_request_service.preview_merge(db, device=device, snippet=snippet, current_config=current_config)


@router.post("")
async def create_change_request(
    device_id: str = Body(...),
    proposed_config: Optional[str] = Body(None, description="A complete proposed configuration"),
    snippet: Optional[str] = Body(None, description="A CLI remediation delta, merged via the merge engine instead"),
    current_config: Optional[str] = Body(None, description="Override the device's last-known config as the merge base"),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_role("admin", "operator")),
):
    device = db.query(Device).filter(Device.id == device_id, Device.tenant_id == tenant_id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    if (proposed_config is None) == (snippet is None):
        raise HTTPException(400, "Provide exactly one of proposed_config or snippet")
    cr = await change_request_service.create_and_validate(
        db, tenant_id=tenant_id, device=device,
        proposed_config=proposed_config, snippet=snippet, current_config=current_config,
        created_by=user.username, source="manual",
    )
    return change_request_service.to_dict(cr)


@router.get("")
def list_change_requests(
    status: Optional[str] = None,
    device_id: Optional[str] = None,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    q = db.query(ChangeRequest).filter(ChangeRequest.tenant_id == tenant_id)
    if status:
        q = q.filter(ChangeRequest.status == status)
    if device_id:
        q = q.filter(ChangeRequest.device_id == device_id)
    rows = q.order_by(ChangeRequest.created_at.desc()).limit(200).all()
    return {"count": len(rows), "change_requests": [change_request_service.to_dict(c) for c in rows]}


@router.get("/{cr_id}")
def get_change_request(cr_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    return change_request_service.to_dict(_get_owned(db, tenant_id, cr_id))


@router.get("/{cr_id}/configs")
def get_change_request_configs(cr_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    """Raw CURRENT and PROPOSED config text for the before/after diff viewer.
    Read-only: fetches the archived blobs from object storage by the hashes
    already recorded on the ChangeRequest -- never mutates anything and is
    reachable by any authenticated tenant member (same visibility as GET
    /{cr_id}), since reviewers must be able to see what they're approving."""
    cr = _get_owned(db, tenant_id, cr_id)
    current_config = None
    proposed_config = None
    if cr.current_config_object_key:
        try:
            current_config = minio_service.get_object(cr.current_config_object_key).decode("utf-8", errors="replace")
        except Exception:
            current_config = None
    if cr.proposed_config_object_key:
        try:
            proposed_config = minio_service.get_object(cr.proposed_config_object_key).decode("utf-8", errors="replace")
        except Exception:
            proposed_config = None
    return {
        "current_config": current_config,
        "proposed_config": proposed_config,
        "current_config_hash": cr.current_config_hash,
        "proposed_config_hash": cr.proposed_config_hash,
    }


@router.get("/{cr_id}/blast-radius")
def get_change_request_blast_radius(
    cr_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    """Projected impact of this change: new vulnerability exposure, compliance
    violations, and reachability severance — plus per-node states for the
    topology canvas.

    Read-only and derived entirely from analysis already recorded at
    validation time (see services/blast_radius_service.py). Same visibility
    as GET /{cr_id}: a reviewer has to be able to see what they're approving.
    """
    cr = _get_owned(db, tenant_id, cr_id)
    device = db.query(Device).filter(Device.id == cr.device_id).first()

    current_config = None
    proposed_config = None
    if cr.current_config_object_key:
        try:
            current_config = minio_service.get_object(cr.current_config_object_key).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001 - a missing blob degrades the report, never 500s it
            current_config = None
    if cr.proposed_config_object_key:
        try:
            proposed_config = minio_service.get_object(cr.proposed_config_object_key).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            proposed_config = None

    return blast_radius_service.build(cr, device, current_config, proposed_config)


@router.post("/{cr_id}/approve")
def approve(
    cr_id: str,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_permission(Permission.APPROVE_REMEDIATION)),
):
    cr = _get_owned(db, tenant_id, cr_id)
    prior_status = cr.status
    try:
        cr = change_request_service.approve(db, cr, approved_by=user.username)
    except ValueError as e:
        audit_service.record_from_user(
            db, user, action="change_request.approve", request=request, result="FAILURE",
            object_type="change_request", object_id=cr_id,
            old_value={"status": prior_status}, new_value={"error": str(e)},
        )
        raise HTTPException(409, str(e))
    audit_service.record_from_user(
        db, user, action="change_request.approve", request=request, result="SUCCESS",
        object_type="change_request", object_id=cr_id,
        old_value={"status": prior_status}, new_value={"status": cr.status},
    )
    return change_request_service.to_dict(cr)


@router.post("/{cr_id}/reject")
def reject(
    cr_id: str,
    request: Request,
    reason: str = Body(..., embed=True),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_permission(Permission.APPROVE_REMEDIATION)),
):
    cr = _get_owned(db, tenant_id, cr_id)
    prior_status = cr.status
    try:
        cr = change_request_service.reject(db, cr, rejected_by=user.username, reason=reason)
    except ValueError as e:
        audit_service.record_from_user(
            db, user, action="change_request.reject", request=request, result="FAILURE",
            object_type="change_request", object_id=cr_id,
            old_value={"status": prior_status}, new_value={"error": str(e)},
        )
        raise HTTPException(409, str(e))
    audit_service.record_from_user(
        db, user, action="change_request.reject", request=request, result="SUCCESS",
        object_type="change_request", object_id=cr_id,
        old_value={"status": prior_status}, new_value={"status": cr.status, "reason": reason},
    )
    return change_request_service.to_dict(cr)


@router.post("/{cr_id}/deploy")
async def deploy(
    cr_id: str,
    credential_ref_id: Optional[str] = Body(default=None),
    transport: Optional[str] = Body(default=None),
    framework: str = Body(default="ALL"),
    target_control_ids: Optional[list] = Body(
        default=None,
        description="Control IDs this deployment targets; post-deploy verification checks these specifically flipped to PASS.",
    ),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_role("admin", "operator")),
):
    """Deploy an APPROVED change request. Requires prior human approval
    (approve()) -- deployment is never triggered by AI or automatically on
    validation (RULE 4/5)."""
    cr = _get_owned(db, tenant_id, cr_id)
    try:
        dr = await deployment_service.deploy_change_request(
            db, cr, initiated_by=user.username,
            credential_ref_id=credential_ref_id, transport=transport, framework=framework,
            target_control_ids=target_control_ids,
        )
        return deployment_service.to_dict(dr)
    except ValueError as e:
        raise HTTPException(409, str(e))
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise e




@router.get("/{cr_id}/deployments")
def list_deployments(cr_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    _get_owned(db, tenant_id, cr_id)
    rows = (
        db.query(DeploymentRecord)
        .filter(DeploymentRecord.change_request_id == cr_id, DeploymentRecord.tenant_id == tenant_id)
        .order_by(DeploymentRecord.started_at.desc())
        .all()
    )
    return {"count": len(rows), "deployments": [deployment_service.to_dict(d) for d in rows]}


def _get_owned_deployment(db: Session, tenant_id: str, cr_id: str, deployment_id: str) -> DeploymentRecord:
    dr = db.query(DeploymentRecord).filter(
        DeploymentRecord.id == deployment_id,
        DeploymentRecord.change_request_id == cr_id,
        DeploymentRecord.tenant_id == tenant_id,
    ).first()
    if not dr:
        raise HTTPException(404, "Deployment not found")
    return dr


# ---------------------------------------------------------------------------
# Developer-mode drift simulation
# ---------------------------------------------------------------------------
#
# Exercising the drift -> alert -> rollback path normally requires breaking a
# real device's connectivity. This endpoint forces an already-completed
# deployment into DRIFTED and fires the REAL alert_rollback_required() path,
# so the loop can be demonstrated in a browser with no device involved.
#
# SCOPE -- read this before demoing it: this triggers the *operator-initiated*
# rollback path. After this call the deployment is DRIFTED and a
# "rollback required" alert exists; a human then clicks Roll Back, which runs
# rollback_service. Nothing reverts on its own. There is no unattended
# auto-revert in this codebase (RULE 4/5 -- see rollback_service.py and
# deployment_service.py:265), and this endpoint does not add one.
#
# INTEGRITY: this writes a verdict into deployment_records, which is an
# evidence table that feeds reports and audit exports. A simulated drift that
# reads as a real one would corrupt that evidence, so every row it touches is
# stamped "[SIMULATED DRIFT]" with the acting user, the route is disabled
# unless ENABLE_DEV_SIMULATION=true, and the action is audit-logged.

ENABLE_DEV_SIMULATION = os.getenv("ENABLE_DEV_SIMULATION", "false").strip().lower() in (
    "1", "true", "yes", "on",
)

# A deployment is only "active" (and therefore driftable) once the push has
# actually landed. PENDING/FAILED deployments never reached the device.
_DRIFTABLE_STATUSES = ("DEPLOYED", "VERIFIED")


@router.post("/{cr_id}/simulate-drift")
async def simulate_drift(
    cr_id: str,
    request: Request,
    # embed=True: with a single Body parameter FastAPI would otherwise expect
    # a bare JSON string as the whole body, not {"deployment_id": ...}.
    deployment_id: Optional[str] = Body(default=None, embed=True),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_role("admin", "operator")),
):
    """Force this change request's most recent active deployment into DRIFTED,
    firing the real rollback-required alert, without touching a device.

    Demonstrates drift detection and the operator-initiated rollback path.
    Does NOT demonstrate an automatic revert — the platform has none.

    Disabled unless ENABLE_DEV_SIMULATION=true.
    """
    if not ENABLE_DEV_SIMULATION:
        # 404 rather than 403: in a production deployment this route should be
        # indistinguishable from one that doesn't exist.
        raise HTTPException(404, "Not Found")

    cr = _get_owned(db, tenant_id, cr_id)

    if deployment_id:
        dr = _get_owned_deployment(db, tenant_id, cr_id, deployment_id)
    else:
        dr = (
            db.query(DeploymentRecord)
            .filter(
                DeploymentRecord.change_request_id == cr_id,
                DeploymentRecord.tenant_id == tenant_id,
                DeploymentRecord.status.in_(_DRIFTABLE_STATUSES),
            )
            .order_by(DeploymentRecord.started_at.desc())
            .first()
        )
        if not dr:
            raise HTTPException(
                409,
                "No active deployment to drift. Deploy this change request first — "
                f"only deployments in {'/'.join(_DRIFTABLE_STATUSES)} can be simulated as drifted.",
            )

    if dr.status not in _DRIFTABLE_STATUSES:
        raise HTTPException(
            409,
            f"Deployment {dr.id} is {dr.status}; only {'/'.join(_DRIFTABLE_STATUSES)} "
            "deployments can be simulated as drifted.",
        )
    if dr.rolled_back:
        raise HTTPException(409, f"Deployment {dr.id} has already been rolled back.")

    device = db.query(Device).filter(Device.id == dr.device_id).first()
    prior_status = dr.status

    detail = (
        f"[SIMULATED DRIFT] Post-deployment configuration hash does not match the approved "
        f"proposed configuration (change_request={cr.id}, deployment={dr.id}). "
        f"Injected by {user.username} via the developer drift simulator — no device was contacted "
        f"and no real drift occurred."
    )

    dr.status = "DRIFTED"
    dr.post_verification_passed = False
    # Deliberately overwrite rather than append: a simulated row must not carry
    # a real post-deploy hash that would make the fake drift look corroborated.
    dr.post_config_hash = None
    dr.error = detail
    dr.completed_at = datetime.utcnow()
    db.commit()
    db.refresh(dr)

    # The real alert path -- same call deployment_service makes on genuine drift.
    alert_dispatched = False
    if device is not None:
        try:
            await alert_service.alert_rollback_required(db, cr.tenant_id, device.id, dr.id, detail)
            alert_dispatched = True
        except Exception:  # noqa: BLE001 - a dispatch failure must not undo the state change
            logger.warning("Simulated-drift rollback alert dispatch failed", exc_info=True)

    audit_service.record_from_user(
        db, user, action="deployment.simulate_drift", request=request, result="SUCCESS",
        object_type="deployment_record", object_id=dr.id,
        old_value={"status": prior_status},
        new_value={"status": "DRIFTED", "simulated": True},
    )

    return {
        "deployment": deployment_service.to_dict(dr),
        "simulated": True,
        "alert_dispatched": alert_dispatched,
        # The next step is a human action, not an automatic one.
        "next_step": {
            "description": (
                "Deployment is now DRIFTED and a rollback-required alert has been raised. "
                "Rollback is operator-initiated — the platform will not revert on its own."
            ),
            "rollback_url": f"/api/change-requests/{cr_id}/deployments/{dr.id}/rollback",
        },
    }


@router.post("/{cr_id}/deployments/{deployment_id}/rollback")
async def rollback(
    cr_id: str,
    deployment_id: str,
    reason: Optional[str] = Body(default=None),
    credential_ref_id: Optional[str] = Body(default=None),
    framework: str = Body(default="ALL"),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_role("admin", "operator")),
):
    """Revert a deployment (typically one that DRIFTED -- push succeeded but
    post-deploy verification didn't match the approved config) back to the
    change request's archived pre-change configuration. Same human-approval
    gate as /deploy: never triggered automatically (RULE 4/5)."""
    _get_owned(db, tenant_id, cr_id)
    dr = _get_owned_deployment(db, tenant_id, cr_id, deployment_id)
    try:
        rb = await rollback_service.rollback_deployment(
            db, dr, initiated_by=user.username, reason=reason,
            credential_ref_id=credential_ref_id, framework=framework,
        )
    except ValueError as e:
        raise HTTPException(409, str(e))
    await audit_service.log_action(
        db, tenant_id, user.username, "ROLLBACK_DEPLOYMENT", "deployment_record", deployment_id,
        old_value={"deployment_status": dr.status}, new_value={"rollback_status": rb.status},
    )
    return rollback_service.to_dict(rb)


@router.get("/{cr_id}/deployments/{deployment_id}/rollbacks")
def list_rollbacks(
    cr_id: str, deployment_id: str,
    db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant),
):
    _get_owned(db, tenant_id, cr_id)
    _get_owned_deployment(db, tenant_id, cr_id, deployment_id)
    rows = (
        db.query(RollbackRecord)
        .filter(RollbackRecord.deployment_record_id == deployment_id, RollbackRecord.tenant_id == tenant_id)
        .order_by(RollbackRecord.started_at.desc())
        .all()
    )
    return {"count": len(rows), "rollbacks": [rollback_service.to_dict(r) for r in rows]}
