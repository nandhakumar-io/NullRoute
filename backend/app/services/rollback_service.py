"""
Phase 15b -- Rollback.

    DRIFTED (or VERIFIED, for a manually-initiated revert) DeploymentRecord
            |
    fetch the ChangeRequest's ARCHIVED pre-change config (MinIO
    current.cfg, same object change_request_service.py wrote at CR
    creation) -- if it isn't there, we cannot safely guess our way back to
    a known-good config, so this is an immediate CRITICAL/manual case
            |
    push it back via the SAME deployer the original deployment used
    (services/deployment/{ssh,netconf,gnmi}.py -- RULE 11, no second
    transport implementation)
            |
    re-collect the running configuration (SAME collector everywhere else
    uses) and hash it
            |
    compare to change_request.current_config_hash (the target we rolled
    back TO, never the proposed hash)
            |
    rerun the SAME compliance pipeline (services/pipeline.run_pipeline) on
    the post-rollback config, for an evidence trail identical in shape to
    a normal deployment's
            |
    VERIFIED | CRITICAL_MANUAL_INTERVENTION_REQUIRED

Never automatic (RULE 4/5, same as deployment_service.py): this module is
only ever invoked by an authenticated human actor via the router. A
DeploymentRecord landing in DRIFTED raises an alert recommending rollback,
but nothing in this codebase pushes a rollback config on its own.

Per section 12 of the Part 3 integration brief: a rollback is never
reported as successful without re-collecting and re-hashing the device's
actual configuration. "The push command didn't error" is not verification.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, Optional

import anyio
from sqlalchemy.orm import Session

from app.models.db import ChangeRequest, Device, DeploymentRecord, RollbackRecord, Scan
from app.services import alert_service, minio_service, openbao_service
from app.services.collectors.registry import get_collector
from app.services.deployment.registry import get_deployer
from app.services.deployment_service import _resolve_credentials
from app.services.pipeline import run_pipeline

logger = logging.getLogger("rollback_service")

# DeploymentRecord states a rollback may legitimately be initiated from.
# DRIFTED is the section-12 failure path (push succeeded, post-deploy hash
# didn't match what was approved). VERIFIED is included for the case where
# a human decides -- after the fact, for reasons the automated pipeline
# can't see (an unexpected outage, a business decision) -- to revert an
# otherwise-successful deployment; it is still gated by require_role at
# the router, same as every other device-mutating action.
ROLLBACK_ELIGIBLE_STATUSES = {"DRIFTED", "VERIFIED"}


def to_dict(rb: RollbackRecord) -> Dict[str, Any]:
    return {
        "id": rb.id,
        "tenant_id": rb.tenant_id,
        "deployment_record_id": rb.deployment_record_id,
        "change_request_id": rb.change_request_id,
        "device_id": rb.device_id,
        "initiated_by": rb.initiated_by,
        "reason": rb.reason,
        "transport": rb.transport,
        "target_config_hash": rb.target_config_hash,
        "status": rb.status,
        "post_rollback_hash": rb.post_rollback_hash,
        "post_rollback_verified": rb.post_rollback_verified,
        "post_rollback_scan_id": rb.post_rollback_scan_id,
        "error": rb.error,
        "started_at": rb.started_at.isoformat() if rb.started_at else None,
        "completed_at": rb.completed_at.isoformat() if rb.completed_at else None,
    }


async def rollback_deployment(
    db: Session,
    dr: DeploymentRecord,
    initiated_by: str,
    reason: Optional[str] = None,
    credential_ref_id: Optional[str] = None,
    framework: str = "ALL",
) -> RollbackRecord:
    if dr.status not in ROLLBACK_ELIGIBLE_STATUSES:
        raise ValueError(
            f"Deployment {dr.id} is not eligible for rollback (status={dr.status}); "
            f"must be one of {sorted(ROLLBACK_ELIGIBLE_STATUSES)}"
        )
    if dr.rolled_back:
        raise ValueError(f"Deployment {dr.id} has already been rolled back")

    cr: Optional[ChangeRequest] = db.query(ChangeRequest).get(dr.change_request_id)
    if cr is None:
        raise ValueError(f"Change request {dr.change_request_id} not found")
    device: Optional[Device] = db.query(Device).get(dr.device_id)
    if device is None:
        raise ValueError(f"Device {dr.device_id} not found")

    rb = RollbackRecord(
        tenant_id=dr.tenant_id, deployment_record_id=dr.id, change_request_id=cr.id,
        device_id=device.id, initiated_by=initiated_by, reason=reason,
        transport=dr.transport, target_config_hash=cr.current_config_hash, status="PENDING",
    )
    db.add(rb)
    db.commit()
    db.refresh(rb)

    # 0. Without an archived pre-change config there is nothing safe to
    #    roll back TO -- guessing is exactly what section 12 forbids.
    if not cr.current_config_object_key or not cr.current_config_hash:
        rb.status = "CRITICAL_MANUAL_INTERVENTION_REQUIRED"
        rb.error = (
            "No archived pre-change configuration on this change request "
            "(current_config_object_key/current_config_hash missing); cannot "
            "automatically roll back. Manual recovery from a known-good backup "
            "or console access is required."
        )
        rb.completed_at = datetime.utcnow()
        db.commit()
        await _alert_failure(db, rb, device)
        return rb

    try:
        rollback_text = minio_service.get_object(cr.current_config_object_key).decode("utf-8", errors="replace")
    except Exception as e:  # noqa: BLE001
        rb.status = "CRITICAL_MANUAL_INTERVENTION_REQUIRED"
        rb.error = f"Could not read archived pre-change configuration from object storage: {e}"
        rb.completed_at = datetime.utcnow()
        db.commit()
        await _alert_failure(db, rb, device)
        return rb

    try:
        credentials = _resolve_credentials(db, device, dr.tenant_id, credential_ref_id)
    except (ValueError, openbao_service.OpenBaoError) as e:
        rb.status = "CRITICAL_MANUAL_INTERVENTION_REQUIRED"
        rb.error = f"Could not resolve device credentials for rollback: {e}"
        rb.completed_at = datetime.utcnow()
        db.commit()
        await _alert_failure(db, rb, device)
        return rb

    # 1. Push the archived pre-change config back, via the SAME transport
    #    the original deployment used (RULE 11 -- no second implementation).
    config_lines = [line for line in rollback_text.splitlines() if line.strip()]
    deployer = get_deployer(rb.transport)
    push_result = await anyio.to_thread.run_sync(deployer.push_config, device, credentials, config_lines)
    del credentials

    if not push_result.success:
        rb.status = "CRITICAL_MANUAL_INTERVENTION_REQUIRED"
        rb.error = f"Rollback push failed: {push_result.error}"
        rb.completed_at = datetime.utcnow()
        db.commit()
        await _alert_failure(db, rb, device)
        return rb

    rb.status = "ROLLED_BACK"
    db.commit()

    # 2. Never report rollback success without re-collecting and
    #    re-hashing the device's actual configuration (section 12).
    try:
        verify_credentials = _resolve_credentials(db, device, dr.tenant_id, credential_ref_id)
        collector = get_collector(device.vendor)
        post_result = await anyio.to_thread.run_sync(collector.collect_config, device, verify_credentials)
        del verify_credentials
    except (ValueError, openbao_service.OpenBaoError) as e:
        rb.status = "CRITICAL_MANUAL_INTERVENTION_REQUIRED"
        rb.error = (
            f"Rollback was pushed but post-rollback verification credentials/collection "
            f"failed ({e}); the device's actual state is UNVERIFIED."
        )
        rb.completed_at = datetime.utcnow()
        db.commit()
        await _alert_failure(db, rb, device)
        return rb

    if not post_result.success or not post_result.raw_config:
        rb.status = "CRITICAL_MANUAL_INTERVENTION_REQUIRED"
        rb.error = (
            f"Rollback was pushed but post-rollback verification collection failed "
            f"({post_result.error or 'no config returned'}); the device's actual state is UNVERIFIED."
        )
        rb.completed_at = datetime.utcnow()
        db.commit()
        await _alert_failure(db, rb, device)
        return rb

    rb.post_rollback_hash = post_result.config_hash
    rb.post_rollback_verified = (post_result.config_hash == rb.target_config_hash)

    # 3. Evidence trail: rerun the SAME compliance pipeline on the
    #    post-rollback config (identical pattern to deployment_service.py's
    #    post-deploy step) so the rollback produces a real Scan/Finding/
    #    Evidence chain, not just a status string.
    scan = Scan(tenant_id=dr.tenant_id, device_id=device.id, framework=framework, status="uploaded")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    await run_pipeline(db, scan, post_result.raw_config, framework=framework)
    db.refresh(scan)
    rb.post_rollback_scan_id = scan.id

    if rb.post_rollback_verified:
        rb.status = "VERIFIED"
        dr.rolled_back = True
        db.add(dr)
    else:
        # Push reported success, but the device isn't actually back on the
        # approved pre-change config. This is exactly the case section 12
        # calls out: do not silently convert this into a success.
        rb.status = "CRITICAL_MANUAL_INTERVENTION_REQUIRED"
        rb.error = (
            f"Rollback push succeeded but post-rollback hash ({rb.post_rollback_hash}) "
            f"does not match the target pre-change hash ({rb.target_config_hash}). "
            "Device state is UNVERIFIED against both the proposed and original configuration."
        )

    rb.completed_at = datetime.utcnow()
    db.commit()
    db.refresh(rb)

    if rb.status == "CRITICAL_MANUAL_INTERVENTION_REQUIRED":
        await _alert_failure(db, rb, device)

    return rb


async def _alert_failure(db: Session, rb: RollbackRecord, device: Device) -> None:
    try:
        await alert_service.alert_rollback_failed(db, rb.tenant_id, device.id, rb.id, rb.error or "Rollback failed")
    except Exception:  # noqa: BLE001 -- alerting must never mask the underlying failure
        logger.warning("Failed to dispatch rollback-failure alert", exc_info=True)
