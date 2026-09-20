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
from app.services import alert_service, config_merge, evidence_service, minio_service, openbao_service
from app.services.collectors.registry import get_collector
from app.services.deployment.registry import get_deployer
from app.services.deployment_service import _resolve_credentials
from app.services.pipeline import run_pipeline
from app.services.stage_tracker import (KIND_LABELS, ROLLBACK_STAGES, StageTracker,
                                        classify_push_error)

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
        "stages": _stages_for(rb),
        "stages_derived": not bool(rb.stages),
        "failed_stage": _failed(rb).get("key") if _failed(rb) else None,
        "failure_label": KIND_LABELS.get((_failed(rb) or {}).get("kind") or "", None),
    }


def _stages_for(rb: RollbackRecord) -> list:
    if rb.stages:
        return rb.stages
    # Legacy rows: reconstruct coarsely from status/error.
    from app.services.stage_tracker import blank_stages, PASSED, FAILED, SKIPPED
    stages = blank_stages(ROLLBACK_STAGES)
    by = {s["key"]: s for s in stages}
    order = [k for k, _ in ROLLBACK_STAGES]
    if rb.status == "PENDING":
        return stages
    err = (rb.error or "").lower()
    if rb.status == "VERIFIED":
        for k in order:
            by[k]["status"] = PASSED
        return stages
    fail_key = "verify"
    if "no archived" in err or "object storage" in err:
        fail_key = "archive"
    elif "credentials" in err and "verification" not in err:
        fail_key = "credentials"
    elif "safe minimal revert" in err:
        fail_key = "plan"
    elif "rollback push failed" in err:
        fail_key = "push"
    i = order.index(fail_key)
    for k in order[:i]:
        by[k]["status"] = PASSED
    by[fail_key].update(status=FAILED, error=rb.error)
    for k in order[i + 1:]:
        by[k]["status"] = SKIPPED
    return stages


def _failed(rb: RollbackRecord) -> Optional[Dict[str, Any]]:
    return next((s for s in _stages_for(rb) if s.get("status") == "failed"), None)


def to_dict_full(db: Session, rb: RollbackRecord) -> Dict[str, Any]:
    out = to_dict(rb)
    scan = db.query(Scan).get(rb.post_rollback_scan_id) if rb.post_rollback_scan_id else None
    out["post_validation"] = None if scan is None else {
        "scan_id": scan.id,
        "opa_decision": scan.opa_decision,
        "batfish_status": scan.batfish_status,
        "risk_level": scan.risk_level,
        "risk_score": scan.risk_score,
        "final_decision": scan.final_decision,
        "final_reason": scan.final_reason,
    }
    return out


async def rollback_deployment(
    db: Session,
    dr: DeploymentRecord,
    initiated_by: str,
    reason: Optional[str] = None,
    credential_ref_id: Optional[str] = None,
    framework: str = "ALL",
) -> RollbackRecord:
    """Pre-flight problems raise ValueError (-> 409, nothing recorded). Once a
    RollbackRecord exists an unexpected crash is recorded against the stage in
    flight and the record is flagged CRITICAL_MANUAL_INTERVENTION_REQUIRED --
    a half-finished revert must never be left looking PENDING."""
    holder: Dict[str, Any] = {}
    try:
        return await _rollback_deployment(db, dr, initiated_by, reason, credential_ref_id, framework, holder)
    except Exception as e:  # noqa: BLE001
        rb = holder.get("rb")
        if rb is None:
            raise
        logger.exception("Rollback %s crashed", rb.id)
        try:
            db.rollback()
            rb = db.query(RollbackRecord).get(rb.id)
            StageTracker(db, rb, ROLLBACK_STAGES).fail_running(f"{type(e).__name__}: {e}", kind="internal")
            rb.status = "CRITICAL_MANUAL_INTERVENTION_REQUIRED"
            rb.error = rb.error or f"Rollback crashed unexpectedly ({type(e).__name__}: {e}); the device's state is UNVERIFIED."
            rb.completed_at = datetime.utcnow()
            db.commit()
        except Exception:  # noqa: BLE001
            logger.exception("Could not record crash of rollback %s", rb.id)
        return rb


async def _rollback_deployment(
    db: Session,
    dr: DeploymentRecord,
    initiated_by: str,
    reason: Optional[str],
    credential_ref_id: Optional[str],
    framework: str,
    holder: Dict[str, Any],
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
    rb.started_at = datetime.utcnow()
    db.add(rb)
    db.commit()
    db.refresh(rb)
    holder["rb"] = rb
    tracker = StageTracker(db, rb, ROLLBACK_STAGES)

    # 0. Without an archived pre-change config there is nothing safe to
    #    roll back TO -- guessing is exactly what section 12 forbids.
    tracker.start("archive", "Loading the archived pre-change configuration.")
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
        tracker.fail("archive", rb.error, kind="no_archive")
        await _alert_failure(db, rb, device)
        await _anchor_rollback_event(db, rb, device, "rollback.no_archived_config")
        return rb

    try:
        rollback_text = minio_service.get_object(cr.current_config_object_key).decode("utf-8", errors="replace")
    except Exception as e:  # noqa: BLE001
        rb.status = "CRITICAL_MANUAL_INTERVENTION_REQUIRED"
        rb.error = f"Could not read archived pre-change configuration from object storage: {e}"
        rb.completed_at = datetime.utcnow()
        db.commit()
        tracker.fail("archive", rb.error, kind="archive_read")
        await _alert_failure(db, rb, device)
        await _anchor_rollback_event(db, rb, device, "rollback.archive_read_failed")
        return rb
    tracker.ok("archive", f"Pre-change config loaded ({str(rb.target_config_hash)[:12]}).")

    tracker.start("credentials")

    try:
        credentials = _resolve_credentials(db, device, dr.tenant_id, credential_ref_id)
    except (ValueError, openbao_service.OpenBaoError) as e:
        rb.status = "CRITICAL_MANUAL_INTERVENTION_REQUIRED"
        rb.error = f"Could not resolve device credentials for rollback: {e}"
        rb.completed_at = datetime.utcnow()
        db.commit()
        tracker.fail("credentials", rb.error, kind="credentials")
        await _alert_failure(db, rb, device)
        await _anchor_rollback_event(db, rb, device, "rollback.credentials_unavailable")
        return rb
    tracker.ok("credentials", "Credentials resolved.")

    # 1. Revert ONLY what changed. Pushing the entire archived config back
    #    re-applies the whole device configuration; instead diff the device's
    #    current running config against the pre-change config and send that.
    tracker.start("plan", "Reading the running config and diffing it against the pre-change config.")
    collector = get_collector(device.vendor, transport=rb.transport)
    running_text = None
    try:
        pre = await anyio.to_thread.run_sync(collector.collect_config, device, credentials)
        if pre.success and pre.raw_config:
            running_text = pre.raw_config
    except Exception:  # noqa: BLE001
        logger.warning("Could not collect running config before rollback", exc_info=True)
    proposed_text = None
    if cr.proposed_config_object_key:
        try:
            proposed_text = minio_service.get_object(cr.proposed_config_object_key).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            proposed_text = None

    plan = config_merge.delta_between(running_text or proposed_text, rollback_text, device.vendor)
    if not plan.safe and cr.merge_commands and all(str(c).lower().startswith("set ") for c in cr.merge_commands):
        plan = config_merge.DeltaPlan(["delete " + str(c)[4:] for c in cr.merge_commands], [], True, "inverse-set")
    if not plan.safe:
        rb.status = "CRITICAL_MANUAL_INTERVENTION_REQUIRED"
        rb.error = ("Could not derive a safe minimal revert for this device/config format "
                    f"({'; '.join(plan.warnings)}); refusing to push a full configuration. Manual recovery required.")
        rb.completed_at = datetime.utcnow()
        db.commit()
        del credentials
        tracker.fail("plan", rb.error, kind="no_safe_delta")
        await _alert_failure(db, rb, device)
        await _anchor_rollback_event(db, rb, device, "rollback.no_safe_delta")
        return rb
    tracker.ok("plan", f"{len(plan.commands)} revert command(s) derived ({plan.style if hasattr(plan, 'style') else 'delta'}).")

    deployer = get_deployer(rb.transport)
    tracker.start("push", f"Pushing the revert over {rb.transport or 'ssh'}.")
    if plan.commands:
        push_result = await anyio.to_thread.run_sync(deployer.push_config, device, credentials, plan.commands)
    else:  # device already matches the pre-change config
        from app.services.deployment.base import DeploymentResult
        push_result = DeploymentResult(success=True, transport=rb.transport or "ssh", output="already at target")
    del credentials

    if not push_result.success:
        rb.status = "CRITICAL_MANUAL_INTERVENTION_REQUIRED"
        rb.error = f"Rollback push failed: {push_result.error}"
        rb.completed_at = datetime.utcnow()
        db.commit()
        tracker.fail("push", rb.error, kind=classify_push_error(push_result.error))
        await _alert_failure(db, rb, device)
        await _anchor_rollback_event(db, rb, device, "rollback.push_failed")
        return rb

    rb.status = "ROLLED_BACK"
    db.commit()
    tracker.ok("push", "Revert accepted by the device.")
    tracker.start("verify", "Re-collecting the running config and comparing it with the pre-change hash.")

    # 2. Never report rollback success without re-collecting and
    #    re-hashing the device's actual configuration (section 12).
    try:
        verify_credentials = _resolve_credentials(db, device, dr.tenant_id, credential_ref_id)
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
        tracker.fail("verify", rb.error, kind="unverified")
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
        tracker.fail("verify", rb.error, kind="unverified")
        await _alert_failure(db, rb, device)
        return rb

    rb.post_rollback_hash = post_result.config_hash
    rb.post_rollback_verified = (post_result.config_hash == rb.target_config_hash)
    if not rb.post_rollback_verified:
        from app.services.deployment_service import same_content
        rb.post_rollback_verified = same_content(post_result.raw_config, rollback_text)
    if rb.post_rollback_verified and getattr(push_result, "pending_confirm", False):
        try:
            cc = _resolve_credentials(db, device, dr.tenant_id, credential_ref_id)
            await anyio.to_thread.run_sync(deployer.confirm_commit, device, cc)
            del cc
        except Exception:  # noqa: BLE001
            logger.warning("Rollback commit confirm failed", exc_info=True)

    if rb.post_rollback_verified:
        tracker.ok("verify", f"Device is back on the pre-change config ({str(rb.post_rollback_hash)[:12]}).")
    else:
        tracker.fail("verify", f"Post-rollback hash {str(rb.post_rollback_hash)[:12]} does not match the target "
                     f"{str(rb.target_config_hash)[:12]}.", kind="hash_mismatch", skip_rest=False)

    # 3. Evidence trail: rerun the SAME compliance pipeline on the
    #    post-rollback config (identical pattern to deployment_service.py's
    #    post-deploy step) so the rollback produces a real Scan/Finding/
    #    Evidence chain, not just a status string.
    tracker.start("postval", "Re-running OPA, Batfish and risk scoring on the reverted config.")
    scan = Scan(tenant_id=dr.tenant_id, device_id=device.id, framework=framework, status="uploaded")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    await run_pipeline(db, scan, post_result.raw_config, framework=framework)
    db.refresh(scan)
    rb.post_rollback_scan_id = scan.id
    _bits = " · ".join([
        f"OPA {scan.opa_decision or '—'}", f"Batfish {scan.batfish_status or '—'}",
        f"Risk {scan.risk_level or '—'}", f"Decision {scan.final_decision or '—'}",
    ])
    if (scan.final_decision or "PASS") == "PASS":
        tracker.ok("postval", _bits)
    else:
        tracker.warn("postval", _bits)

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

    await _anchor_rollback_event(
        db, rb, device,
        "rollback.verified" if rb.status == "VERIFIED" else "rollback.unverified",
        scan_id=rb.post_rollback_scan_id,
    )

    return rb


async def _alert_failure(db: Session, rb: RollbackRecord, device: Device) -> None:
    try:
        await alert_service.alert_rollback_failed(db, rb.tenant_id, device.id, rb.id, rb.error or "Rollback failed")
    except Exception:  # noqa: BLE001 -- alerting must never mask the underlying failure
        logger.warning("Failed to dispatch rollback-failure alert", exc_info=True)


async def _anchor_rollback_event(
    db: Session, rb: RollbackRecord, device: Device, event_type: str, scan_id: Optional[str] = None,
) -> None:
    """Same Fabric-anchoring pattern as deployment_service.py's
    `_anchor_deployment_event` -- the chaincode's `eventType` is free-form,
    so `rollback.*` event kinds need no chaincode change. Best-effort,
    never blocks the rollback result."""
    try:
        await evidence_service.anchor_event(
            db, event_type=event_type, actor=rb.initiated_by or "system:rollback",
            device_id=device.id, tenant_id=rb.tenant_id, final_decision=rb.status,
            scan_id=scan_id, vendor=device.vendor or "Unknown",
            config_hash=rb.post_rollback_hash or rb.target_config_hash,
        )
    except Exception:  # noqa: BLE001
        logger.warning("Failed to anchor %s event for rollback %s", event_type, rb.id, exc_info=True)
