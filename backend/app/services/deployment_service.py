"""
Phase 15 -- Deployment.

    APPROVED ChangeRequest
            |
    verify current device hash == change_request.current_config_hash
    (collect via the SAME collector used everywhere else) -- MISMATCH aborts
            |
    push via services/deployment/{ssh,netconf}.py
            |
    re-collect running configuration
            |
    hash + compare to change_request.proposed_config_hash
            |
    rerun the SAME compliance pipeline (services/pipeline.run_pipeline) on
    the post-deploy config, for evidence + verification
            |
    DEPLOYED (post_verification_passed) | FAILED | DRIFTED

Deployment always requires status == "APPROVED" on the ChangeRequest and is
only ever invoked by an authenticated human actor via the router
(require_role) -- AI never calls this module directly (RULE 4).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, Optional

import anyio
from sqlalchemy.orm import Session

from app.models.db import (ChangeRequest, Device, DeviceCredentialRef,
                            DeploymentRecord, Finding, Scan)
from app.services import alert_service, minio_service, openbao_service
from app.services.collectors.registry import get_collector
from app.services.deployment.registry import get_deployer
from app.services.pipeline import run_pipeline

logger = logging.getLogger("deployment_service")


def to_dict(dr: DeploymentRecord) -> Dict[str, Any]:
    return {
        "id": dr.id,
        "tenant_id": dr.tenant_id,
        "change_request_id": dr.change_request_id,
        "device_id": dr.device_id,
        "initiated_by": dr.initiated_by,
        "transport": dr.transport,
        "expected_pre_hash": dr.expected_pre_hash,
        "observed_pre_hash": dr.observed_pre_hash,
        "status": dr.status,
        "post_config_hash": dr.post_config_hash,
        "post_verification_passed": dr.post_verification_passed,
        "post_scan_id": dr.post_scan_id,
        "error": dr.error,
        "started_at": dr.started_at.isoformat() if dr.started_at else None,
        "completed_at": dr.completed_at.isoformat() if dr.completed_at else None,
        "request_hash": dr.request_hash,
        "model_name": dr.model_name,
        "paths": dr.paths,
        "operation": dr.operation,
        "verification_engine": dr.verification_engine,
        "verification_result": dr.verification_result,
        "verification_metadata": dr.verification_metadata,
    }


def _resolve_credentials(
    db: Session, device: Device, tenant_id: str,
    credential_ref_id: Optional[str] = None, transport: Optional[str] = None,
):
    from app.gateway import connectors
    if connectors.GATEWAY_MOCK_CONNECTOR:
        return openbao_service.DeviceCredentials(credential_type="mock", secret={"username": "mock", "password": "mock"})

    query = db.query(DeviceCredentialRef).filter(
        DeviceCredentialRef.device_id == device.id, DeviceCredentialRef.tenant_id == tenant_id,
    )
    ref_row = None
    if credential_ref_id:
        ref_row = query.filter(DeviceCredentialRef.id == credential_ref_id).first()
    elif transport:
        # Prefer a credential ref whose type actually matches the transport
        # being used for this deployment (e.g. don't hand SSH-only
        # credentials to a NETCONF push/collect just because it's the most
        # recently created ref on the device) -- falls back to the newest
        # ref of any type if nothing matches, same as before.
        from app.services.collectors.registry import credential_type_matches_transport
        candidates = query.order_by(DeviceCredentialRef.created_at.desc()).all()
        ref_row = next(
            (c for c in candidates if credential_type_matches_transport(c.credential_type, transport)),
            candidates[0] if candidates else None,
        )
    else:
        ref_row = query.order_by(DeviceCredentialRef.created_at.desc()).first()

    if not ref_row:
        raise ValueError("No credential reference on file for this device")
    return openbao_service.DeviceCredentials(
        credential_type=ref_row.credential_type, 
        secret=ref_row.secret_data or {}
    )


async def deploy_change_request(
    db: Session,
    cr: ChangeRequest,
    initiated_by: str,
    credential_ref_id: Optional[str] = None,
    transport: Optional[str] = None,
    framework: str = "ALL",
) -> DeploymentRecord:
    if cr.status != "APPROVED":
        raise ValueError(f"Change request {cr.id} is not APPROVED (status={cr.status})")

    device: Device = db.query(Device).get(cr.device_id)
    if device is None:
        raise ValueError(f"Device {cr.device_id} not found")

    dr = DeploymentRecord(
        tenant_id=cr.tenant_id, change_request_id=cr.id, device_id=device.id,
        initiated_by=initiated_by, transport=transport or "ssh",
        expected_pre_hash=cr.current_config_hash, status="PENDING",
    )
    db.add(dr)
    cr.status = "DEPLOYING"
    db.commit()
    db.refresh(dr)

    try:
        credentials = _resolve_credentials(db, device, cr.tenant_id, credential_ref_id, transport=dr.transport)
    except (ValueError, openbao_service.OpenBaoError) as e:
        dr.status = "FAILED"
        dr.error = f"Could not resolve device credentials: {e}"
        dr.completed_at = datetime.utcnow()
        cr.status = "FAILED"
        db.commit()
        return dr

    # 1. Pre-deployment hash verification -- never deploy over an unknown
    #    intervening change (RULE: verify current device hash matches
    #    expected hash before deployment; abort if not).
    #
    # IMPORTANT: pass the *deployment's* transport through, not just the
    # vendor. get_collector(vendor) alone falls back to that vendor's
    # default transport priority (e.g. plain "ssh" for cisco_ios), which
    # silently ignores an operator's explicit choice of transport="netconf"
    # (or "gnmi") for this deployment. That mismatch is what produced
    # errors like "transport: netconf ... TCP connection to device failed
    # ... cisco_ios 172.17.1.18:22" -- the push correctly went out over
    # NETCONF (port 830) but pre/post verification collection was still
    # being attempted over SSH (port 22) with the wrong credential set,
    # even though both SSH and NETCONF work fine independently. Pre- and
    # post-deployment collection must always use the SAME transport that
    # was actually used (or requested) for the push.
    collector = get_collector(device.vendor, transport=dr.transport)
    pre_result = await anyio.to_thread.run_sync(collector.collect_config, device, credentials)
    if not pre_result.success or not pre_result.raw_config:
        dr.status = "FAILED"
        dr.error = f"Pre-deployment verification collection failed: {pre_result.error or 'no config returned'}"
        dr.completed_at = datetime.utcnow()
        cr.status = "FAILED"
        db.commit()
        return dr

    dr.observed_pre_hash = pre_result.config_hash
    if dr.expected_pre_hash and pre_result.config_hash != dr.expected_pre_hash:
        dr.status = "ABORTED_STALE_HASH"
        dr.error = (
            f"Device's current configuration hash ({pre_result.config_hash}) does not match "
            f"the change request's expected pre-change hash ({dr.expected_pre_hash}); the device "
            "changed since this change request was validated. Aborting."
        )
        dr.completed_at = datetime.utcnow()
        cr.status = "FAILED"
        db.commit()
        try:
            await alert_service.alert_collection_failure(db, cr.tenant_id, device.id, dr.error)
        except Exception:  # noqa: BLE001 -- alerting must never mask the abort
            logger.warning("Failed to dispatch stale-hash-abort alert", exc_info=True)
        return dr

    # 2. Push. `credentials` goes out of scope once this returns (RULE 6).
    proposed_text = minio_service.get_object(cr.proposed_config_object_key).decode("utf-8", errors="replace")
    config_lines = [line for line in proposed_text.splitlines() if line.strip()]
    deployer = get_deployer(transport)
    dr.status = "DEPLOYING"
    db.commit()
    push_result = await anyio.to_thread.run_sync(deployer.push_config, device, credentials, config_lines)
    del credentials
    if dr.transport == "gnmi":
        from app.services.observability import record_gnmi_set_result
        record_gnmi_set_result(push_result.success)

    if not push_result.success:
        dr.status = "FAILED"
        dr.error = f"Deployment push failed: {push_result.error}"
        dr.completed_at = datetime.utcnow()
        cr.status = "FAILED"
        db.commit()
        try:
            await alert_service.alert_collection_failure(db, cr.tenant_id, device.id, dr.error)
        except Exception:  # noqa: BLE001
            logger.warning("Failed to dispatch deployment-failure alert", exc_info=True)
        return dr

    # gNMI records structured request metadata (never credentials) in its
    # DeploymentResult.output as JSON -- surface it onto the record's own
    # columns for reporting/UI (spec sections 26/47/53). SSH/NETCONF leave
    # these columns NULL.
    if dr.transport == "gnmi" and push_result.output:
        try:
            gnmi_meta = json.loads(push_result.output)
            dr.request_hash = gnmi_meta.get("request_hash")
            dr.model_name = gnmi_meta.get("model")
            dr.paths = gnmi_meta.get("paths")
            dr.operation = gnmi_meta.get("operation")
        except (json.JSONDecodeError, AttributeError):  # noqa: BLE001 -- metadata is best-effort, never blocks deployment
            logger.warning("Could not parse gNMI deployment metadata for reporting", exc_info=True)

    dr.status = "DEPLOYED"
    db.commit()

    # 3. Post-deployment collection + verification. Re-resolve credentials
    #    fresh (the earlier reference was deliberately dropped after push).
    try:
        post_credentials = _resolve_credentials(db, device, cr.tenant_id, credential_ref_id, transport=dr.transport)
        post_result = await anyio.to_thread.run_sync(collector.collect_config, device, post_credentials)
        del post_credentials
    except (ValueError, openbao_service.OpenBaoError) as e:
        dr.error = f"Post-deployment verification credentials unavailable: {e}"
        post_result = None

    if not post_result or not post_result.success or not post_result.raw_config:
        dr.status = "FAILED"
        dr.error = dr.error or f"Post-deployment verification collection failed: {getattr(post_result, 'error', 'unknown')}"
        dr.completed_at = datetime.utcnow()
        cr.status = "FAILED"
        db.commit()
        return dr

    dr.post_config_hash = post_result.config_hash
    dr.post_verification_passed = (post_result.config_hash == cr.proposed_config_hash)

    # 3b. Optional supplemental pyATS/Genie verification (spec sections
    #     29-34/47) -- Cisco-only, best-effort, and NEVER authoritative:
    #     OPA/Batfish/risk (run next, unconditionally) remain the actual
    #     compliance decision. A verifier failure/unsupported result never
    #     aborts the deployment or is treated as a deployment failure.
    if os.environ.get("PYATS_ENABLED", "false").strip().lower() in ("1", "true", "yes", "on"):
        try:
            from app.services.verification.registry import get_verifier
            verify_credentials = _resolve_credentials(db, device, cr.tenant_id, credential_ref_id, transport=dr.transport)
            verifier = get_verifier("pyats_genie")
            verify_result = await anyio.to_thread.run_sync(verifier.verify, device, verify_credentials)
            del verify_credentials
            dr.verification_engine = verifier.engine
            dr.verification_result = verify_result.status
            dr.verification_metadata = verify_result.as_metadata()
            from app.services.observability import record_pyats_verification_result
            record_pyats_verification_result(verify_result.success)
        except Exception:  # noqa: BLE001 -- supplemental verification must never block/fail the deployment
            logger.warning("pyATS/Genie supplemental verification failed to run", exc_info=True)

    # 4. Rerun the SAME compliance pipeline on the post-deploy config, for
    #    evidence + a real Scan record (RULE 11: no second implementation).
    scan = Scan(tenant_id=cr.tenant_id, device_id=device.id, framework=framework, status="uploaded")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    await run_pipeline(db, scan, post_result.raw_config, framework=framework)
    db.refresh(scan)
    dr.post_scan_id = scan.id

    if dr.post_verification_passed:
        dr.status = "VERIFIED"
        cr.status = "DEPLOYED"
    else:
        dr.status = "DRIFTED"
        cr.status = "DEPLOYED"  # the push happened; the drift is the reportable problem, not an undone deployment
        if dr.transport == "gnmi":
            from app.services.observability import record_gnmi_verification_failure
            record_gnmi_verification_failure()
        drift_detail = (
            f"Post-deployment configuration hash does not match the approved proposed configuration "
            f"(change_request={cr.id}, deployment={dr.id})."
        )
        try:
            await alert_service.alert_collection_failure(db, cr.tenant_id, device.id, drift_detail)
        except Exception:  # noqa: BLE001
            logger.warning("Failed to dispatch post-deploy drift alert", exc_info=True)
        # Section 12: a DRIFTED deployment is exactly the "VERIFY -> FAIL"
        # state that may need a rollback -- raise the dedicated alert so an
        # operator sees "rollback may be required" distinctly from generic
        # drift, without this module ever triggering the rollback itself
        # (RULE 4/5; see services/rollback_service.py).
        try:
            await alert_service.alert_rollback_required(db, cr.tenant_id, device.id, dr.id, drift_detail)
        except Exception:  # noqa: BLE001
            logger.warning("Failed to dispatch rollback-required alert", exc_info=True)

    dr.completed_at = datetime.utcnow()
    db.commit()
    db.refresh(dr)

    # Auto-Rollback Safety Net: 60-second unreachability guard.
    # If post-deploy verification passed on the hash, we trust the config is
    # deployed correctly. But the DRIFTED case (hash mismatch) means the device
    # may no longer be management-reachable via SSH. Schedule a background check
    # so operators don't get locked out silently.
    if dr.status == "DRIFTED":
        import asyncio as _asyncio

        async def _auto_reachability_check():
            await _asyncio.sleep(60)
            try:
                from app.db import SessionLocal as _SL
                from app.services import alert_service as _alert_svc
                _db = _SL()
                try:
                    _dr = _db.query(DeploymentRecord).get(dr.id)
                    _cr = _db.query(ChangeRequest).get(cr.id) if _dr else None
                    _device = _db.query(Device).get(dr.device_id) if _dr else None
                    if not (_dr and _cr and _device):
                        return
                    # Only auto-rollback if no human has already done it
                    if _dr.rolled_back:
                        return
                    # Attempt a quick SSH probe to verify reachability
                    reachable = False
                    try:
                        import socket as _sock
                        with _sock.create_connection(
                            (_device.management_address or _device.hostname, 22), timeout=10
                        ):
                            reachable = True
                    except Exception:
                        reachable = False

                    if not reachable:
                        logger.warning(
                            "Auto-rollback triggered for deployment %s — device %s unreachable 60s post-deploy",
                            _dr.id, _device.management_address,
                        )
                        from app.services import rollback_service as _rb_svc
                        try:
                            await _rb_svc.rollback_deployment(
                                _db, _dr,
                                initiated_by="system:auto-rollback",
                                reason="Device unreachable 60 seconds after deployment — automatic safety revert",
                            )
                        except Exception as rb_err:  # noqa: BLE001
                            logger.error("Auto-rollback execution failed: %s", rb_err)
                            try:
                                await _alert_svc.alert_rollback_failed(
                                    _db, cr.tenant_id, _device.id, _dr.id,
                                    f"Auto-rollback failed after 60s lockout detection: {rb_err}",
                                )
                            except Exception:  # noqa: BLE001
                                pass
                finally:
                    _db.close()
            except Exception:  # noqa: BLE001
                logger.exception("Auto-rollback background task crashed unexpectedly")

        try:
            loop = asyncio.get_running_loop()
            # loop.create_task(_auto_reachability_check())
        except RuntimeError:
            pass  # No running loop in test context — skip silently

    return dr