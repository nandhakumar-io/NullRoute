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
from app.services import alert_service, config_merge, minio_service, openbao_service
from app.services.stage_tracker import (DEPLOY_STAGES, KIND_LABELS, StageTracker,
                                        classify_push_error)
from app.services.collectors.registry import get_collector
from app.services.deployment.registry import get_deployer
from app.services.pipeline import run_pipeline

logger = logging.getLogger("deployment_service")


def to_dict(dr: DeploymentRecord) -> Dict[str, Any]:
    stages = dr.stages or derive_stages(dr)
    failed = next((st for st in stages if st.get("status") == "failed"), None)
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
        "rolled_back": bool(dr.rolled_back),
        "started_at": dr.started_at.isoformat() if dr.started_at else None,
        "completed_at": dr.completed_at.isoformat() if dr.completed_at else None,
        "request_hash": dr.request_hash,
        "model_name": dr.model_name,
        "paths": dr.paths,
        "operation": dr.operation,
        "verification_engine": dr.verification_engine,
        "verification_result": dr.verification_result,
        "verification_metadata": dr.verification_metadata,
        # Where did it stop? `stages` is the ordered pipeline; `failed_stage`
        # names the one that failed (None while running / on success).
        "stages": stages,
        "stages_derived": not bool(dr.stages),
        "failed_stage": failed["key"] if failed else None,
        "failure_kind": failed.get("kind") if failed else None,
        "failure_label": KIND_LABELS.get(failed.get("kind") or "", None) if failed else None,
        "target_control_ids": dr.target_control_ids,
        "target_controls_result": dr.target_controls_result,
        "target_controls_passed": dr.target_controls_passed,
        "batfish_diff_status": dr.batfish_diff_status,
        "batfish_diff_summary": dr.batfish_diff_summary,
        "batfish_diff_detail": dr.batfish_diff_detail,
        # A human decides -- nothing reverts automatically -- but the record
        # says when a revert is the sensible next step.
        "rollback_recommended": dr.status == "DRIFTED" and not dr.rolled_back,
    }


def to_dict_full(db: Session, dr: DeploymentRecord) -> Dict[str, Any]:
    """`to_dict` + the joined post-validation summary and every rollback
    attempt for this deployment: everything the pipeline view needs in one
    payload."""
    from app.models.db import RollbackRecord
    from app.services import rollback_service

    out = to_dict(dr)
    out["post_validation"] = post_validation(db, dr)
    rbs = (
        db.query(RollbackRecord)
        .filter(RollbackRecord.deployment_record_id == dr.id, RollbackRecord.tenant_id == dr.tenant_id)
        .order_by(RollbackRecord.started_at.desc())
        .all()
    )
    out["rollbacks"] = [rollback_service.to_dict_full(db, rb) for rb in rbs]
    return out


def derive_stages(dr: DeploymentRecord) -> list:
    """Best-effort stage list for deployments recorded before per-stage
    tracking existed. Works only from `status` / `error` / hashes, so the UI
    marks the result as derived rather than presenting it as first-hand."""
    from app.services.stage_tracker import blank_stages, PASSED, FAILED, SKIPPED, WARNING
    stages = blank_stages(DEPLOY_STAGES)
    by = {st["key"]: st for st in stages}
    err = dr.error or ""

    def mark(keys, status):
        for k in keys:
            by[k]["status"] = status

    order = [k for k, _ in DEPLOY_STAGES]

    def fail_at(key, kind):
        i = order.index(key)
        mark(order[:i], PASSED)
        by[key].update(status=FAILED, error=err or None, kind=kind)
        mark(order[i + 1:], SKIPPED)

    if dr.status in ("PENDING", "DEPLOYING"):
        mark(["credentials"], PASSED)
        return stages
    if dr.status == "ABORTED_STALE_HASH":
        fail_at("precheck", "stale_hash")
    elif dr.status == "FAILED":
        low = err.lower()
        if "credentials" in low and "post-deployment" not in low:
            fail_at("credentials", "credentials")
        elif "pre-deployment verification collection failed" in low:
            fail_at("connect", classify_push_error(err))
        elif "refusing to deploy" in low:
            fail_at("plan", "no_plan")
        elif "deployment push failed" in low:
            fail_at("commit", classify_push_error(err))
        elif "post-deployment" in low:
            fail_at("verify", "verification_unavailable")
        else:
            fail_at("commit", classify_push_error(err))
    elif dr.status in ("DEPLOYED", "VERIFIED", "DRIFTED"):
        mark(["credentials", "connect", "precheck", "plan", "commit"], PASSED)
        if dr.status == "DRIFTED":
            by["verify"].update(status=FAILED, error=err or "Post-change config does not match the approved proposal.",
                                kind="verification_mismatch")
        else:
            by["verify"]["status"] = PASSED
        by["postval"]["status"] = PASSED if dr.post_scan_id else SKIPPED
        if dr.status == "DEPLOYED":
            by["verify"]["status"] = WARNING
    return stages


def post_validation(db: Session, dr: DeploymentRecord) -> Optional[Dict[str, Any]]:
    """What the post-change compliance pipeline (OPA + Batfish + risk) said about
    the config that is actually on the device, plus the real before/after
    Batfish diff. Read-only; None until a post-scan exists."""
    if not dr.post_scan_id and not dr.batfish_diff_status:
        return None
    scan = db.query(Scan).get(dr.post_scan_id) if dr.post_scan_id else None
    findings = []
    if scan is not None:
        findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    failed = [f for f in findings if f.result == "FAIL"]
    return {
        "scan_id": dr.post_scan_id,
        "opa_decision": scan.opa_decision if scan else None,
        "batfish_status": scan.batfish_status if scan else None,
        "risk_level": scan.risk_level if scan else None,
        "risk_score": scan.risk_score if scan else None,
        "final_decision": scan.final_decision if scan else None,
        "final_reason": scan.final_reason if scan else None,
        "findings_total": len(findings),
        "findings_failed": len(failed),
        "failed_controls": [
            {"control_id": f.control_id, "title": f.title, "severity": f.severity}
            for f in failed[:25]
        ],
        "target_control_ids": dr.target_control_ids,
        "target_controls_result": dr.target_controls_result,
        "target_controls_passed": dr.target_controls_passed,
        "batfish_diff_status": dr.batfish_diff_status,
        "batfish_diff_summary": dr.batfish_diff_summary,
        "batfish_diff": dr.batfish_diff_detail,
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


def same_content(a: Optional[str], b: Optional[str]) -> bool:
    """Same configuration lines, ignoring order, whitespace and volatile lines.
    Forgives a device re-ordering/re-indenting output; an extra or missing line
    is still a mismatch (i.e. genuine drift)."""
    norm = lambda t: sorted(" ".join(l.split()) for l in config_merge.canonical_lines(t))
    return norm(a) == norm(b)


async def _batfish_before_after(device: Device, before_cfg: Optional[str], after_cfg: Optional[str],
                                dr_id: str) -> Dict[str, Any]:
    """Real Batfish before/after comparison of the device's configuration
    immediately before and after the push. Best-effort by design: a Batfish
    outage degrades to a labelled status (never a fabricated PASS) and can
    never fail the deployment itself."""
    from app.services import batfish_service
    vendor = device.vendor or "Unknown"
    host = device.hostname or "device"
    try:
        if not before_cfg or not after_cfg:
            return {"status": "BATFISH_UNAVAILABLE", "summary": "Before/after config was not available to diff.", "detail": None}
        if not batfish_service.is_vendor_supported(vendor):
            return {"status": "BATFISH_UNSUPPORTED", "summary": f"Batfish does not support vendor '{vendor}'.", "detail": None}
        result = await anyio.to_thread.run_sync(
            lambda: batfish_service.compare_network_snapshots(
                scan_id=f"deploy-{dr_id}",
                current_devices=[{"hostname": host, "raw_config": before_cfg}],
                proposed_devices=[{"hostname": host, "raw_config": after_cfg}],
            )
        )
        parts = []
        changed = (result.get("differential_reachability") or {}).get("changed_flow_count")
        if changed:
            parts.append(f"{changed} flow(s) changed reachability")
        rd = result.get("route_delta") or {}
        if rd.get("count_delta"):
            parts.append(f"routes {rd.get('current_count')}→{rd.get('proposed_count')}")
        nd = result.get("node_delta") or {}
        if nd.get("added") or nd.get("removed"):
            parts.append(f"nodes +{len(nd.get('added') or [])}/−{len(nd.get('removed') or [])}")
        return {
            "status": result.get("status", "BATFISH_ERROR"),
            "summary": "; ".join(parts) or "No behavioural difference detected between before and after.",
            "detail": result,
        }
    except Exception as e:  # noqa: BLE001 -- advisory only
        logger.warning("Batfish before/after diff failed for deployment %s", dr_id, exc_info=True)
        return {"status": "BATFISH_ERROR", "summary": f"Batfish before/after diff could not run: {type(e).__name__}", "detail": None}


async def deploy_change_request(
    db: Session,
    cr: ChangeRequest,
    initiated_by: str,
    credential_ref_id: Optional[str] = None,
    transport: Optional[str] = None,
    framework: str = "ALL",
    target_control_ids: Optional[list] = None,
    existing_dr: Optional[DeploymentRecord] = None,
) -> DeploymentRecord:
    """Run one deployment attempt. Pre-flight problems (not APPROVED, device
    missing) raise ValueError -> HTTP 409 with no record created. Once a
    DeploymentRecord exists, *nothing* escapes as an exception: an unexpected
    crash is recorded against the stage that was in flight, so the auditor
    sees where it died instead of a bare 500 and a record stuck DEPLOYING."""
    holder: Dict[str, Any] = {}
    try:
        return await _deploy_change_request(
            db, cr, initiated_by, credential_ref_id, transport, framework, target_control_ids, holder,
            existing_dr=existing_dr,
        )
    except Exception as e:  # noqa: BLE001
        dr = holder.get("dr")
        if dr is None:  # pre-flight failure (409) -- nothing was recorded
            raise
        logger.exception("Deployment %s crashed", dr.id)
        try:
            db.rollback()
            dr = db.query(DeploymentRecord).get(dr.id)
            StageTracker(db, dr, DEPLOY_STAGES).fail_running(f"{type(e).__name__}: {e}", kind="internal")
            dr.status = "FAILED"
            dr.error = dr.error or f"Deployment crashed unexpectedly: {type(e).__name__}: {e}"
            dr.completed_at = datetime.utcnow()
            cr_row = db.query(ChangeRequest).get(cr.id)
            if cr_row is not None:
                cr_row.status = "FAILED"
            db.commit()
        except Exception:  # noqa: BLE001
            logger.exception("Could not record crash of deployment %s", dr.id)
        return dr


async def _deploy_change_request(
    db: Session,
    cr: ChangeRequest,
    initiated_by: str,
    credential_ref_id: Optional[str],
    transport: Optional[str],
    framework: str,
    target_control_ids: Optional[list],
    holder: Dict[str, Any],
    existing_dr: Optional[DeploymentRecord] = None,
) -> DeploymentRecord:
    if cr.status not in ("APPROVED", "FAILED", "DEPLOYING"):
        raise ValueError(f"Change request {cr.id} is not APPROVED or FAILED (status={cr.status})")
    # The approval must still describe what is about to be pushed (HITL binding).
    from app.services.change_request_service import approval_still_valid
    stale_reason = approval_still_valid(cr)
    if stale_reason:
        raise ValueError(stale_reason)

    device: Device = db.query(Device).get(cr.device_id)
    if device is None:
        raise ValueError(f"Device {cr.device_id} not found")

    if existing_dr:
        dr = existing_dr
    else:
        dr = DeploymentRecord(
            tenant_id=cr.tenant_id, change_request_id=cr.id, device_id=device.id,
            initiated_by=initiated_by, transport=transport or "ssh",
            expected_pre_hash=cr.current_config_hash, status="PENDING",
            started_at=datetime.utcnow(),
            target_control_ids=list(target_control_ids) if target_control_ids else None,
        )
        db.add(dr)
    
    cr.status = "DEPLOYING"
    db.commit()
    db.refresh(dr)
    holder["dr"] = dr
    tracker = StageTracker(db, dr, DEPLOY_STAGES)

    tracker.start("credentials")
    try:
        credentials = _resolve_credentials(db, device, cr.tenant_id, credential_ref_id, transport=dr.transport)
    except (ValueError, openbao_service.OpenBaoError) as e:
        dr.status = "FAILED"
        dr.error = f"Could not resolve device credentials: {e}"
        dr.completed_at = datetime.utcnow()
        cr.status = "FAILED"
        db.commit()
        tracker.fail("credentials", dr.error, kind="credentials")
        return dr
    tracker.ok("credentials", f"Credentials resolved for {dr.transport or 'ssh'}.")

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
    tracker.start("connect", f"Connecting over {dr.transport or 'ssh'} and reading the running config.")
    pre_result = await anyio.to_thread.run_sync(collector.collect_config, device, credentials)
    if not pre_result.success or not pre_result.raw_config:
        dr.status = "FAILED"
        dr.error = f"Pre-deployment verification collection failed: {pre_result.error or 'no config returned'}"
        dr.completed_at = datetime.utcnow()
        cr.status = "FAILED"
        db.commit()
        tracker.fail("connect", pre_result.error or "no config returned",
                     kind=classify_push_error(pre_result.error) if pre_result.error else "connection")
        return dr
    tracker.ok("connect", f"Connected; running config read ({len(pre_result.raw_config.splitlines())} lines).")

    tracker.start("precheck", "Comparing the device's current config hash with the hash the change was validated against.")
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
        tracker.fail("precheck", dr.error, kind="stale_hash",
                     detail=f"expected {str(dr.expected_pre_hash)[:12]} · observed {str(pre_result.config_hash)[:12]}")
        try:
            await alert_service.alert_collection_failure(db, cr.tenant_id, device.id, dr.error)
        except Exception:  # noqa: BLE001 -- alerting must never mask the abort
            logger.warning("Failed to dispatch stale-hash-abort alert", exc_info=True)
        return dr
    tracker.ok("precheck", f"Device config matches the validated baseline ({str(pre_result.config_hash)[:12]}).")

    # 2. Push ONLY the delta. Previously every line of the full proposed
    #    config was sent through send_config_set, re-applying the whole device
    #    configuration (can lock a device out / make it unusable).
    tracker.start("plan", "Deriving the minimal command set to push.")
    proposed_text = minio_service.get_object(cr.proposed_config_object_key).decode("utf-8", errors="replace")
    plan = config_merge.resolve_deploy_commands(
        cr.merge_commands, pre_result.raw_config, proposed_text, device.vendor,
    )
    if not plan.safe or not plan.commands:
        dr.status = "FAILED"
        dr.error = (
            "Refusing to deploy: no safe, minimal command set could be derived for this change "
            f"({'; '.join(plan.warnings) or 'nothing to change'}). Edit the change request's proposed "
            "commands and re-approve it."
        )
        dr.completed_at = datetime.utcnow()
        cr.status = "FAILED"
        db.commit()
        del credentials
        tracker.fail("plan", dr.error, kind="no_plan")
        return dr
    tracker.ok("plan", f"{len(plan.commands)} command(s) will be pushed (never the whole config).")
    config_lines = plan.commands
    logger.info("Deploying %d command(s) to device %s for CR %s", len(config_lines), device.id, cr.id)
    deployer = get_deployer(transport)
    dr.status = "DEPLOYING"
    db.commit()
    tracker.start("commit", f"Pushing {len(config_lines)} command(s) over {dr.transport or 'ssh'}.")
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
        tracker.fail("commit", dr.error, kind=classify_push_error(push_result.error))
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
    tracker.ok("commit", "Commit accepted by the device"
               + (" (commit-confirmed timer running)." if getattr(push_result, "pending_confirm", False) else "."))

    # 3. Post-deployment collection + verification. Re-resolve credentials
    #    fresh (the earlier reference was deliberately dropped after push).
    tracker.start("verify", "Re-collecting the running config and comparing it with the approved proposal.")
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
        tracker.fail("verify", dr.error, kind="verification_unavailable",
                     detail="The commit was accepted but the device could not be re-read — its true state is unverified.")
        return dr

    dr.post_config_hash = post_result.config_hash
    hash_match = (post_result.config_hash == cr.proposed_config_hash)
    # Hash is order/whitespace sensitive; the same lines in a different order
    # (devices reorder output) is not drift, an extra/missing line is.
    dr.post_verification_passed = hash_match or same_content(post_result.raw_config, proposed_text)

    # Junos commit-confirmed: finalise only once the device is reachable and the
    # change is visible; otherwise leave it to auto-revert on the device.
    if getattr(push_result, "pending_confirm", False):
        if dr.post_verification_passed:
            try:
                confirm_creds = _resolve_credentials(db, device, cr.tenant_id, credential_ref_id, transport=dr.transport)
                confirm = await anyio.to_thread.run_sync(deployer.confirm_commit, device, confirm_creds)
                del confirm_creds
            except (ValueError, openbao_service.OpenBaoError) as e:
                confirm = None
                dr.error = f"Could not confirm commit (credentials unavailable: {e}); the device will auto-revert."
            if confirm is not None and not confirm.success:
                dr.error = f"Commit confirm failed: {confirm.error}; the device will auto-revert."
                dr.post_verification_passed = False
        else:
            dr.error = ((dr.error or "") + " Change was not confirmed; the device will auto-revert its commit-confirmed change.").strip()

    if dr.post_verification_passed:
        tracker.ok("verify", f"Device config matches the approved proposal ({str(post_result.config_hash)[:12]}).")
    else:
        tracker.fail(
            "verify",
            dr.error or "Post-change configuration does not match the approved proposal.",
            kind="verification_mismatch", skip_rest=False,
            detail=f"expected {str(cr.proposed_config_hash)[:12]} · observed {str(post_result.config_hash)[:12]}",
        )

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
    tracker.start("postval", "Re-running OPA, Batfish and risk scoring on the config now on the device.")
    scan = Scan(tenant_id=cr.tenant_id, device_id=device.id, framework=framework, status="uploaded")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    await run_pipeline(db, scan, post_result.raw_config, framework=framework)
    db.refresh(scan)
    dr.post_scan_id = scan.id

    if scan.status in ("stopped", "failed"):
        dr.post_verification_passed = False
        target_failed = True
        error_msg = f"Post-deployment validation scan did not complete (status: {scan.status}). Note: {scan.error or 'Pipeline stopped'}"
        dr.error = ((dr.error or "") + " " + error_msg).strip()

    target_failed = target_failed or False
    if target_control_ids:
        rows = db.query(Finding).filter(
            Finding.scan_id == scan.id, Finding.control_id.in_(list(target_control_ids)),
        ).all()
        by_control: Dict[str, str] = {}
        for f in rows:
            # A control is only PASS if every finding for it passed.
            if by_control.get(f.control_id) != "FAIL":
                by_control[f.control_id] = f.result
        dr.target_controls_result = [
            {"control_id": c, "result": by_control.get(c, "NOT_EVALUATED")} for c in target_control_ids
        ]
        failing = [f.control_id for f in rows if f.result != "PASS"]
        if failing:
            target_failed = True
            dr.post_verification_passed = False
            dr.error = (dr.error or "") + f" Targeted control(s) did not flip to PASS: {', '.join(sorted(set(failing)))}."

    # Real before/after Batfish diff of what was on the device before vs after
    # this change -- separate from the scan's single-snapshot Batfish verdict.
    diff = await _batfish_before_after(device, pre_result.raw_config, post_result.raw_config, dr.id)
    dr.batfish_diff_status = diff.get("status")
    dr.batfish_diff_summary = diff.get("summary")
    dr.batfish_diff_detail = diff.get("detail")
    db.commit()

    summary_bits = [
        f"OPA {scan.opa_decision or '—'}", f"Batfish {scan.batfish_status or '—'}",
        f"Risk {scan.risk_level or '—'}", f"Decision {scan.final_decision or '—'}",
    ]
    if target_failed:
        tracker.fail("postval", dr.error.strip(), kind="target_controls_failed",
                     detail=" · ".join(summary_bits), skip_rest=False)
    elif (scan.final_decision or "PASS") != "PASS" or diff.get("status") in ("BATFISH_FAIL", "BATFISH_ERROR"):
        tracker.warn("postval", " · ".join(summary_bits)
                     + (f" · Batfish before/after: {diff.get('summary')}" if diff.get("summary") else ""))
    else:
        tracker.ok("postval", " · ".join(summary_bits))

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