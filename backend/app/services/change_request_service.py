"""Phase 14 -- change request creation, validation, and approval.

`create_and_validate()` is the ONLY place a ChangeRequest's proposed
configuration is run through the compliance engines, and it calls the
exact same functions services/pipeline.py uses for scans
(services/compliance.py:evaluate_baseline_via_opa, services/
batfish_service.py:analyze_security_behavior, services/risk_engine.py:
calculate_risk, services/change_validation_service.py:correlate) --
RULE 11, no second compliance implementation. The differences from a
scan are intentional and match the Phase 14 workflow, which stops at
"approval" (deployment, post-deployment verification, and evidence
generation are Phase 15/18, not here):

  - no Finding/Evidence/Fabric rows are written for a ChangeRequest --
    those are scan-shaped concepts; the validator's output is stored
    directly on the ChangeRequest row instead.
  - approval is a separate, always-required human step (RULE 5) --
    validate() never sets status to APPROVED, regardless of what the
    validator decided.
"""
from __future__ import annotations

import copy
import logging
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.models.baseline import SecurityBaselineModel
from app.models.db import ChangeRequest, Device, Scan
from app.services import batfish_service, config_merge, minio_service, risk_engine
from app.services.change_validation_service import correlate
from app.services.compliance import evaluate_baseline_via_opa
from app.services.parsers import parse_config

logger = logging.getLogger("change_request_service")


def object_key(tenant_id: str, device_id: str, cr_id: str, filename: str) -> str:
    """Change-request artifacts get their own namespace, parallel to but
    distinct from minio_service.object_key's scans/{scan_id}/ layout."""
    return f"tenants/{tenant_id}/devices/{device_id}/change-requests/{cr_id}/{filename}"


def latest_known_config(db: Session, device_id: str) -> Optional[str]:
    """Best-effort lookup of the device's most recent successful scan's raw
    configuration, used as the "current" side of a change request when the
    caller doesn't supply one explicitly. Returns None (not an error) if
    there is no prior scan or the object can't be read -- a ChangeRequest
    can still be created and validated without a known "current" baseline;
    it just won't have a current_config_hash to compare against later."""
    scan = (
        db.query(Scan)
        .filter(Scan.device_id == device_id, Scan.raw_config_path.isnot(None))
        .order_by(Scan.created_at.desc())
        .first()
    )
    if not scan or not scan.raw_config_path:
        return None
    try:
        return minio_service.get_object(scan.raw_config_path).decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001 - missing/unreadable prior config is not fatal
        logger.warning("Could not read prior config for device %s", device_id, exc_info=True)
        return None


def to_dict(cr: ChangeRequest) -> Dict[str, Any]:
    return {
        "id": cr.id, "tenant_id": cr.tenant_id, "device_id": cr.device_id,
        "created_by": cr.created_by, "source": cr.source,
        "current_config_hash": cr.current_config_hash,
        "proposed_config_hash": cr.proposed_config_hash,
        "status": cr.status,
        "syntax_status": cr.syntax_status, "opa_decision": cr.opa_decision,
        "batfish_status": cr.batfish_status, "risk_score": cr.risk_score,
        "risk_level": cr.risk_level, "final_decision": cr.final_decision,
        "final_reason": cr.final_reason, "validation_detail": cr.validation_detail,
        "snapshot_diff": cr.snapshot_diff,
        "approval_required": cr.approval_required,
        "approved_by": cr.approved_by, "approved_at": cr.approved_at,
        "rejected_by": cr.rejected_by, "rejected_at": cr.rejected_at,
        "rejection_reason": cr.rejection_reason,
        "created_at": cr.created_at, "updated_at": cr.updated_at,
        # Only non-null when this CR was created from a CLI remediation
        # delta rather than a full proposed config -- see preview_merge()/
        # create_and_validate()'s `snippet` argument.
        "snippet": cr.snippet,
        "merge_style": cr.merge_style,
        "merge_confidence": cr.merge_confidence,
        "merge_applied": cr.merge_applied,
        "merge_warnings": cr.merge_warnings,
        "merge_commands": cr.merge_commands,
        "edited_by": cr.edited_by, "edited_at": cr.edited_at, "revision": getattr(cr, "revision", 1) or 1,
        # Human-in-the-loop state -- everything the approval UI needs to decide
        # what to demand from the reviewer, in one place.
        "approved_revision": cr.approved_revision, "approved_hash": cr.approved_hash,
        "review_comment": cr.review_comment, "override_justification": cr.override_justification,
        "review_events": cr.review_events or [],
        "hitl": hitl_requirements(cr),
    }


# ---------------------------------------------------------------------------
# Human-in-the-loop policy
# ---------------------------------------------------------------------------
# The platform's founding rule (RULE 4/5) is that AI proposes and a human
# disposes. These functions are where "a human disposed" is made *meaningful*
# rather than a single unconditional button:
#
#  * an approval is bound to the exact revision + hash the reviewer was shown,
#    so an edit landing between "open" and "click" cannot be approved unseen;
#  * a change the validator BLOCKed can still be approved (a human may know
#    better) but only with a written justification that is stored on the record;
#  * risky changes (REVIEW/BLOCK, HIGH/CRITICAL risk) need a reviewer note;
#  * four-eyes: for the risky class the approver must not be the author
#    (HITL_FOUR_EYES = off | high_risk (default) | always). Skipped in the
#    single-implicit-user demo mode, where "different person" is meaningless;
#  * approvals can expire (HITL_APPROVAL_TTL_HOURS, default 0 = never);
#  * rejection requires a reason; every decision lands in `review_events`.

MIN_NOTE_CHARS = 10


class HitlError(ValueError):
    """A human-in-the-loop policy refusal. Carries a machine-readable `code`
    and the HTTP status the router should answer with."""

    def __init__(self, message: str, code: str, http_status: int = 409):
        super().__init__(message)
        self.code = code
        self.http_status = http_status


def _four_eyes_mode() -> str:
    mode = os.environ.get("HITL_FOUR_EYES", "high_risk").strip().lower()
    return mode if mode in ("off", "high_risk", "always") else "high_risk"


def _approval_ttl_hours() -> float:
    try:
        return max(0.0, float(os.environ.get("HITL_APPROVAL_TTL_HOURS", "0")))
    except ValueError:
        return 0.0


def _is_risky(cr: ChangeRequest) -> bool:
    return (cr.final_decision in ("REVIEW", "BLOCK")) or (cr.risk_level in ("HIGH", "CRITICAL"))


def _auth_enforced() -> bool:
    from app.auth import dependencies as deps_mod
    return bool(deps_mod.AUTH_ENABLED)


def hitl_requirements(cr: ChangeRequest) -> Dict[str, Any]:
    """What approving THIS change demands of the reviewer (also drives the UI)."""
    mode = _four_eyes_mode()
    four_eyes = _auth_enforced() and (mode == "always" or (mode == "high_risk" and _is_risky(cr)))
    ttl = _approval_ttl_hours()
    expires = None
    if ttl and cr.approved_at and cr.status == "APPROVED":
        expires = (cr.approved_at + timedelta(hours=ttl)).isoformat()
    return {
        "note_required": _is_risky(cr),
        "min_note_chars": MIN_NOTE_CHARS,
        "override_required": cr.final_decision == "BLOCK",
        "four_eyes_required": bool(four_eyes),
        "four_eyes_mode": mode,
        "approval_expires_at": expires,
        "approval_ttl_hours": ttl or None,
    }


def add_event(db: Session, cr: ChangeRequest, action: str, actor: Optional[str],
              comment: Optional[str] = None, commit: bool = True, **extra: Any) -> None:
    """Append one entry to the CR's human-decision trail. Append-only; never
    raises (an audit-trail hiccup must not block the decision it records)."""
    try:
        events: List[Dict[str, Any]] = copy.deepcopy(cr.review_events or [])
        events.append({
            "at": datetime.utcnow().isoformat(), "action": action, "actor": actor or "unknown",
            "revision": getattr(cr, "revision", 1) or 1, "comment": comment, **extra,
        })
        cr.review_events = events  # reassign so SQLAlchemy sees the JSON change
        if commit:
            db.commit()
    except Exception:  # noqa: BLE001
        logger.warning("Could not append review event %s to change request %s", action, cr.id, exc_info=True)
        try:
            db.rollback()
        except Exception:  # noqa: BLE001
            pass


def approval_still_valid(cr: ChangeRequest) -> Optional[str]:
    """None if the standing approval may be acted on (deployed); otherwise the
    reason it may not. Called by deployment before a single command is sent."""
    if cr.approved_hash and cr.approved_hash != cr.proposed_config_hash:
        return ("The proposed configuration changed after it was approved; "
                "the approval no longer applies. Re-approve the current revision.")
    if cr.approved_revision and cr.approved_revision != (cr.revision or 1):
        return (f"Approval was granted for revision {cr.approved_revision} but the change is now at revision "
                f"{cr.revision}. Re-approve the current revision.")
    ttl = _approval_ttl_hours()
    if ttl and cr.approved_at and datetime.utcnow() > cr.approved_at + timedelta(hours=ttl):
        return f"The approval expired after {ttl:g} hour(s). Re-approve before deploying."
    return None


def preview_merge(
    db: Session, device: Device, snippet: str, current_config: Optional[str] = None,
) -> Dict[str, Any]:
    """Read-only preview of what applying `snippet` (a CLI remediation
    delta) to `device`'s current configuration would produce. Persists
    nothing -- used by POST /api/change-requests/preview so a reviewer can
    see the merged config, the applied-commands breakdown, and the
    confidence/warnings the merge engine reports *before* deciding whether
    to actually create a change request from it. Mirrors exactly the merge
    step create_and_validate() runs when it's given a `snippet` instead of
    a full `proposed_config`, so what was previewed is what gets created.
    """
    if current_config is None:
        current_config = latest_known_config(db, device.id)
    result = config_merge.apply_commands(current_config, snippet, vendor=device.vendor)
    return {
        "device_id": device.id,
        "current_config": current_config,
        "proposed_config": result.merged_text,
        "diff_stats": config_merge.diff_stats(current_config, result.merged_text),
        **result.to_dict(),
    }


async def _validate(db: Session, cr: ChangeRequest, device: Device, proposed_config: str,
                    current_config: Optional[str]) -> None:
    """Run the full OPA/Batfish/risk validation and record the verdict on `cr`
    (status -> PENDING_APPROVAL, or DRAFT/BLOCK if validation itself failed)."""
    try:
        vendor = device.vendor or "Unknown"
        baseline: SecurityBaselineModel = parse_config(vendor, proposed_config)
        baseline.device.hostname = baseline.device.hostname or device.hostname
        baseline.raw_config_hash = cr.proposed_config_hash

        opa_decision = await evaluate_baseline_via_opa(f"cr:{cr.id}", baseline, "ALL", db=db, tenant_id=cr.tenant_id)

        bf_result = batfish_service.analyze_security_behavior(
            scan_id=f"cr-{cr.id}", vendor=vendor,
            hostname=baseline.device.hostname or device.hostname or "device",
            raw_config=proposed_config,
        )
        batfish_findings = bf_result.findings()

        unknown_count = len([p for p in baseline.provenance if p.source == "ai" and p.confidence < 0.75])
        risk = risk_engine.calculate_risk(
            opa_decision.findings, batfish_findings=batfish_findings, unknown_syntax_count=unknown_count,
        )

        # Change-impact simulation (Phase 10 wiring): diff a CURRENT
        # snapshot (the device's last known scanned config, if any) against
        # a PROPOSED snapshot (this change request's candidate config) so a
        # reviewer sees behavioral deltas -- e.g. a newly-reachable
        # Guest->Management path -- *before* approval, not discovered only
        # after deployment. Purely additive/advisory: it can only surface a
        # REVIEW reason via change_validation_service.correlate(), never
        # itself BLOCK or override OPA/Batfish's own single-snapshot
        # verdict (RULE 11/13 -- no second compliance authority).
        change_impact_status = "NOT_CHECKED"
        change_impact_summary: Optional[str] = None
        snapshot_diff: Optional[Dict[str, Any]] = None
        if current_config is not None and batfish_service.BATFISH_ENABLED and batfish_service.is_vendor_supported(vendor):
            try:
                snapshot_diff = batfish_service.compare_network_snapshots(
                    scan_id=f"cr-{cr.id}",
                    current_devices=[{"hostname": device.hostname or "device", "raw_config": current_config}],
                    proposed_devices=[{"hostname": device.hostname or "device", "raw_config": proposed_config}],
                )
                change_impact_status = snapshot_diff.get("status", "BATFISH_ERROR")
                if change_impact_status == "BATFISH_FAIL":
                    node_delta = snapshot_diff.get("node_delta", {})
                    diff_reach = snapshot_diff.get("differential_reachability", {})
                    parts = []
                    if node_delta.get("added") or node_delta.get("removed"):
                        parts.append(f"nodes added={node_delta.get('added')} removed={node_delta.get('removed')}")
                    if diff_reach.get("changed_flow_count"):
                        parts.append(f"{diff_reach['changed_flow_count']} flow(s) changed reachability")
                    change_impact_summary = "; ".join(parts) or None
            except Exception:  # noqa: BLE001 - snapshot diff is best-effort, never blocks CR validation
                logger.warning("Batfish snapshot diff failed for change request %s", cr.id, exc_info=True)
                change_impact_status = "BATFISH_ERROR"
                snapshot_diff = {"status": "BATFISH_ERROR", "detail": "Snapshot diff raised; see server logs."}

        decision = correlate(
            syntax_ok=True, opa_decision=opa_decision, risk=risk,
            batfish_status=bf_result.status, batfish_critical_violation=bf_result.critical_violation,
            change_impact_status=change_impact_status, change_impact_summary=change_impact_summary,
        )

        cr.syntax_status = "OK"
        cr.opa_decision = opa_decision.decision
        cr.batfish_status = bf_result.status
        cr.risk_score = risk.risk_score
        cr.risk_level = risk.risk_level
        cr.final_decision = decision.decision
        cr.final_reason = decision.reason
        cr.snapshot_diff = snapshot_diff
        cr.validation_detail = {
            "opa_findings": opa_decision.findings,
            "batfish_findings": batfish_findings,
            "risk_factors": risk.contributing_factors,
            "contributing": decision.contributing,
            "change_impact_status": change_impact_status,
        }
        cr.status = "PENDING_APPROVAL"
    except Exception as e:  # noqa: BLE001 - a validation failure is recorded, not raised
        logger.exception("Change request %s validation failed", cr.id)
        cr.syntax_status = "ERROR"
        cr.final_decision = "BLOCK"
        cr.final_reason = f"Validation could not complete: {e}"
        cr.status = "DRAFT"



async def create_and_validate(
    db: Session,
    tenant_id: str,
    device: Device,
    proposed_config: Optional[str] = None,
    created_by: str = None,
    source: str = "manual",
    current_config: Optional[str] = None,
    snippet: Optional[str] = None,
) -> ChangeRequest:
    """Create a ChangeRequest and run it through the full validation
    pipeline. Exactly one of `proposed_config` (a complete configuration)
    or `snippet` (a CLI remediation delta, e.g. straight from a Finding's
    `remediation` text) must be given.

    When `snippet` is given, services/config_merge.py::apply_commands()
    (the merge engine -- previously implemented but never called from any
    endpoint) is run against the device's current configuration first, and
    its merged_text becomes `proposed_config` for every step below
    (validation, hashing, archival). This is the same merge preview_merge()
    runs, so a CR created from a snippet a reviewer already previewed
    produces exactly the config they saw.
    """
    if (proposed_config is None) == (snippet is None):
        raise ValueError("create_and_validate requires exactly one of proposed_config or snippet")

    if current_config is None:
        current_config = latest_known_config(db, device.id)

    # A remediation delta submitted as `proposed_config` (what the scan page used
    # to do) is NOT a device config: treat it as a snippet so it is merged onto the
    # current config instead of replacing it.
    if snippet is None and proposed_config is not None and current_config \
            and not config_merge.is_full_config(proposed_config):
        snippet, proposed_config = proposed_config, None

    merge_result = None
    if snippet is not None:
        merge_result = config_merge.apply_commands(current_config, snippet, vendor=device.vendor)
        proposed_config = merge_result.merged_text

    cr = ChangeRequest(
        tenant_id=tenant_id, device_id=device.id, created_by=created_by, source=source,
        # Canonical (volatile-line-stripped) hashes -- see
        # services/config_merge.py::config_hash and
        # services/collectors/base.py::CollectionResult.__post_init__ for
        # why: deployment_service.py compares these against freshly
        # collected devices' CollectionResult.config_hash (now also
        # canonical), and a raw byte hash would false-positive on
        # vendor-inserted volatile lines (timestamps, NVRAM metadata) that
        # differ on every collection regardless of whether anything
        # meaningful changed.
        proposed_config_hash=config_merge.config_hash(proposed_config),
        current_config_hash=(config_merge.config_hash(current_config) if current_config else None),
        status="DRAFT",
    )
    if merge_result is not None:
        cr.snippet = snippet
        cr.merge_style = merge_result.style
        cr.merge_confidence = merge_result.confidence
        cr.merge_applied = [a.to_dict() for a in merge_result.applied]
        cr.merge_warnings = list(merge_result.warnings)
        cr.merge_commands = list(merge_result.commands)
    db.add(cr)
    db.commit()
    db.refresh(cr)

    # Archive both sides in MinIO (Phase 8 pattern); best-effort, never
    # blocks validation (see minio_service.put_object docstring).
    proposed_put = minio_service.put_object(
        object_key(tenant_id, device.id, cr.id, "proposed.cfg"),
        proposed_config.encode("utf-8"), content_type="text/plain",
    )
    if proposed_put is not None:
        cr.proposed_config_object_key = proposed_put.object_key
    if current_config is not None:
        current_put = minio_service.put_object(
            object_key(tenant_id, device.id, cr.id, "current.cfg"),
            current_config.encode("utf-8"), content_type="text/plain",
        )
        if current_put is not None:
            cr.current_config_object_key = current_put.object_key
    db.commit()

    await _validate(db, cr, device, proposed_config, current_config)

    db.commit()
    add_event(db, cr, "submitted", created_by or ("ai" if source == "ai_suggestion" else "unknown"),
              source=source, decision=cr.final_decision, risk=cr.risk_level, status=cr.status)
    db.refresh(cr)
    return cr


def approve(
    db: Session, cr: ChangeRequest, approved_by: str,
    comment: Optional[str] = None,
    expected_revision: Optional[int] = None,
    expected_hash: Optional[str] = None,
) -> ChangeRequest:
    if cr.status != "PENDING_APPROVAL":
        raise HitlError(f"Change request {cr.id} is not pending approval (status={cr.status})", "wrong_status", 409)

    # 1. The reviewer must be approving what they actually looked at.
    current_rev = cr.revision or 1
    if expected_revision is not None and expected_revision != current_rev:
        raise HitlError(
            f"This change was edited while you were reviewing it (you saw revision {expected_revision}, "
            f"it is now revision {current_rev}). Reload and review the new version before approving.",
            "stale_revision", 409,
        )
    if expected_hash is not None and expected_hash != cr.proposed_config_hash:
        raise HitlError(
            "The proposed configuration no longer matches what you reviewed. Reload and review it again.",
            "stale_revision", 409,
        )

    # 2. Four-eyes: the author cannot wave through their own risky change.
    req = hitl_requirements(cr)
    if req["four_eyes_required"] and cr.created_by and cr.created_by == approved_by:
        raise HitlError(
            "Four-eyes rule: you created this change request, so a different reviewer must approve it "
            f"(policy: {req['four_eyes_mode']}).",
            "four_eyes", 403,
        )

    # 3. Risky changes need a written reason; a validator BLOCK needs a
    #    justification for overriding it. Both are stored on the record.
    note = (comment or "").strip()
    if req["note_required"] and len(note) < MIN_NOTE_CHARS:
        what = ("overriding the validator's BLOCK verdict" if req["override_required"]
                else "approving a change flagged for review / elevated risk")
        raise HitlError(
            f"A reviewer note of at least {MIN_NOTE_CHARS} characters is required when {what}.",
            "note_required", 422,
        )

    override = cr.final_decision == "BLOCK"
    cr.status = "APPROVED"
    cr.approved_by = approved_by
    cr.approved_at = datetime.utcnow()
    cr.approved_revision = current_rev
    cr.approved_hash = cr.proposed_config_hash
    cr.review_comment = note or None
    cr.override_justification = note if override else None
    # An approval clears any earlier rejection on this record.
    cr.rejected_by = cr.rejected_at = cr.rejection_reason = None
    add_event(db, cr, "override_approved" if override else "approved", approved_by, note or None,
              commit=False, decision=cr.final_decision, risk=cr.risk_level, hash=cr.proposed_config_hash)
    db.commit()
    db.refresh(cr)
    return cr


def reject(db: Session, cr: ChangeRequest, rejected_by: str, reason: Optional[str] = None) -> ChangeRequest:
    if cr.status not in ("PENDING_APPROVAL", "APPROVED"):
        raise HitlError(f"Change request {cr.id} cannot be rejected from status={cr.status}", "wrong_status", 409)
    reason = (reason or "").strip()
    if len(reason) < 3:
        raise HitlError("A reason is required to reject a change request.", "reason_required", 422)
    cr.status = "REJECTED"
    cr.rejected_by = rejected_by
    cr.rejected_at = datetime.utcnow()
    cr.rejection_reason = reason
    cr.review_comment = reason
    cr.approved_revision = cr.approved_hash = None
    add_event(db, cr, "rejected", rejected_by, reason, commit=False)
    db.commit()
    db.refresh(cr)
    return cr


EDITABLE_STATUSES = ("DRAFT", "PENDING_APPROVAL", "APPROVED")


def _read_blob(key: Optional[str]) -> Optional[str]:
    if not key:
        return None
    try:
        return minio_service.get_object(key).decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return None


def preview_edit(db: Session, cr: ChangeRequest, device: Device, snippet: Optional[str] = None,
                 proposed_config: Optional[str] = None) -> Dict[str, Any]:
    """Read-only: what would this edit produce? Merges onto the CR's ARCHIVED
    current config (the base its approval hash was taken against)."""
    if (snippet is None) == (proposed_config is None):
        raise ValueError("Provide exactly one of snippet or proposed_config")
    current = _read_blob(cr.current_config_object_key) or latest_known_config(db, device.id)
    if snippet is not None:
        res = config_merge.apply_commands(current, snippet, vendor=device.vendor)
        proposed, commands, extra = res.merged_text, list(res.commands), res.to_dict()
    else:
        proposed = proposed_config
        if current and not config_merge.is_full_config(proposed_config):
            res = config_merge.apply_commands(current, proposed_config, vendor=device.vendor)
            proposed, commands, extra = res.merged_text, list(res.commands), res.to_dict()
        else:
            plan = config_merge.delta_between(current, proposed_config, device.vendor)
            commands, extra = plan.commands, {"warnings": plan.warnings, "safe": plan.safe, "style": plan.style}
    return {"current_config": current, "proposed_config": proposed, "commands": commands,
            "diff_stats": config_merge.diff_stats(current, proposed), **extra}


def deploy_plan(cr: ChangeRequest, device: Device) -> Dict[str, Any]:
    """Exactly what deployment would push for this CR (never a full config)."""
    plan = config_merge.resolve_deploy_commands(
        cr.merge_commands, _read_blob(cr.current_config_object_key),
        _read_blob(cr.proposed_config_object_key), device.vendor,
    )
    return {"commands": plan.commands, "warnings": plan.warnings, "safe": plan.safe and bool(plan.commands),
            "style": plan.style}


async def update_proposal(db: Session, cr: ChangeRequest, device: Device, edited_by: str,
                          snippet: Optional[str] = None, proposed_config: Optional[str] = None) -> ChangeRequest:
    """Admin fine-tuning: replace the proposed change, re-merge onto the archived
    current config, re-run validation, and require a fresh approval."""
    if cr.status not in EDITABLE_STATUSES:
        raise ValueError(f"Change request {cr.id} cannot be edited in status {cr.status}")
    prev = preview_edit(db, cr, device, snippet=snippet, proposed_config=proposed_config)
    proposed = prev["proposed_config"]
    current = prev["current_config"]
    if not (proposed or "").strip():
        raise ValueError("Proposed change is empty")

    use_snippet = snippet is not None or (current and not config_merge.is_full_config(proposed_config or ""))
    raw_snippet = snippet if snippet is not None else proposed_config
    cr.proposed_config_hash = config_merge.config_hash(proposed)
    if use_snippet:
        cr.snippet = raw_snippet
        cr.merge_style = prev.get("style")
        cr.merge_confidence = prev.get("confidence")
        cr.merge_applied = prev.get("applied")
        cr.merge_warnings = prev.get("warnings")
        cr.merge_commands = prev.get("commands")
    else:  # full-config edit: deployment will diff it against the device
        cr.snippet = cr.merge_style = cr.merge_confidence = None
        cr.merge_applied = cr.merge_warnings = cr.merge_commands = None

    put = minio_service.put_object(object_key(cr.tenant_id, device.id, cr.id, "proposed.cfg"),
                                   proposed.encode("utf-8"), content_type="text/plain")
    if put is not None:
        cr.proposed_config_object_key = put.object_key
    # Any edit invalidates a prior approval / rejection.
    cr.approved_by = cr.approved_at = cr.rejected_by = cr.rejected_at = cr.rejection_reason = None
    cr.edited_by, cr.edited_at = edited_by, datetime.utcnow()
    cr.revision = (cr.revision or 1) + 1
    # ...including the HITL binding: whatever was approved is not this.
    cr.approved_revision = cr.approved_hash = cr.review_comment = cr.override_justification = None
    db.commit()
    await _validate(db, cr, device, proposed, current)
    db.commit()
    add_event(db, cr, "edited", edited_by, "Proposal edited; validation re-run and approval reset.",
              decision=cr.final_decision, risk=cr.risk_level)
    db.refresh(cr)
    return cr
