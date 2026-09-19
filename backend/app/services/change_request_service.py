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

import logging
from datetime import datetime
from typing import Any, Dict, Optional

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
    }


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

    try:
        vendor = device.vendor or "Unknown"
        baseline: SecurityBaselineModel = parse_config(vendor, proposed_config)
        baseline.device.hostname = baseline.device.hostname or device.hostname
        baseline.raw_config_hash = cr.proposed_config_hash

        opa_decision = await evaluate_baseline_via_opa(f"cr:{cr.id}", baseline, "ALL", db=db, tenant_id=tenant_id)

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

    db.commit()
    db.refresh(cr)
    return cr


def approve(db: Session, cr: ChangeRequest, approved_by: str) -> ChangeRequest:
    if cr.status != "PENDING_APPROVAL":
        raise ValueError(f"Change request {cr.id} is not pending approval (status={cr.status})")
    cr.status = "APPROVED"
    cr.approved_by = approved_by
    cr.approved_at = datetime.utcnow()
    db.commit()
    db.refresh(cr)
    return cr


def reject(db: Session, cr: ChangeRequest, rejected_by: str, reason: Optional[str] = None) -> ChangeRequest:
    if cr.status not in ("PENDING_APPROVAL", "APPROVED"):
        raise ValueError(f"Change request {cr.id} cannot be rejected from status={cr.status}")
    cr.status = "REJECTED"
    cr.rejected_by = rejected_by
    cr.rejected_at = datetime.utcnow()
    cr.rejection_reason = reason
    db.commit()
    db.refresh(cr)
    return cr
