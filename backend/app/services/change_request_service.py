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

import hashlib
import logging
from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app.models.baseline import SecurityBaselineModel
from app.models.db import ChangeRequest, Device, Scan
from app.services import batfish_service, minio_service, risk_engine
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
        "approval_required": cr.approval_required,
        "approved_by": cr.approved_by, "approved_at": cr.approved_at,
        "rejected_by": cr.rejected_by, "rejected_at": cr.rejected_at,
        "rejection_reason": cr.rejection_reason,
        "created_at": cr.created_at, "updated_at": cr.updated_at,
    }


async def create_and_validate(
    db: Session,
    tenant_id: str,
    device: Device,
    proposed_config: str,
    created_by: str,
    source: str = "manual",
    current_config: Optional[str] = None,
) -> ChangeRequest:
    if current_config is None:
        current_config = latest_known_config(db, device.id)

    cr = ChangeRequest(
        tenant_id=tenant_id, device_id=device.id, created_by=created_by, source=source,
        proposed_config_hash=hashlib.sha256(proposed_config.encode("utf-8")).hexdigest(),
        current_config_hash=(
            hashlib.sha256(current_config.encode("utf-8")).hexdigest() if current_config else None
        ),
        status="DRAFT",
    )
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

        opa_decision = await evaluate_baseline_via_opa(f"cr:{cr.id}", baseline, "ALL")

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

        decision = correlate(
            syntax_ok=True, opa_decision=opa_decision, risk=risk,
            batfish_status=bf_result.status, batfish_critical_violation=bf_result.critical_violation,
        )

        cr.syntax_status = "OK"
        cr.opa_decision = opa_decision.decision
        cr.batfish_status = bf_result.status
        cr.risk_score = risk.risk_score
        cr.risk_level = risk.risk_level
        cr.final_decision = decision.decision
        cr.final_reason = decision.reason
        cr.validation_detail = {
            "opa_findings": opa_decision.findings,
            "batfish_findings": batfish_findings,
            "risk_factors": risk.contributing_factors,
            "contributing": decision.contributing,
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