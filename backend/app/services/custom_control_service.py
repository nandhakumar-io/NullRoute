"""CRUD + evaluation-time loader for tenant-defined CustomControl rows.

Referenced by policies/common/custom.rego's module docstring and by
IMPLEMENTATION_AUDIT.md §C. This is the piece that was missing: the model
and the Rego evaluation logic existed, but nothing wrote to CustomControl's
review-workflow columns (status/approved_by/approved_at) and nothing built
`input.custom_controls` for OPA to actually consume. See
services/compliance.py::evaluate_baseline_via_opa for the call site that
uses `for_opa_input()` below.

Lifecycle: create() always lands in "pending_review" -- a freshly created
custom control MUST NOT affect any scan's decision until a human approves
it (same anti-fabrication posture as everything else gated by RULE 12).
Only approve() flips status to "approved", which is the only status
for_opa_input() will pick up.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.models.db import CustomControl, gen_uuid

VALID_OPERATORS = {"eq", "ne", "gte", "lte", "in", "exists", "not_true"}
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


class CustomControlValidationError(Exception):
    """Raised for a malformed control (bad operator/severity, or a
    control_id already used by this tenant). Routers turn this into a 400."""


def list_controls(db: Session, tenant_id: str, status: Optional[str] = None) -> List[CustomControl]:
    q = db.query(CustomControl).filter(CustomControl.tenant_id == tenant_id)
    if status:
        q = q.filter(CustomControl.status == status)
    return q.order_by(CustomControl.created_at.desc()).all()


def get_control(db: Session, tenant_id: str, control_id: str) -> Optional[CustomControl]:
    return (
        db.query(CustomControl)
        .filter(CustomControl.tenant_id == tenant_id, CustomControl.id == control_id)
        .first()
    )


def create_control(
    db: Session,
    tenant_id: str,
    *,
    control_id: str,
    title: str,
    parameter: str,
    operator: str,
    expected: Any,
    severity: str = "MEDIUM",
    remediation: Optional[str] = None,
    created_by: Optional[str] = None,
) -> CustomControl:
    if operator not in VALID_OPERATORS:
        raise CustomControlValidationError(
            f"operator must be one of {sorted(VALID_OPERATORS)}, got {operator!r}"
        )
    if severity not in VALID_SEVERITIES:
        raise CustomControlValidationError(
            f"severity must be one of {sorted(VALID_SEVERITIES)}, got {severity!r}"
        )
    existing = (
        db.query(CustomControl)
        .filter(CustomControl.tenant_id == tenant_id, CustomControl.control_id == control_id)
        .first()
    )
    if existing:
        raise CustomControlValidationError(
            f"control_id {control_id!r} already exists for this tenant"
        )

    row = CustomControl(
        id=gen_uuid(),
        tenant_id=tenant_id,
        control_id=control_id,
        title=title,
        parameter=parameter,
        operator=operator,
        expected_json=expected,
        severity=severity,
        remediation=remediation,
        status="pending_review",
        created_by=created_by,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _set_status(db: Session, control: CustomControl, status: str, reviewer: Optional[str]) -> CustomControl:
    control.status = status
    control.approved_by = reviewer
    control.approved_at = datetime.utcnow()
    control.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(control)
    return control


def approve_control(db: Session, control: CustomControl, reviewer: str) -> CustomControl:
    """Flip a pending_review control to approved. This is the only
    transition that makes for_opa_input() start including it -- effective
    on the very next scan for this tenant, no bundle reload."""
    return _set_status(db, control, "approved", reviewer)


def reject_control(db: Session, control: CustomControl, reviewer: str) -> CustomControl:
    return _set_status(db, control, "rejected", reviewer)


def delete_control(db: Session, control: CustomControl) -> None:
    db.delete(control)
    db.commit()


def for_opa_input(db: Session, tenant_id: str) -> List[Dict[str, Any]]:
    """Approved custom controls for this tenant, shaped exactly as
    policies/common/custom.rego expects each entry of input.custom_controls:
    {control_id, title, parameter, operator, expected, severity, remediation}.
    Anything not status=="approved" (pending_review, rejected) is excluded --
    an unreviewed or rejected custom control must never influence a
    decision."""
    rows = (
        db.query(CustomControl)
        .filter(CustomControl.tenant_id == tenant_id, CustomControl.status == "approved")
        .all()
    )
    return [
        {
            "control_id": r.control_id,
            "title": r.title,
            "parameter": r.parameter,
            "operator": r.operator,
            "expected": r.expected_json,
            "severity": r.severity,
            "remediation": r.remediation,
        }
        for r in rows
    ]