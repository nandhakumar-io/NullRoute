"""
Phase 16 -- Compliance Exceptions.

An exception NEVER modifies OPA's original result: the underlying
Finding row (and its OPA-computed `result`) is untouched forever. This
module only computes a PRESENTATION overlay -- given a finding's
(device_id, control_id) and the current, unexpired, APPROVED exceptions
for that tenant, decide whether the finding should additionally show
EXCEPTION_ACCEPTED. Evidence and reports must show BOTH the underlying
OPA result and this presentation overlay, never one in place of the other.

Expired exceptions stop suppressing findings automatically -- there is no
separate cron job for this: `is_active()` re-checks `expires_at` on every
call, and `sweep_expired()` (called opportunistically from the router) also
flips the stored `status` to EXPIRED so listing/reporting reflects it
without waiting for the next presentation lookup.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy.orm import Session

from app.models.db import ComplianceException


def to_dict(exc: ComplianceException) -> Dict[str, Any]:
    return {
        "id": exc.id,
        "tenant_id": exc.tenant_id,
        "device_id": exc.device_id,
        "control_id": exc.control_id,
        "reason": exc.reason,
        "created_by": exc.created_by,
        "approved_by": exc.approved_by,
        "approved_at": exc.approved_at.isoformat() if exc.approved_at else None,
        "rejected_by": exc.rejected_by,
        "rejected_at": exc.rejected_at.isoformat() if exc.rejected_at else None,
        "expires_at": exc.expires_at.isoformat() if exc.expires_at else None,
        "status": exc.status,
        "created_at": exc.created_at.isoformat() if exc.created_at else None,
    }


def is_active(exc: ComplianceException, now: Optional[datetime] = None) -> bool:
    now = now or datetime.utcnow()
    return exc.status == "APPROVED" and exc.expires_at > now


def create_exception(
    db: Session, tenant_id: str, device_id: str, control_id: str,
    reason: str, expires_at: datetime, created_by: Optional[str],
) -> ComplianceException:
    exc = ComplianceException(
        tenant_id=tenant_id, device_id=device_id, control_id=control_id,
        reason=reason, expires_at=expires_at, created_by=created_by, status="PENDING",
    )
    db.add(exc)
    db.commit()
    db.refresh(exc)
    return exc


def approve_exception(db: Session, exc: ComplianceException, approved_by: str) -> ComplianceException:
    if exc.status != "PENDING":
        raise ValueError(f"Exception {exc.id} is not pending (status={exc.status})")
    if exc.expires_at <= datetime.utcnow():
        raise ValueError("Cannot approve an exception whose expiry is already in the past")
    exc.status = "APPROVED"
    exc.approved_by = approved_by
    exc.approved_at = datetime.utcnow()
    exc.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(exc)
    return exc


def reject_exception(db: Session, exc: ComplianceException, rejected_by: str) -> ComplianceException:
    if exc.status not in ("PENDING", "APPROVED"):
        raise ValueError(f"Exception {exc.id} cannot be rejected from status={exc.status}")
    exc.status = "REJECTED"
    exc.rejected_by = rejected_by
    exc.rejected_at = datetime.utcnow()
    exc.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(exc)
    return exc


def sweep_expired(db: Session, tenant_id: str) -> int:
    """Flip any APPROVED exception whose expires_at has passed to EXPIRED.
    Returns the number changed. Safe/idempotent to call on every list/read
    of exceptions or findings -- never destructive, never touches PENDING
    or REJECTED rows."""
    now = datetime.utcnow()
    rows = (
        db.query(ComplianceException)
        .filter(
            ComplianceException.tenant_id == tenant_id,
            ComplianceException.status == "APPROVED",
            ComplianceException.expires_at <= now,
        )
        .all()
    )
    for row in rows:
        row.status = "EXPIRED"
        row.updated_at = now
    if rows:
        db.commit()
    return len(rows)


def active_exceptions_index(db: Session, tenant_id: str) -> Dict[tuple, ComplianceException]:
    """(device_id, control_id) -> active ComplianceException, for O(1)
    presentation-overlay lookup when rendering a finding list/evidence
    package/report."""
    sweep_expired(db, tenant_id)
    rows = (
        db.query(ComplianceException)
        .filter(ComplianceException.tenant_id == tenant_id, ComplianceException.status == "APPROVED")
        .all()
    )
    now = datetime.utcnow()
    return {(r.device_id, r.control_id): r for r in rows if r.expires_at > now}


def presentation_result(finding_result: str, device_id: str, control_id: str,
                         index: Dict[tuple, ComplianceException]) -> str:
    """The value to SHOW the user for a finding. `finding_result` (the
    underlying OPA PASS/FAIL/NOT_APPLICABLE) is never altered by this
    function's caller -- this return value is presentation-only."""
    if finding_result == "FAIL" and (device_id, control_id) in index:
        return "EXCEPTION_ACCEPTED"
    return finding_result