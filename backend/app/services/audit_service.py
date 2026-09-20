"""Section 12: 'Audit everything important'.

Every audit event captures: who, tenant, what, when, source IP, object,
old value, new value, result. Call `record_from_user` from any router that
mutates state or exposes sensitive data (config uploads, scans, compliance
changes, AI mapping approval, remediation approval, user/role changes,
credential operations, report downloads, ...). Writing the audit row never
raises — a logging failure must never block or mask the underlying
request's own success/failure.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import Request
from sqlalchemy.orm import Session

from app.models.db import AuditLog

logger = logging.getLogger("audit")


def get_client_ip(request: Optional[Request]) -> Optional[str]:
    if request is None:
        return None
    # Respect a reverse proxy's X-Forwarded-For (first hop = original
    # client) when present, since this app is deployed behind one in the
    # docker-compose topology; fall back to the direct peer address.
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return None


def record_from_user(
    db: Session,
    user: Any,
    action: str,
    request: Optional[Request] = None,
    *,
    result: str = "SUCCESS",
    object_type: Optional[str] = None,
    object_id: Optional[str] = None,
    old_value: Optional[dict] = None,
    new_value: Optional[dict] = None,
) -> None:
    """Write one audit_log row for an authenticated action.

    `user` is a `CurrentUser` (app.auth.dependencies) — typed loosely here
    to avoid a circular import between auth and services.
    """
    try:
        row = AuditLog(
            tenant_id=getattr(user, "tenant_id", None),
            actor=getattr(user, "username", None),
            action=action,
            resource=object_id or object_type or action,
            details={"object_type": object_type} if object_type else None,
            user_id=getattr(user, "subject", None),
            username=getattr(user, "username", None),
            source_ip=get_client_ip(request),
            object_type=object_type,
            object_id=object_id,
            old_value=old_value,
            new_value=new_value,
            result=result,
        )
        db.add(row)
        db.commit()
    except Exception:
        logger.exception("Failed to write audit log for action=%s object=%s/%s", action, object_type, object_id)
        try:
            db.rollback()
        except Exception:
            pass


def record_system(
    db: Session,
    action: str,
    *,
    tenant_id: Optional[str] = None,
    result: str = "SUCCESS",
    object_type: Optional[str] = None,
    object_id: Optional[str] = None,
    old_value: Optional[dict] = None,
    new_value: Optional[dict] = None,
) -> None:
    """Same as record_from_user, for actions with no authenticated actor
    (e.g. scheduled/worker-triggered scans)."""
    try:
        db.add(AuditLog(
            tenant_id=tenant_id,
            actor="system",
            action=action,
            resource=object_id or object_type or action,
            details={"object_type": object_type} if object_type else None,
            user_id=None,
            username="system",
            source_ip=None,
            object_type=object_type,
            object_id=object_id,
            old_value=old_value,
            new_value=new_value,
            result=result,
        ))
        db.commit()
    except Exception:
        logger.exception("Failed to write system audit log for action=%s", action)
        try:
            db.rollback()
        except Exception:
            pass


# Values callers may legitimately pass in `result` (see the AuditLog.result
# docstring: "SUCCESS / FAILURE / DENIED"). Anything outside this set (a
# severity like "critical", a workflow state like "Pending Approval", a
# count like "3 approved", ...) is a caller bug -- normalize it here rather
# than writing an unrecognized value that the Audit Log UI/filter can't
# classify as success or failure.
_VALID_RESULTS = {"SUCCESS", "FAILURE", "DENIED"}

# Result values (or prefixes) that indicate the action genuinely didn't
# succeed, even though the caller passed something other than "FAILURE"
# verbatim.
_FAILURE_HINTS = ("fail", "error", "denied", "reject", "block", "critical", "high")


def _normalize_result(result: Optional[str]) -> str:
    if not result:
        return "SUCCESS"
    upper = result.strip().upper()
    if upper in _VALID_RESULTS:
        return upper
    lowered = result.strip().lower()
    if any(hint in lowered for hint in _FAILURE_HINTS):
        return "FAILURE"
    return "SUCCESS"


def record_event(
    db: Session,
    actor: str,
    action: str,
    *,
    result: str = "SUCCESS",
    device_hostname: Optional[str] = None,
    detail: Optional[str] = None,
    change_request_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> None:
    """Lighter-weight event log used by services that don't have a full
    `CurrentUser`/`Request` on hand (e.g. app.services.advanced_drift_service,
    called from both an API route and a Celery task) but still need to
    record who/what/when/result. Distinct from `record_from_user` in that
    `actor` is just a string (a username, an email, or "system") rather
    than a full user object, and `detail` is a free-text summary rather
    than structured old/new value dicts.

    This function previously did not exist at all -- every call site in
    advanced_drift_service.py (`audit_service.record_event(...)`) raised
    `AttributeError: module 'app.services.audit_service' has no attribute
    'record_event'` the moment it ran, so no drift-detection event, human
    or automated, was ever actually written to the audit trail. It also
    normalizes whatever ad-hoc string those call sites pass as `result`
    (e.g. a drift severity like "critical", or "Pending Approval") into
    SUCCESS/FAILURE so the Audit Log page's result filter and coloring
    stay meaningful instead of everything falling through to "FAILURE" by
    convention or showing an unrecognized string verbatim.
    """
    try:
        db.add(AuditLog(
            tenant_id=tenant_id,
            actor=actor,
            action=action,
            resource=device_hostname or change_request_id or action,
            details={"detail": detail, "raw_result": result} if detail else {"raw_result": result},
            user_id=None,
            username=actor,
            source_ip=None,
            object_type="device" if device_hostname else ("change_request" if change_request_id else None),
            object_id=change_request_id or device_hostname,
            old_value=None,
            new_value={"detail": detail} if detail else None,
            result=_normalize_result(result),
        ))
        db.commit()
    except Exception:
        logger.exception("Failed to write audit event for action=%s actor=%s", action, actor)
        try:
            db.rollback()
        except Exception:
            pass