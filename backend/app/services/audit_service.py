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
            resource=object_id,
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
            resource=object_id,
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