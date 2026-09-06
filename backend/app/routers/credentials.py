"""Device credential reference API (Phase 6).

CRITICAL: no endpoint in this router ever returns secret material. Request
bodies containing secrets (POST/PATCH) are written straight through to
OpenBao and dropped; only the non-secret `credential_ref` row is ever
returned to the client. Collection requires operator/admin (RULE ordering
matches Phase 4's "device configuration collection requires operator/admin").
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth.dependencies import (CurrentUser, get_current_tenant, get_current_user,
                                    require_permission, require_role)
from app.db import get_db
from app.models.db import Device, DeviceCredentialRef
from app.services import audit_service, openbao_service
from app.auth.rbac import Permission

router = APIRouter(prefix="/api/devices", tags=["credentials"], dependencies=[Depends(get_current_user)])

ALLOWED_CREDENTIAL_TYPES = {"ssh_password", "ssh_key", "netconf", "restconf_token", "snmp_community"}


class CredentialRefOut(BaseModel):
    id: str
    device_id: str
    credential_type: str
    credential_ref: str
    created_at: datetime
    updated_at: datetime
    rotated_at: Optional[datetime]

    class Config:
        from_attributes = True


class CredentialCreate(BaseModel):
    credential_type: str
    secret: Dict[str, Any]  # e.g. {"username": "...", "password": "..."} -- never persisted to Postgres


class CredentialRotate(BaseModel):
    secret: Dict[str, Any]


def _get_device_or_404(db: Session, device_id: str, tenant_id: str) -> Device:
    device = db.query(Device).filter(Device.id == device_id, Device.tenant_id == tenant_id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    return device


@router.get("/{device_id}/credentials", response_model=List[CredentialRefOut])
def list_credential_refs(
    device_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_role("admin", "operator")),
):
    _get_device_or_404(db, device_id, tenant_id)
    return (
        db.query(DeviceCredentialRef)
        .filter(DeviceCredentialRef.device_id == device_id, DeviceCredentialRef.tenant_id == tenant_id)
        .order_by(DeviceCredentialRef.created_at.desc())
        .all()
    )


@router.post("/{device_id}/credentials", response_model=CredentialRefOut)
def create_credential_ref(
    device_id: str,
    payload: CredentialCreate,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_permission(Permission.MANAGE_CREDENTIALS)),
):
    _get_device_or_404(db, device_id, tenant_id)
    if payload.credential_type not in ALLOWED_CREDENTIAL_TYPES:
        raise HTTPException(422, f"credential_type must be one of {sorted(ALLOWED_CREDENTIAL_TYPES)}")

    ref = openbao_service.generate_credential_ref()
    try:
        openbao_service.store_device_credentials(tenant_id, ref, payload.credential_type, payload.secret)
    except openbao_service.OpenBaoError as e:
        audit_service.record_from_user(
            db, user, action="credential.create", request=request, result="FAILURE",
            object_type="device_credential_ref", object_id=device_id,
            new_value={"credential_type": payload.credential_type, "error": str(e)},
        )
        raise HTTPException(502, f"OpenBao store failed: {e}") from e

    row = DeviceCredentialRef(
        tenant_id=tenant_id,
        device_id=device_id,
        credential_ref=ref,
        credential_type=payload.credential_type,
        created_by=user.username,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    # Never log the secret material itself -- only the non-secret reference metadata.
    audit_service.record_from_user(
        db, user, action="credential.create", request=request, result="SUCCESS",
        object_type="device_credential_ref", object_id=row.id,
        new_value={"device_id": device_id, "credential_type": payload.credential_type, "credential_ref": ref},
    )
    return row


@router.post("/{device_id}/credentials/{ref_id}/rotate", response_model=CredentialRefOut)
def rotate_credential_ref(
    device_id: str,
    ref_id: str,
    payload: CredentialRotate,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_permission(Permission.MANAGE_CREDENTIALS)),
):
    _get_device_or_404(db, device_id, tenant_id)
    row = (
        db.query(DeviceCredentialRef)
        .filter(
            DeviceCredentialRef.id == ref_id,
            DeviceCredentialRef.device_id == device_id,
            DeviceCredentialRef.tenant_id == tenant_id,
        )
        .first()
    )
    if not row:
        raise HTTPException(404, "Credential reference not found")

    prior_rotated_at = row.rotated_at.isoformat() if row.rotated_at else None
    try:
        openbao_service.rotate_device_credentials(tenant_id, row.credential_ref, row.credential_type, payload.secret)
    except openbao_service.OpenBaoError as e:
        audit_service.record_from_user(
            db, user, action="credential.rotate", request=request, result="FAILURE",
            object_type="device_credential_ref", object_id=ref_id,
            old_value={"rotated_at": prior_rotated_at}, new_value={"error": str(e)},
        )
        raise HTTPException(502, f"OpenBao rotate failed: {e}") from e

    row.rotated_at = datetime.utcnow()
    db.commit()
    db.refresh(row)
    audit_service.record_from_user(
        db, user, action="credential.rotate", request=request, result="SUCCESS",
        object_type="device_credential_ref", object_id=ref_id,
        old_value={"rotated_at": prior_rotated_at}, new_value={"rotated_at": row.rotated_at.isoformat()},
    )
    return row


@router.delete("/{device_id}/credentials/{ref_id}")
def delete_credential_ref(
    device_id: str,
    ref_id: str,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_role("admin", "TENANT_ADMIN", "SUPER_ADMIN")),
):
    _get_device_or_404(db, device_id, tenant_id)
    row = (
        db.query(DeviceCredentialRef)
        .filter(
            DeviceCredentialRef.id == ref_id,
            DeviceCredentialRef.device_id == device_id,
            DeviceCredentialRef.tenant_id == tenant_id,
        )
        .first()
    )
    if not row:
        raise HTTPException(404, "Credential reference not found")

    try:
        openbao_service.delete_device_credentials(tenant_id, row.credential_ref)
    except openbao_service.OpenBaoError as e:
        audit_service.record_from_user(
            db, user, action="credential.delete", request=request, result="FAILURE",
            object_type="device_credential_ref", object_id=ref_id,
            old_value={"device_id": device_id, "credential_type": row.credential_type},
            new_value={"error": str(e)},
        )
        raise HTTPException(502, f"OpenBao delete failed: {e}") from e

    db.delete(row)
    db.commit()
    audit_service.record_from_user(
        db, user, action="credential.delete", request=request, result="SUCCESS",
        object_type="device_credential_ref", object_id=ref_id,
        old_value={"device_id": device_id, "credential_type": row.credential_type},
    )
    return {"status": "deleted", "id": ref_id}