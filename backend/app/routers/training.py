from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.db import AuditLog, CommandMapping
from app.schemas import CommandMappingOut, MappingReviewIn
from app.services import audit_service
from app.rbac import Permission

from app.auth.dependencies import (CurrentUser, get_current_tenant, get_current_user,
                                    require_permission, require_role)

router = APIRouter(prefix="/api/training", tags=["training"], dependencies=[Depends(get_current_user)])


@router.get("/pending", response_model=List[CommandMappingOut])
def list_pending(
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    return (
        db.query(CommandMapping)
        .filter(CommandMapping.status == "pending")
        .filter(
            (CommandMapping.tenant_id == tenant_id) | (CommandMapping.tenant_id.is_(None))
        )
        .order_by(CommandMapping.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.get("/approved", response_model=List[CommandMappingOut])
def list_approved(
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    return (
        db.query(CommandMapping)
        .filter(CommandMapping.status == "approved")
        .filter(
            (CommandMapping.tenant_id == tenant_id) | (CommandMapping.tenant_id.is_(None))
        )
        .order_by(CommandMapping.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.post("/{mapping_id}/review", response_model=CommandMappingOut)
def review_mapping(
    mapping_id: str,
    payload: MappingReviewIn,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_permission(Permission.APPROVE_AI_MAPPING)),
):
    mapping = (
        db.query(CommandMapping)
        .filter(CommandMapping.id == mapping_id)
        .filter(
            (CommandMapping.tenant_id == tenant_id) | (CommandMapping.tenant_id.is_(None))
        )
        .first()
    )
    if not mapping:
        raise HTTPException(404, "Mapping not found")

    prior = {"status": mapping.status, "normalized_parameter": mapping.normalized_parameter,
             "confidence": mapping.confidence}

    if payload.action == "approve":
        mapping.status = "approved"
        if payload.normalized_parameter:
            mapping.normalized_parameter = payload.normalized_parameter
        mapping.confidence = max(mapping.confidence, 0.95)  # human-confirmed
    elif payload.action == "reject":
        mapping.status = "rejected"
    else:
        raise HTTPException(400, "action must be 'approve' or 'reject'")

    from datetime import datetime
    mapping.reviewed_by = payload.reviewer
    mapping.reviewed_at = datetime.utcnow()
    db.commit()
    db.refresh(mapping)

    audit_service.record_from_user(
        db, user, action=f"training.mapping.{payload.action}", request=request, result="SUCCESS",
        object_type="command_mapping", object_id=mapping_id,
        old_value=prior,
        new_value={"status": mapping.status, "normalized_parameter": mapping.normalized_parameter,
                   "confidence": mapping.confidence, "reviewed_by": mapping.reviewed_by},
    )
    return mapping