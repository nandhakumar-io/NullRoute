from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.db import AuditLog, CommandMapping
from app.schemas import CommandMappingOut, MappingReviewIn

from app.auth.dependencies import get_current_tenant, get_current_user, require_role

router = APIRouter(prefix="/api/training", tags=["training"], dependencies=[Depends(get_current_user)])


def _tenant_scoped_mappings_query(db: Session, tenant_id: str):
    return (
        db.query(CommandMapping)
        .filter((CommandMapping.tenant_id == tenant_id) | (CommandMapping.tenant_id.is_(None)))
    )


@router.get("/pending", response_model=List[CommandMappingOut])
def list_pending(db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    return (
        _tenant_scoped_mappings_query(db, tenant_id)
        .filter(CommandMapping.status == "pending")
        .order_by(CommandMapping.created_at.desc())
        .all()
    )


@router.get("/approved", response_model=List[CommandMappingOut])
def list_approved(db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    return (
        _tenant_scoped_mappings_query(db, tenant_id)
        .filter(CommandMapping.status == "approved")
        .order_by(CommandMapping.created_at.desc())
        .all()
    )


@router.post("/{mapping_id}/review", response_model=CommandMappingOut)
def review_mapping(
    mapping_id: str,
    payload: MappingReviewIn,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    _user=Depends(require_role("admin", "security_analyst")),
):
    mapping = (
        _tenant_scoped_mappings_query(db, tenant_id)
        .filter(CommandMapping.id == mapping_id)
        .first()
    )
    if not mapping:
        raise HTTPException(404, "Mapping not found")

    if payload.action == "approve" or payload.action == "correct":
        mapping.status = "approved"
        if payload.normalized_parameter:
            mapping.normalized_parameter = payload.normalized_parameter
        mapping.confidence = max(mapping.confidence, 0.95)  # human-confirmed
    elif payload.action == "reject":
        mapping.status = "rejected"
    else:
        raise HTTPException(400, "action must be 'approve', 'correct', or 'reject'")

    from datetime import datetime
    mapping.reviewed_by = payload.reviewer
    mapping.reviewed_at = datetime.utcnow()
    db.add(AuditLog(actor=payload.reviewer, action=f"training.{payload.action}",
                     resource=mapping_id, details={"normalized_parameter": mapping.normalized_parameter}))
    db.commit()
    db.refresh(mapping)
    return mapping
