from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.db import CommandMapping
from app.schemas import CommandMappingOut, MappingReviewIn
from app.services import hitl_service

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
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user=Depends(require_role("admin", "security_analyst")),
):
    """Approve/correct/reject a pending command mapping.

    Delegates to `hitl_service`, which is the single place this actually
    persists: it updates the `CommandMapping` row *and* writes the
    corresponding `TrainingExample` (redacted raw text, normalized facts,
    human_action, correction_reason) that Loop 2 dataset building reads
    from, generates the pgvector embedding, and records the audit log.
    Previously this endpoint only flipped `CommandMapping.status` and
    tried to hand-edit a JSON file at a developer's hardcoded local path
    — it never created a TrainingExample at all, so nothing downstream
    (dataset snapshots, model retraining) ever saw these reviews.
    """
    mapping = (
        _tenant_scoped_mappings_query(db, tenant_id)
        .filter(CommandMapping.id == mapping_id)
        .first()
    )
    if not mapping:
        raise HTTPException(404, "Mapping not found")

    normalized_facts = dict(payload.normalized_facts or {})
    if payload.normalized_parameter and "facts" not in normalized_facts:
        normalized_facts["facts"] = [{"parameter": payload.normalized_parameter}]

    if payload.action == "approve":
        mapping = hitl_service.approve_mapping(
            db, mapping, normalized_facts, payload.correction_reason, user, request
        )
    elif payload.action == "correct":
        mapping = hitl_service.correct_mapping(
            db, mapping, normalized_facts, payload.correction_reason, user, request
        )
    elif payload.action == "reject":
        mapping = hitl_service.reject_mapping(
            db, mapping, payload.correction_reason, user, request
        )
    else:
        raise HTTPException(400, "action must be 'approve', 'correct', or 'reject'")

    return mapping