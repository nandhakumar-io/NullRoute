from typing import List, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.db import CommandMapping, TrainingExample
from app.schemas import CommandMappingOut, MappingReviewIn, TrainingExampleOut
from app.services import hitl_service, audit_service

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


# ── Dataset-level review gate ────────────────────────────────────────────
#
# `review_mapping` above is the *first* human gate: it turns an unknown
# command into a CommandMapping decision (approve/correct/reject) and, via
# hitl_service, writes a TrainingExample row for it (validation_status
# defaults to PENDING — see app/models/db.py). That TrainingExample is raw
# HITL signal, not yet a curated training set.
#
# dataset_service.create_dataset_version() only ever snapshots examples
# whose validation_status == "VALIDATED" (app/services/dataset_service.py).
# Nothing previously ever set that status, so every "unknown corrected
# command" sat in TrainingExample forever and every dataset compiled empty.
# These endpoints are the missing second gate: a reviewer looks at the
# accumulated PENDING examples (the corrected/approved/rejected unknown
# commands) and explicitly validates (or excludes) each one before it can
# be pulled into a dataset and, from there, a training job.


def _tenant_scoped_examples_query(db: Session, tenant_id: str):
    return db.query(TrainingExample).filter(
        (TrainingExample.tenant_id == tenant_id) | (TrainingExample.tenant_id.is_(None))
    )


@router.get("/settings")
def training_settings():
    """Read-only HITL settings the UI needs (e.g. whether an admin's own
    approve/correct also counts as the second validation gate)."""
    return {"admin_auto_validate": hitl_service._admin_auto_validate_enabled()}


@router.get("/examples", response_model=List[TrainingExampleOut])
def list_training_examples(
    status: str = "PENDING",
    human_action: Optional[str] = None,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    """List HITL training examples awaiting (or already given) dataset-level
    review. `status` is validation_status (PENDING/VALIDATED/EXCLUDED,
    default PENDING — the review queue). `human_action` optionally narrows
    to APPROVED/CORRECTED/REJECTED (e.g. CORRECTED to see just the unknown
    commands a reviewer fixed)."""
    q = _tenant_scoped_examples_query(db, tenant_id)
    if status.upper() != "ALL":
        q = q.filter(TrainingExample.validation_status == status.upper())
    if human_action:
        q = q.filter(TrainingExample.human_action == human_action.upper())
    return q.order_by(TrainingExample.created_at.desc()).all()


@router.post("/examples/{example_id}/validate", response_model=TrainingExampleOut)
def validate_training_example(
    example_id: str,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user=Depends(require_role("admin", "security_analyst")),
):
    """Second-gate approval: mark a TrainingExample fit to be included in
    the next dataset snapshot."""
    ex = _tenant_scoped_examples_query(db, tenant_id).filter(TrainingExample.id == example_id).first()
    if not ex:
        raise HTTPException(404, "Training example not found")
    if ex.human_action == "REJECTED":
        raise HTTPException(400, "Cannot validate a REJECTED example — it has no usable facts")
    prior_status = ex.validation_status
    ex.validation_status = "VALIDATED"
    db.commit()
    db.refresh(ex)
    audit_service.record_from_user(
        db, user, action="training.example.validate", request=request, result="SUCCESS",
        object_type="training_example", object_id=ex.id,
        old_value={"validation_status": prior_status},
        new_value={"validation_status": ex.validation_status},
    )
    return ex


@router.post("/examples/{example_id}/exclude", response_model=TrainingExampleOut)
def exclude_training_example(
    example_id: str,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user=Depends(require_role("admin", "security_analyst")),
):
    """Second-gate rejection: keep a TrainingExample out of every future
    dataset snapshot (e.g. it's a duplicate, low-quality, or a correction
    the reviewer no longer trusts)."""
    ex = _tenant_scoped_examples_query(db, tenant_id).filter(TrainingExample.id == example_id).first()
    if not ex:
        raise HTTPException(404, "Training example not found")
    prior_status = ex.validation_status
    ex.validation_status = "EXCLUDED"
    db.commit()
    db.refresh(ex)
    audit_service.record_from_user(
        db, user, action="training.example.exclude", request=request, result="SUCCESS",
        object_type="training_example", object_id=ex.id,
        old_value={"validation_status": prior_status},
        new_value={"validation_status": ex.validation_status},
    )
    return ex


@router.post("/examples/bulk-validate")
def bulk_validate_training_examples(
    request: Request,
    example_ids: List[str] = Body(..., embed=False),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user=Depends(require_role("admin", "security_analyst")),
):
    """Validate several TrainingExamples in one call (e.g. a batch of
    approved-not-corrected examples a reviewer trusts wholesale)."""
    examples = (
        _tenant_scoped_examples_query(db, tenant_id)
        .filter(TrainingExample.id.in_(example_ids))
        .all()
    )
    validated_ids = []
    skipped_rejected_ids = []
    for ex in examples:
        if ex.human_action == "REJECTED":
            skipped_rejected_ids.append(ex.id)
            continue
        ex.validation_status = "VALIDATED"
        validated_ids.append(ex.id)
    db.commit()
    audit_service.record_from_user(
        db, user, action="training.example.bulk_validate", request=request, result="SUCCESS",
        object_type="training_example", object_id=None,
        old_value=None,
        new_value={"validated_ids": validated_ids, "skipped_rejected_ids": skipped_rejected_ids},
    )
    return {
        "validated_count": len(validated_ids),
        "validated_ids": validated_ids,
        "skipped_rejected_ids": skipped_rejected_ids,
    }