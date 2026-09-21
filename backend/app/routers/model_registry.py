from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.db import get_db
from app.auth.rbac import Permission
from app.auth.dependencies import CurrentUser, get_current_tenant, require_permission, get_current_user
from app.models.db import ModelRegistryEntry
from app.services import model_registry_service

router = APIRouter(prefix="/api/ai/registry", tags=["ai-model-registry"], dependencies=[Depends(get_current_user)])


def _out(m: ModelRegistryEntry) -> dict:
    """Plain-dict form (ORM objects don't JSON-serialize reliably). Coverage
    of the 13 known intents is surfaced for the Models tab; promotion is
    intentionally NOT gated on it."""
    metrics = m.metrics or {}
    return {
        "id": m.id,
        "model_name": m.model_name,
        "model_type": m.model_type,
        "dataset_version": m.dataset_version,
        "base_model_version": m.base_model_version,
        "artifact_path": m.artifact_path,
        "model_hash": m.model_hash,
        "metrics": metrics,
        "training_timestamp": m.training_timestamp.isoformat() if m.training_timestamp else None,
        "status": m.status,
        "created_by": m.created_by,
        "approved_by": m.approved_by,
        "approved_at": m.approved_at.isoformat() if m.approved_at else None,
        "training_job_id": m.training_job_id,
        "intent_coverage": metrics.get("intent_coverage"),
        "known_intents_covered": metrics.get("known_intents_covered"),
        "known_intents_total": metrics.get("known_intents_total"),
        "known_intents_missing": metrics.get("known_intents_missing"),
    }


class RollbackRequest(BaseModel):
    target_model_id: str


@router.get("/models")
def list_models(
    model_type: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    q = db.query(ModelRegistryEntry)
    if model_type:
        q = q.filter(ModelRegistryEntry.model_type == model_type)
    if status:
        q = q.filter(ModelRegistryEntry.status == status)
    return [_out(m) for m in q.order_by(ModelRegistryEntry.training_timestamp.desc()).all()]


@router.get("/models/{model_id}")
def get_model(
    model_id: str,
    db: Session = Depends(get_db),
):
    model = db.query(ModelRegistryEntry).filter(ModelRegistryEntry.id == model_id).first()
    if not model:
        raise HTTPException(404, "Model not found")
    return _out(model)


@router.post("/models/{model_id}/approve")
def approve_model(
    model_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission(Permission.APPROVE_AI_MAPPING)),
):
    try:
        return _out(model_registry_service.approve_candidate(db, model_id, user, request))
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/models/{model_id}/reject")
def reject_model(
    model_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission(Permission.APPROVE_AI_MAPPING)),
):
    model = db.query(ModelRegistryEntry).filter(ModelRegistryEntry.id == model_id).first()
    if not model:
        raise HTTPException(404, "Model not found")
    if model.status != "CANDIDATE":
        raise HTTPException(400, f"Model status is {model.status}, expected CANDIDATE to reject")
    model.status = "REJECTED"
    db.commit()
    db.refresh(model)
    return _out(model)


@router.post("/models/{model_id}/promote")
def promote_model(
    model_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission(Permission.APPROVE_AI_MAPPING)),
):
    try:
        return _out(model_registry_service.promote_to_production(db, model_id, user, request))
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/models/rollback")
def rollback_model(
    payload: RollbackRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission(Permission.APPROVE_AI_MAPPING)),
):
    # Note: the target is the ARCHIVED/APPROVED model to roll back TO, never
    # the current PRODUCTION row itself (that was the "wrong rollback button"
    # bug: the UI must not offer Rollback on a PRODUCTION entry).
    target = db.query(ModelRegistryEntry).filter(ModelRegistryEntry.id == payload.target_model_id).first()
    if target and target.status == "PRODUCTION":
        raise HTTPException(400, "Cannot roll back to a model that is already PRODUCTION")
    try:
        return _out(model_registry_service.rollback(db, payload.target_model_id, user, request))
    except ValueError as e:
        raise HTTPException(400, str(e))