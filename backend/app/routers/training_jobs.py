"""Training jobs (Loop 2).

Jobs are created QUEUED and executed by the training worker
(app/workers/training_worker.py), never inside an HTTP request. The only
exception is the explicit dev/test escape hatch POST /{id}/run, which is
disabled unless TRAINING_ALLOW_SYNC_RUN=true.
"""
import os
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth.dependencies import CurrentUser, get_current_tenant, get_current_user, require_permission
from app.auth.rbac import Permission
from app.db import get_db
from app.models.db import TrainingJob
from app.serialization import orm_dict, orm_list
from app.services import audit_service, training_service

router = APIRouter(prefix="/api/ai/training/jobs", tags=["ai-jobs"], dependencies=[Depends(get_current_user)])


class JobCreate(BaseModel):
    dataset_version_id: str
    base_model_version: Optional[str] = None


def _scoped(db: Session, tenant_id: str):
    return db.query(TrainingJob).filter(
        (TrainingJob.tenant_id == tenant_id) | (TrainingJob.tenant_id.is_(None))
    )


@router.get("")
def list_training_jobs(
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    return orm_list(_scoped(db, tenant_id).order_by(TrainingJob.created_at.desc()).all())


@router.get("/{job_id}")
def get_training_job(
    job_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    job = _scoped(db, tenant_id).filter(TrainingJob.id == job_id).first()
    if not job:
        raise HTTPException(404, "Training job not found")
    return orm_dict(job)


@router.post("")
def create_training_job(
    payload: JobCreate,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_permission(Permission.APPROVE_AI_MAPPING)),
):
    try:
        job = training_service.create_training_job(
            db, tenant_id, payload.dataset_version_id, payload.base_model_version, user
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit_service.record_from_user(
        db, user, action="training.job.create", request=request, result="SUCCESS",
        object_type="training_job", object_id=job.id,
        old_value=None, new_value={"dataset_version_id": payload.dataset_version_id},
    )
    return orm_dict(job)


@router.post("/{job_id}/retry")
def retry_training_job(
    job_id: str,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_permission(Permission.APPROVE_AI_MAPPING)),
):
    try:
        job = training_service.requeue_job(db, job_id, tenant_id)
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit_service.record_from_user(
        db, user, action="training.job.retry", request=request, result="SUCCESS",
        object_type="training_job", object_id=job.id, old_value=None, new_value={"status": job.status},
    )
    return orm_dict(job)


@router.post("/{job_id}/cancel")
def cancel_training_job(
    job_id: str,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_permission(Permission.APPROVE_AI_MAPPING)),
):
    try:
        job = training_service.cancel_job(db, job_id, tenant_id)
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit_service.record_from_user(
        db, user, action="training.job.cancel", request=request, result="SUCCESS",
        object_type="training_job", object_id=job.id, old_value=None, new_value={"status": job.status},
    )
    return orm_dict(job)


@router.post("/{job_id}/run")
def run_training_job_sync(
    job_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_permission(Permission.APPROVE_AI_MAPPING)),
):
    """Dev/test only: run a QUEUED job inline. Blocks the request for the
    whole fine-tune, so it is off unless TRAINING_ALLOW_SYNC_RUN=true --
    production runs go through the training worker."""
    if os.getenv("TRAINING_ALLOW_SYNC_RUN", "false").strip().lower() not in ("1", "true", "yes", "on"):
        raise HTTPException(
            409,
            "Synchronous runs are disabled; the training worker picks up QUEUED jobs automatically "
            "(set TRAINING_ALLOW_SYNC_RUN=true for local dev).",
        )
    job = _scoped(db, tenant_id).filter(TrainingJob.id == job_id).first()
    if not job:
        raise HTTPException(404, "Training job not found")
    training_service.run_training_job(db, job_id)
    db.refresh(job)
    return orm_dict(job)
