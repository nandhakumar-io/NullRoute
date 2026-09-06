from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.db import get_db
from app.auth.rbac import Permission
from app.auth.dependencies import CurrentUser, get_current_tenant, require_permission, get_current_user
from app.services import training_service

router = APIRouter(prefix="/api/ai/training/jobs", tags=["ai-jobs"], dependencies=[Depends(get_current_user)])


class JobCreate(BaseModel):
    dataset_version_id: str
    base_model_version: Optional[str] = None


@router.get("")
def list_training_jobs(
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    from app.models.db import TrainingJob
    return (
        db.query(TrainingJob)
        .filter((TrainingJob.tenant_id == tenant_id) | (TrainingJob.tenant_id.is_(None)))
        .order_by(TrainingJob.created_at.desc() if hasattr(TrainingJob, "created_at") else TrainingJob.started_at.desc())
        .all()
    )


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
        return job
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/{job_id}/run")
def run_training_job_sync(
    job_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_permission(Permission.APPROVE_AI_MAPPING)),
):
    # For testing, we mock running it synchronously
    training_service.run_training_job(db, job_id)
    from app.models.db import TrainingJob
    return db.query(TrainingJob).filter(TrainingJob.id == job_id).first()
