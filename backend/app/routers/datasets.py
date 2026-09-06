from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.db import get_db
from app.auth.rbac import Permission
from app.auth.dependencies import CurrentUser, get_current_tenant, require_permission, get_current_user
from app.services import dataset_service

router = APIRouter(prefix="/api/ai/datasets", tags=["ai-datasets"], dependencies=[Depends(get_current_user)])


@router.get("")
def list_datasets(
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    from app.models.db import DatasetVersion
    return (
        db.query(DatasetVersion)
        .filter((DatasetVersion.tenant_id == tenant_id) | (DatasetVersion.tenant_id.is_(None)))
        .order_by(DatasetVersion.created_at.desc())
        .all()
    )


@router.get("/{version_id}")
def get_dataset(
    version_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    dv = dataset_service.get_dataset(db, tenant_id, version_id)
    if not dv:
        raise HTTPException(404, "Dataset not found")
    return dv


@router.post("")
def create_dataset_version(
    version_label: str,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_permission(Permission.APPROVE_AI_MAPPING)),
):
    dv = dataset_service.create_dataset_version(db, tenant_id, user, version_label)
    return dv
