from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.db import get_db
from app.auth.rbac import Permission
from app.auth.dependencies import CurrentUser, get_current_tenant, require_permission, get_current_user
from app.serialization import orm_dict, orm_list
from app.services import dataset_service

router = APIRouter(prefix="/api/ai/datasets", tags=["ai-datasets"], dependencies=[Depends(get_current_user)])


class DraftCreate(BaseModel):
    version_label: str


class ExampleIds(BaseModel):
    example_ids: List[str]


class CloneRequest(BaseModel):
    new_label: str


@router.get("")
def list_datasets(
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    from app.models.db import DatasetVersion
    return orm_list(
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
    # Looked up by primary-key UUID (matching how training jobs reference a
    # dataset), with a fallback to the human-readable label for old links.
    dv = dataset_service.get_dataset(db, tenant_id, version_id)
    if not dv:
        raise HTTPException(404, "Dataset not found")
    return orm_dict(dv)


@router.get("/{version_id}/examples")
def get_dataset_examples(
    version_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    try:
        return orm_list(dataset_service.list_draft_examples(db, tenant_id, version_id))
    except ValueError as e:
        raise HTTPException(404, str(e))


@router.post("")
def create_dataset_version(
    version_label: str,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_permission(Permission.APPROVE_AI_MAPPING)),
):
    """One-shot: snapshot every currently-VALIDATED example into an
    immediately-finalized dataset (back-compat behavior; empty is allowed).
    Prefer POST .../draft + .../examples + .../finalize for the editable
    flow, which refuses to finalize an empty dataset."""
    try:
        return orm_dict(dataset_service.create_dataset_version(db, tenant_id, user, version_label))
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/draft")
def create_dataset_draft(
    payload: DraftCreate,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_permission(Permission.APPROVE_AI_MAPPING)),
):
    """Create a new empty DRAFT dataset. Add examples with POST .../examples,
    then POST .../finalize to freeze it before it can be used to train."""
    try:
        return orm_dict(dataset_service.create_draft(db, tenant_id, user, payload.version_label))
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/{version_id}/examples")
def add_dataset_examples(
    version_id: str,
    payload: ExampleIds,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_permission(Permission.APPROVE_AI_MAPPING)),
):
    try:
        return orm_dict(dataset_service.add_examples(db, tenant_id, version_id, payload.example_ids, user))
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.delete("/{version_id}/examples/{example_id}")
def remove_dataset_example(
    version_id: str,
    example_id: str,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_permission(Permission.APPROVE_AI_MAPPING)),
):
    try:
        return orm_dict(dataset_service.remove_example(db, tenant_id, version_id, example_id, user))
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.delete("/{version_id}")
def delete_dataset_draft(
    version_id: str,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_permission(Permission.APPROVE_AI_MAPPING)),
):
    try:
        dataset_service.delete_draft(db, tenant_id, version_id, user)
        return {"deleted": True}
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/{version_id}/finalize")
def finalize_dataset(
    version_id: str,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_permission(Permission.APPROVE_AI_MAPPING)),
):
    try:
        return orm_dict(dataset_service.finalize(db, tenant_id, version_id, user))
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/{version_id}/clone")
def clone_dataset(
    version_id: str,
    payload: CloneRequest,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(require_permission(Permission.APPROVE_AI_MAPPING)),
):
    try:
        return orm_dict(dataset_service.clone(db, tenant_id, version_id, user, payload.new_label))
    except ValueError as e:
        raise HTTPException(400, str(e))