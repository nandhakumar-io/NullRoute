from typing import List, Optional

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.db import CommandMapping
from app.policies.controls import CONTROLS
from app.schemas import CommandMappingOut

from app.auth.dependencies import get_current_tenant, get_current_user

router = APIRouter(prefix="/api/knowledge-base", tags=["knowledge-base"], dependencies=[Depends(get_current_user)])


@router.get("/mappings", response_model=List[CommandMappingOut])
def learned_mappings(
    vendor: Optional[str] = None,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    q = db.query(CommandMapping).filter(
        (CommandMapping.tenant_id == tenant_id) | (CommandMapping.tenant_id.is_(None))
    )
    if vendor:
        q = q.filter(CommandMapping.vendor == vendor)
    return q.order_by(CommandMapping.created_at.desc()).all()


@router.get("/controls")
def control_catalog(framework: Optional[str] = None):
    items = CONTROLS if not framework or framework.upper() == "ALL" else [c for c in CONTROLS if c.framework.upper() == framework.upper()]
    return [c.__dict__ for c in items]