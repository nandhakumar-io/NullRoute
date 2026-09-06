from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.db import CommandMapping
from app.policies.controls import CONTROLS
from app.schemas import CommandMappingOut
from app.services import vector_search

from app.auth.dependencies import get_current_tenant, get_current_user

router = APIRouter(prefix="/api/knowledge-base", tags=["knowledge-base"], dependencies=[Depends(get_current_user)])


@router.get("/mappings", response_model=List[CommandMappingOut])
def learned_mappings(
    vendor: Optional[str] = None,
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    q = db.query(CommandMapping).filter(
        (CommandMapping.tenant_id == tenant_id) | (CommandMapping.tenant_id.is_(None))
    )
    if vendor:
        q = q.filter(CommandMapping.vendor == vendor)
    # Bounded + offset-paginated: this table grows with every unrecognized
    # command across the whole fleet, and the Training Center page used to
    # pull the entire thing unbounded on every load -- the single biggest
    # contributor to that page's slow load time.
    return q.order_by(CommandMapping.created_at.desc()).offset(offset).limit(limit).all()


@router.get("/similar-mappings")
def similar_mappings(
    text: str,
    vendor: Optional[str] = None,
    status: str = "approved",
    limit: int = Query(5, ge=1, le=25),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    """Training Center semantic search: CommandMapping -> embedding ->
    pgvector -> cosine similarity -> similar mappings (see
    services/vector_search.py for the real retrieval pipeline and its
    SQLite/no-embedder fallbacks)."""
    return {
        "query": text,
        "vendor": vendor,
        "status": status,
        "results": vector_search.find_similar_mappings(
            db, tenant_id=tenant_id, query_text=text, vendor=vendor, status=status, top_k=limit,
        ),
    }


@router.get("/controls")
def control_catalog(framework: Optional[str] = None):
    items = CONTROLS if not framework or framework.upper() == "ALL" else [c for c in CONTROLS if c.framework.upper() == framework.upper()]
    return [c.__dict__ for c in items]