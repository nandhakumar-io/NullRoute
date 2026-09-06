from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_tenant, get_current_user
from app.db import get_db
from app.services.config_search_service import search_configs

router = APIRouter(prefix="/api/config-search", tags=["config-search"], dependencies=[Depends(get_current_user)])


@router.get("")
def config_search(
    q: str = Query(..., min_length=1, max_length=300, description="Text/phrase to search for, e.g. 'telnet' or 'snmp community public'"),
    deep: bool = Query(True, description="Also grep each device's stored raw config, not just structured findings"),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    """Search every device's latest config + compliance findings for `q`,
    returning per-device hits split into compliant / non-compliant / not
    yet scanned. This is the auditor-specific search — "who has telnet on,
    and is that already flagged" — not a generic keyword index."""
    result = search_configs(db, tenant_id, q, deep=deep)
    return result.to_dict()