"""Phase 11 -- System Health.

GET /api/system/health   aggregated status of every core/optional service
                          dependency (PostgreSQL, NATS, OPA, Batfish, MinIO,
                          OpenBao, Keycloak, Fabric, Device Gateway, AI).

Any authenticated user can view this (it's an operational status page, not
sensitive data); no credential values or connection strings are ever
included in the response -- only reachability/latency/error text.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends

from app.auth.dependencies import get_current_user
from app.services.system_health_service import get_system_health

router = APIRouter(prefix="/api", tags=["system-health"], dependencies=[Depends(get_current_user)])


@router.get("/system/health")
async def system_health():
    return await get_system_health()