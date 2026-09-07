"""
FastAPI dependencies for Keycloak-authenticated requests.

    get_current_user()   -> CurrentUser (validated identity + roles + tenant)
    require_role(*roles) -> dependency factory; 403s if none of the user's
                             roles match
    get_current_tenant() -> tenant_id, taken ONLY from the validated token
                             claims — a tenant_id supplied by the browser
                             (query param, body field, header) is NEVER
                             trusted (Phase 5 rule).

Roles: admin, security_analyst, operator, auditor, viewer.

Demo/dev mode: when AUTH_ENABLED=false (explicit opt-in, see auth/jwt.py),
requests are treated as an implicit admin user scoped to the SIH-Demo
tenant, so the existing file-upload demo flow keeps working without
Keycloak configured. This must never be the default in a real deployment.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.auth.jwt import AUTH_ENABLED, AuthError, decode_and_validate

_bearer = HTTPBearer(auto_error=False)

DEMO_TENANT_NAME = "SIH-Demo"
ALL_ROLES = ["admin", "security_analyst", "operator", "auditor", "viewer"]


@dataclass
class CurrentUser:
    subject: str
    username: str
    roles: List[str] = field(default_factory=list)
    tenant_id: Optional[str] = None
    tenant_name: Optional[str] = None

    def has_role(self, *roles: str) -> bool:
        return any(r in self.roles for r in roles)


def _extract_roles(claims: dict) -> List[str]:
    roles: List[str] = []
    realm_access = claims.get("realm_access") or {}
    roles.extend(realm_access.get("roles", []))
    resource_access = claims.get("resource_access") or {}
    for client in resource_access.values():
        roles.extend(client.get("roles", []))
    # Only keep roles this application actually recognizes.
    return [r for r in roles if r in ALL_ROLES]


def _extract_tenant(claims: dict) -> Optional[str]:
    # Tenant is a custom claim populated by Keycloak (protocol mapper),
    # never a value the browser can set directly.
    return claims.get("tenant_id") or claims.get("tenant")


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> CurrentUser:
    if not AUTH_ENABLED:
        # Explicit local/offline demo mode only (Phase 5 rule).
        from sqlalchemy.orm import Session

        from app.db import SessionLocal
        from app.models.db import Tenant

        db: Session = SessionLocal()
        try:
            tenant = db.query(Tenant).filter(Tenant.name == DEMO_TENANT_NAME).first()
            if not tenant:
                tenant = Tenant(name=DEMO_TENANT_NAME)
                db.add(tenant)
                db.commit()
                db.refresh(tenant)
            return CurrentUser(
                subject="demo-user",
                username="demo-admin",
                roles=list(ALL_ROLES),
                tenant_id=tenant.id,
                tenant_name=tenant.name,
            )
        finally:
            db.close()

    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing bearer token")

    try:
        claims = decode_and_validate(credentials.credentials)
    except AuthError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message) from e

    tenant_id = _extract_tenant(claims)
    if not tenant_id:
        raise HTTPException(status_code=403, detail="Token has no tenant claim")

    return CurrentUser(
        subject=claims.get("sub", ""),
        username=claims.get("preferred_username", claims.get("sub", "")),
        roles=_extract_roles(claims),
        tenant_id=tenant_id,
        tenant_name=claims.get("tenant_name"),
    )


def require_role(*roles: str):
    """Dependency factory: raises 403 unless the current user has at least
    one of the given roles."""

    async def _check(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if not user.has_role(*roles):
            raise HTTPException(
                status_code=403,
                detail=f"Requires one of roles: {', '.join(roles)}",
            )
        return user

    return _check

def require_permission(*permissions):
    """Dependency factory: raises 403 unless the current user has at least
    one of the given permissions."""
    from app.auth.rbac import has_permission, Permission
    
    async def _check(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if not has_permission(user.roles, *permissions):
            raise HTTPException(
                status_code=403,
                detail=f"Requires one of permissions: {', '.join(p.value if hasattr(p, 'value') else str(p) for p in permissions)}",
            )
        return user

    return _check


async def get_current_tenant(user: CurrentUser = Depends(get_current_user)) -> str:
    """Tenant id from the validated identity ONLY — never from client input."""
    return user.tenant_id
