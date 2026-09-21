"""Local username/password login, alongside Keycloak.

POST /api/auth/login  -- returns a local HS256 access token (see
                          auth/local.py) on success.
GET  /api/auth/me     -- works with either a local or a Keycloak token.
POST /api/auth/logout -- bumps token_version, invalidating every
                          previously issued local token for this user.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.auth import local as local_auth
from app.auth.dependencies import CurrentUser, get_current_user
from app.auth.passwords import verify_password
from app.db import get_db
from app.models.db import Tenant, User

logger = logging.getLogger("app.routers.auth")
router = APIRouter(prefix="/api/auth", tags=["auth"])

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


class LoginRequest(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)
    # Optional: disambiguates a username that exists in more than one
    # tenant. Most deployments have one tenant per user and can omit this.
    tenant: str | None = None


class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int


@router.get("/config")
def auth_config():
    """Public: lets the SPA know whether to show the login form at all
    (AUTH_ENABLED=false demo deployments have no login)."""
    from app.auth import dependencies as deps

    return {"auth_enabled": bool(deps.AUTH_ENABLED)}


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    query = db.query(User).filter(User.username == payload.username)
    if payload.tenant:
        query = query.join(Tenant, Tenant.id == User.tenant_id).filter(Tenant.name == payload.tenant)
    candidates = query.all()

    if len(candidates) > 1:
        # Ambiguous username across tenants and the caller didn't disambiguate.
        raise HTTPException(status_code=400, detail="Multiple accounts match this username; specify 'tenant'.")

    user = candidates[0] if candidates else None

    # Constant-shape failure path: verify against a dummy hash when there's
    # no such user, so the response timing doesn't reveal whether the
    # username exists.
    if user is None:
        from app.auth.passwords import hash_password

        # Constant-shape failure path: still do a real scrypt hash+verify
        # so the response timing doesn't reveal whether the username exists.
        verify_password(payload.password, hash_password("dummy-password-for-timing"))
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if user.locked_until and user.locked_until > datetime.utcnow():
        raise HTTPException(
            status_code=423,
            detail=f"Account locked until {user.locked_until.isoformat()}Z due to repeated failed logins.",
        )

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")

    if not verify_password(payload.password, user.password_hash):
        user.failed_login_count = (user.failed_login_count or 0) + 1
        if user.failed_login_count >= MAX_FAILED_ATTEMPTS:
            user.locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
            user.failed_login_count = 0
            logger.warning("Account %r locked for %s minutes after repeated failed logins.", user.username, LOCKOUT_MINUTES)
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # Success: reset lockout state and issue a token.
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = datetime.utcnow()
    db.commit()

    tenant = db.query(Tenant).filter(Tenant.id == user.tenant_id).first()
    token = local_auth.issue_token(
        user_id=user.id,
        username=user.username,
        roles=list(user.roles or []),
        tenant_id=user.tenant_id,
        tenant_name=tenant.name if tenant else None,
        token_version=user.token_version,
    )
    return LoginResponse(**token)


@router.post("/logout")
def logout(user: CurrentUser = Depends(get_current_user), db: Session = Depends(get_db)):
    """Bumps token_version so every local token issued before this call
    stops validating (see auth/dependencies.py). No-op for Keycloak-issued
    identities, which this app doesn't hold a revocation list for."""
    row = db.query(User).filter(User.id == user.subject).first()
    if row is not None:
        row.token_version = (row.token_version or 0) + 1
        db.commit()
    return {"status": "ok"}


@router.get("/me")
def me(user: CurrentUser = Depends(get_current_user)):
    return {
        "username": user.username,
        "roles": user.roles,
        "tenant_id": user.tenant_id,
        "tenant_name": user.tenant_name,
    }