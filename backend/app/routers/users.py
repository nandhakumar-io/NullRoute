"""Local user administration + self-service password change.

Only meaningful for local (username/password) accounts; Keycloak-managed
identities live in Keycloak. Everything is scoped to the caller's tenant, and
user management requires the MANAGE_USERS permission (admin roles).
"""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth import local as local_auth
from app.auth.dependencies import ALL_ROLES, CurrentUser, get_current_tenant, get_current_user, require_permission
from app.auth.passwords import WeakPasswordError, hash_password, validate_password_strength, verify_password
from app.auth.rbac import Permission
from app.db import get_db
from app.models.db import Tenant, User
from app.services import audit_service

router = APIRouter(prefix="/api", tags=["users"])


def _out(u: User) -> dict:
    return {
        "id": u.id, "username": u.username, "roles": list(u.roles or []), "is_active": bool(u.is_active),
        "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
        "locked": bool(u.locked_until),
        "created_at": u.created_at.isoformat() if u.created_at else None,
    }


def _clean_roles(roles: List[str]) -> List[str]:
    bad = [r for r in roles if r not in ALL_ROLES]
    if bad:
        raise HTTPException(422, f"Unknown role(s): {', '.join(bad)}. Valid: {', '.join(ALL_ROLES)}")
    if not roles:
        raise HTTPException(422, "At least one role is required")
    return sorted(set(roles))


def _active_admin_count(db: Session, tenant_id: str, excluding: Optional[str] = None) -> int:
    q = db.query(User).filter(User.tenant_id == tenant_id, User.is_active.is_(True))
    return sum(1 for u in q.all() if "admin" in (u.roles or []) and u.id != excluding)


# ------------------------------------------------------------ self-service --
class ChangePassword(BaseModel):
    current_password: str = Field(min_length=1)
    new_password: str = Field(min_length=1)


@router.post("/auth/change-password")
def change_password(
    payload: ChangePassword,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Changes the caller's own password. Bumps token_version, so every other
    session stops working; the response carries a fresh token for this one."""
    row = db.query(User).filter(User.id == user.subject).first()
    if row is None:
        raise HTTPException(400, "Password changes apply to local accounts only (this identity is managed by Keycloak).")
    if not verify_password(payload.current_password, row.password_hash):
        raise HTTPException(400, "Current password is incorrect")
    try:
        validate_password_strength(payload.new_password)
    except WeakPasswordError as e:
        raise HTTPException(422, str(e))
    if payload.new_password == payload.current_password:
        raise HTTPException(422, "New password must differ from the current one")
    row.password_hash = hash_password(payload.new_password)
    row.token_version = (row.token_version or 0) + 1
    db.commit()
    audit_service.record_from_user(db, user, action="auth.password.change", request=request, result="SUCCESS",
                                   object_type="user", object_id=row.id, old_value=None, new_value=None)
    tenant = db.query(Tenant).filter(Tenant.id == row.tenant_id).first()
    return local_auth.issue_token(
        user_id=row.id, username=row.username, roles=list(row.roles or []), tenant_id=row.tenant_id,
        tenant_name=tenant.name if tenant else None, token_version=row.token_version,
    )


# ------------------------------------------------------------------- admin --
class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str
    roles: List[str]


class UserUpdate(BaseModel):
    roles: Optional[List[str]] = None
    is_active: Optional[bool] = None


class PasswordReset(BaseModel):
    new_password: str


@router.get("/users")
def list_users(
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    _: CurrentUser = Depends(require_permission(Permission.MANAGE_USERS)),
):
    return [_out(u) for u in db.query(User).filter(User.tenant_id == tenant_id).order_by(User.username).all()]


@router.post("/users")
def create_user(
    payload: UserCreate,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    actor: CurrentUser = Depends(require_permission(Permission.MANAGE_USERS)),
):
    roles = _clean_roles(payload.roles)
    try:
        pw_hash = hash_password(payload.password)
    except WeakPasswordError as e:
        raise HTTPException(422, str(e))
    u = User(tenant_id=tenant_id, username=payload.username.strip(), password_hash=pw_hash, roles=roles, is_active=True)
    db.add(u)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, f"Username {payload.username!r} already exists in this tenant")
    audit_service.record_from_user(db, actor, action="user.create", request=request, result="SUCCESS",
                                   object_type="user", object_id=u.id, old_value=None, new_value={"username": u.username, "roles": roles})
    return _out(u)


def _get_user(db: Session, tenant_id: str, user_id: str) -> User:
    u = db.query(User).filter(User.id == user_id, User.tenant_id == tenant_id).first()
    if not u:
        raise HTTPException(404, "User not found")
    return u


@router.patch("/users/{user_id}")
def update_user(
    user_id: str,
    payload: UserUpdate,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    actor: CurrentUser = Depends(require_permission(Permission.MANAGE_USERS)),
):
    u = _get_user(db, tenant_id, user_id)
    before = {"roles": list(u.roles or []), "is_active": u.is_active}
    new_roles = _clean_roles(payload.roles) if payload.roles is not None else list(u.roles or [])
    new_active = u.is_active if payload.is_active is None else payload.is_active
    # Never lock the tenant out of administration.
    loses_admin = ("admin" in (u.roles or []) and u.is_active) and ("admin" not in new_roles or not new_active)
    if loses_admin and _active_admin_count(db, tenant_id, excluding=u.id) == 0:
        raise HTTPException(400, "Cannot remove or deactivate the last active admin")
    u.roles, u.is_active = new_roles, new_active
    if before["roles"] != new_roles or before["is_active"] != new_active:
        u.token_version = (u.token_version or 0) + 1  # role/active change takes effect immediately
    if new_active:
        u.locked_until, u.failed_login_count = None, 0  # re-enabling doubles as unlock
    db.commit()
    audit_service.record_from_user(db, actor, action="user.update", request=request, result="SUCCESS",
                                   object_type="user", object_id=u.id, old_value=before,
                                   new_value={"roles": new_roles, "is_active": new_active})
    return _out(u)


@router.post("/users/{user_id}/reset-password")
def reset_password(
    user_id: str,
    payload: PasswordReset,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    actor: CurrentUser = Depends(require_permission(Permission.MANAGE_USERS)),
):
    u = _get_user(db, tenant_id, user_id)
    try:
        u.password_hash = hash_password(payload.new_password)
    except WeakPasswordError as e:
        raise HTTPException(422, str(e))
    u.token_version = (u.token_version or 0) + 1
    u.locked_until, u.failed_login_count = None, 0
    db.commit()
    audit_service.record_from_user(db, actor, action="user.password.reset", request=request, result="SUCCESS",
                                   object_type="user", object_id=u.id, old_value=None, new_value=None)
    return {"status": "ok"}
