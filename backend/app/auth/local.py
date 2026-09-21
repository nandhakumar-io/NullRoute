"""Local (non-Keycloak) JWT issuing and validation.

These tokens are HS256, signed with AUTH_JWT_SECRET, and are only ever
produced by POST /api/auth/login in app/routers/auth.py. They are
distinguished from Keycloak's RS256 tokens by the `alg` in the unverified
header (see is_local_token below), so a single Authorization: Bearer
header works against either issuer without the client needing to know
which one it got.

Configuration:
    AUTH_JWT_SECRET      required whenever AUTH_ENABLED=true and local
                          accounts are in use; the app refuses to issue
                          local tokens without it (see _get_secret).
    AUTH_JWT_TTL_SECONDS  access-token lifetime, default 8 hours.
"""
from __future__ import annotations

import os
import time
import uuid
from typing import Any, Dict, List, Optional

from jose import jwt
from jose.exceptions import JOSEError

from app.auth.jwt import AuthError

LOCAL_JWT_ALGORITHM = "HS256"
LOCAL_JWT_ISSUER = "netsecauditor-local"
DEFAULT_TTL_SECONDS = int(os.getenv("AUTH_JWT_TTL_SECONDS", str(8 * 3600)))


def _get_secret() -> str:
    secret = os.getenv("AUTH_JWT_SECRET", "")
    if not secret:
        raise AuthError(
            "AUTH_JWT_SECRET is not configured; local login is unavailable "
            "until it is set.",
            status_code=500,
        )
    return secret


def is_local_token(token: str) -> bool:
    """Cheap, unverified check of which issuer minted this token, so the
    dependency layer can route to the right validator. This is NOT a trust
    decision by itself -- decode_and_validate below still verifies the
    signature before anything in the token is used."""
    try:
        header = jwt.get_unverified_header(token)
    except JOSEError:
        return False
    return header.get("alg") == LOCAL_JWT_ALGORITHM


def issue_token(
    *,
    user_id: str,
    username: str,
    roles: List[str],
    tenant_id: str,
    tenant_name: Optional[str] = None,
    token_version: int = 0,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> Dict[str, Any]:
    now = int(time.time())
    claims = {
        "iss": LOCAL_JWT_ISSUER,
        "sub": user_id,
        "jti": str(uuid.uuid4()),
        "preferred_username": username,
        "roles": roles,
        "tenant_id": tenant_id,
        "tenant_name": tenant_name,
        "token_version": token_version,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    token = jwt.encode(claims, _get_secret(), algorithm=LOCAL_JWT_ALGORITHM)
    return {"access_token": token, "token_type": "bearer", "expires_in": ttl_seconds}


def decode_and_validate(token: str) -> Dict[str, Any]:
    """Validate signature, issuer, and expiration for a local token.
    Raises AuthError on any failure. Returns the decoded claims on success.
    Does NOT check token_version against the DB -- callers must do that
    (see auth/dependencies.py) since only they have a DB session."""
    try:
        claims = jwt.decode(
            token,
            _get_secret(),
            algorithms=[LOCAL_JWT_ALGORITHM],
            issuer=LOCAL_JWT_ISSUER,
            options={"verify_aud": False, "verify_iss": True},
        )
    except JOSEError as e:
        raise AuthError(f"Token validation failed: {e}") from e
    return claims