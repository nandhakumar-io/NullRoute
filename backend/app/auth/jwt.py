"""
Keycloak JWT validation: issuer, audience, signature (via JWKS), and
expiration.

JWKS is fetched once and cached with a TTL (rotation-safe: a `kid` miss
triggers exactly one forced refresh before failing) so we never fetch
Keycloak's JWKS endpoint on every request.

Configuration (environment variables):
    KEYCLOAK_ISSUER            e.g. https://keycloak.example/realms/netsecauditor
    KEYCLOAK_AUDIENCE          e.g. netsecauditor-backend
    KEYCLOAK_JWKS_URL          defaults to f"{KEYCLOAK_ISSUER}/protocol/openid-connect/certs"
    AUTH_ENABLED               "true" in every real deployment; "false" only for the
                               explicit local/offline demo mode (see Phase 5 rule).
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx
from jose import jwt
from jose.exceptions import JOSEError

KEYCLOAK_ISSUER = os.getenv("KEYCLOAK_ISSUER", "")
KEYCLOAK_AUDIENCE = os.getenv("KEYCLOAK_AUDIENCE", "netsecauditor-backend")
KEYCLOAK_JWKS_URL = os.getenv("KEYCLOAK_JWKS_URL") or (
    f"{KEYCLOAK_ISSUER}/protocol/openid-connect/certs" if KEYCLOAK_ISSUER else ""
)
JWKS_CACHE_TTL_SECONDS = int(os.getenv("KEYCLOAK_JWKS_CACHE_TTL", "3600"))

# Algorithm confusion guard: Keycloak signs with RS256 (asymmetric). We must
# never let the token itself dictate which algorithm is used to verify it --
# if a caller could set alg=HS256 in the header, a library that treats the
# RSA *public* key bytes as an HMAC *secret* would let anyone forge a token
# using the (publicly known) public key. Only ever accept the algorithm(s)
# Keycloak actually issues; a header claiming anything else is rejected
# before signature verification is attempted.
ALLOWED_ALGORITHMS = ["RS256"]

# RULE (Phase 5): demo/dev mode is an explicit opt-in, never the silent
# default in a real deployment.
AUTH_ENABLED = os.getenv("AUTH_ENABLED", "true").strip().lower() in ("1", "true", "yes", "on")


class AuthError(Exception):
    def __init__(self, message: str, status_code: int = 401):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


@dataclass
class _JWKSCache:
    keys: Dict[str, Any]
    fetched_at: float


_cache: Optional[_JWKSCache] = None


def _fetch_jwks() -> Dict[str, Any]:
    if not KEYCLOAK_JWKS_URL:
        raise AuthError("KEYCLOAK_JWKS_URL/KEYCLOAK_ISSUER not configured", status_code=500)
    resp = httpx.get(KEYCLOAK_JWKS_URL, timeout=10.0)
    resp.raise_for_status()
    return resp.json()


def _get_jwks(force_refresh: bool = False) -> Dict[str, Any]:
    global _cache
    now = time.time()
    if (
        force_refresh
        or _cache is None
        or (now - _cache.fetched_at) > JWKS_CACHE_TTL_SECONDS
    ):
        _cache = _JWKSCache(keys=_fetch_jwks(), fetched_at=now)
    return _cache.keys


def _find_key(jwks: Dict[str, Any], kid: str) -> Optional[Dict[str, Any]]:
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            return key
    return None


def decode_and_validate(token: str) -> Dict[str, Any]:
    """Validate signature (via JWKS), issuer, audience, and expiration.
    Raises AuthError on any failure. Returns the decoded claims on success."""
    try:
        unverified_header = jwt.get_unverified_header(token)
    except JOSEError as e:
        raise AuthError(f"Malformed token header: {e}") from e

    kid = unverified_header.get("kid")
    if not kid:
        raise AuthError("Token header missing 'kid'")

    alg = unverified_header.get("alg")
    if alg not in ALLOWED_ALGORITHMS:
        raise AuthError(f"Unsupported token algorithm '{alg}'; must be one of {ALLOWED_ALGORITHMS}")

    jwks = _get_jwks()
    key = _find_key(jwks, kid)
    if key is None:
        # Key rotation: refresh once before giving up.
        jwks = _get_jwks(force_refresh=True)
        key = _find_key(jwks, kid)
        if key is None:
            raise AuthError("No matching JWKS key for token 'kid'")

    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=ALLOWED_ALGORITHMS,
            audience=KEYCLOAK_AUDIENCE,
            issuer=KEYCLOAK_ISSUER or None,
            options={"verify_aud": bool(KEYCLOAK_AUDIENCE), "verify_iss": bool(KEYCLOAK_ISSUER)},
        )
    except JOSEError as e:
        raise AuthError(f"Token validation failed: {e}") from e

    return claims
