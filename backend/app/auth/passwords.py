"""Password hashing for local (non-Keycloak) accounts.

Uses stdlib hashlib.scrypt (PEP 458, available since Python 3.6 -- no extra
dependency, and sidesteps the passlib/bcrypt-4.x ABI breakage currently
affecting passlib[bcrypt]==1.7.4's `bcrypt_sha256` scheme in this
environment). Encoded as a self-describing string so parameters can change
later without invalidating existing hashes:

    scrypt$N$r$p$<salt_b64>$<hash_b64>
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os

_ALGO = "scrypt"
_N = 2 ** 14  # CPU/memory cost
_R = 8        # block size
_P = 1        # parallelization
_DKLEN = 32
_SALT_LEN = 16

# A password below this length is rejected when creating/changing one.
# This does not affect verifying existing hashes.
MIN_PASSWORD_LENGTH = 12


class WeakPasswordError(ValueError):
    pass


def validate_password_strength(password: str) -> None:
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPasswordError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters long."
        )


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def hash_password(password: str) -> str:
    validate_password_strength(password)
    salt = os.urandom(_SALT_LEN)
    derived = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=_N, r=_R, p=_P, dklen=_DKLEN)
    return f"{_ALGO}${_N}${_R}${_P}${_b64(salt)}${_b64(derived)}"


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-time verify. Returns False (never raises) on a malformed
    or empty hash so a corrupt row can't be used as an auth bypass."""
    if not password or not password_hash:
        return False
    try:
        algo, n_s, r_s, p_s, salt_b64, hash_b64 = password_hash.split("$")
        if algo != _ALGO:
            return False
        n, r, p = int(n_s), int(r_s), int(p_s)
        salt = _unb64(salt_b64)
        expected = _unb64(hash_b64)
        candidate = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=len(expected))
        return hmac.compare_digest(candidate, expected)
    except Exception:  # noqa: BLE001 - unrecognized/corrupt hash format
        return False