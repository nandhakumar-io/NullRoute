import time

import pytest
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from jose import jwt as jose_jwt

from app.auth import dependencies as deps_mod
from app.auth import jwt as jwt_mod

PRIVATE_KEY_PEM = None  # generated lazily in fixture (RSA keypair for HS-free RS256 test)


@pytest.fixture
def rsa_keypair():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_numbers = key.public_key().public_numbers()
    return key, private_pem, public_numbers


def _jwk_from_public_numbers(public_numbers, kid="test-key"):
    import base64

    def b64(n: int) -> str:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": b64(public_numbers.n),
        "e": b64(public_numbers.e),
    }


@pytest.fixture(autouse=True)
def _auth_enabled(monkeypatch):
    monkeypatch.setattr(jwt_mod, "AUTH_ENABLED", True)
    monkeypatch.setattr(deps_mod, "AUTH_ENABLED", True)
    monkeypatch.setattr(jwt_mod, "KEYCLOAK_ISSUER", "https://kc.example/realms/test")
    monkeypatch.setattr(jwt_mod, "KEYCLOAK_AUDIENCE", "test-backend")
    yield


def _make_app():
    app = FastAPI()

    @app.get("/whoami")
    async def whoami(user: deps_mod.CurrentUser = Depends(deps_mod.get_current_user)):
        return {"username": user.username, "roles": user.roles, "tenant_id": user.tenant_id}

    @app.get("/admin-only")
    async def admin_only(user: deps_mod.CurrentUser = Depends(deps_mod.require_role("admin"))):
        return {"ok": True}

    return app


def _sign(private_pem, kid, claims, alg="RS256"):
    headers = {"kid": kid}
    return jose_jwt.encode(claims, private_pem, algorithm=alg, headers=headers)


def test_valid_jwt_grants_access(rsa_keypair, monkeypatch):
    key, private_pem, pub = rsa_keypair
    jwks = {"keys": [_jwk_from_public_numbers(pub)]}
    monkeypatch.setattr(jwt_mod, "_get_jwks", lambda force_refresh=False: jwks)

    claims = {
        "sub": "user-1",
        "preferred_username": "alice",
        "iss": "https://kc.example/realms/test",
        "aud": "test-backend",
        "exp": int(time.time()) + 3600,
        "realm_access": {"roles": ["operator"]},
        "tenant_id": "tenant-a",
    }
    token = _sign(private_pem, "test-key", claims)

    client = TestClient(_make_app())
    r = client.get("/whoami", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["username"] == "alice"
    assert r.json()["tenant_id"] == "tenant-a"


def test_missing_token_rejected():
    client = TestClient(_make_app())
    r = client.get("/whoami")
    assert r.status_code == 401


def test_expired_jwt_rejected(rsa_keypair, monkeypatch):
    key, private_pem, pub = rsa_keypair
    jwks = {"keys": [_jwk_from_public_numbers(pub)]}
    monkeypatch.setattr(jwt_mod, "_get_jwks", lambda force_refresh=False: jwks)

    claims = {
        "sub": "user-1",
        "iss": "https://kc.example/realms/test",
        "aud": "test-backend",
        "exp": int(time.time()) - 60,  # expired
        "tenant_id": "tenant-a",
    }
    token = _sign(private_pem, "test-key", claims)

    client = TestClient(_make_app())
    r = client.get("/whoami", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


def test_invalid_signature_rejected(rsa_keypair, monkeypatch):
    key, private_pem, pub = rsa_keypair
    # JWKS advertises a DIFFERENT key than the one used to sign -> bad signature.
    other_key, other_private_pem, other_pub = rsa_keypair[0], private_pem, pub
    from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod

    wrong_key = rsa_mod.generate_private_key(public_exponent=65537, key_size=2048)
    wrong_pub = wrong_key.public_key().public_numbers()
    jwks = {"keys": [_jwk_from_public_numbers(wrong_pub, kid="test-key")]}
    monkeypatch.setattr(jwt_mod, "_get_jwks", lambda force_refresh=False: jwks)

    claims = {
        "sub": "user-1",
        "iss": "https://kc.example/realms/test",
        "aud": "test-backend",
        "exp": int(time.time()) + 3600,
        "tenant_id": "tenant-a",
    }
    token = _sign(private_pem, "test-key", claims)

    client = TestClient(_make_app())
    r = client.get("/whoami", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


def test_wrong_role_rejected(rsa_keypair, monkeypatch):
    key, private_pem, pub = rsa_keypair
    jwks = {"keys": [_jwk_from_public_numbers(pub)]}
    monkeypatch.setattr(jwt_mod, "_get_jwks", lambda force_refresh=False: jwks)

    claims = {
        "sub": "user-1",
        "iss": "https://kc.example/realms/test",
        "aud": "test-backend",
        "exp": int(time.time()) + 3600,
        "realm_access": {"roles": ["viewer"]},
        "tenant_id": "tenant-a",
    }
    token = _sign(private_pem, "test-key", claims)

    client = TestClient(_make_app())
    r = client.get("/admin-only", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403
