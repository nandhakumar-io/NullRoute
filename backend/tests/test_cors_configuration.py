"""Regression test for a CORS misconfiguration: app/main.py previously
hard-coded allow_origins=["*"] together with allow_credentials=True.
Starlette's CORSMiddleware handles that combination by echoing the
request's actual Origin header back (since a literal "*" can't be paired
with credentials per the CORS spec), which means the old configuration
granted every origin on the internet permission to make credentialed
requests against this API -- the wildcard restricted nothing.

Fixed via CORS_ALLOWED_ORIGINS (spec section 54: audit CORS). This test
proves: (1) with no explicit origins configured, a cross-origin request
is not granted CORS access; (2) with an explicit allow-list, only listed
origins are granted access, with credentials allowed; (3) explicitly
requesting "*" gets wildcard access but with credentials forced off,
never both at once.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.auth import dependencies as deps_mod
from app.auth import jwt as jwt_mod


@pytest.fixture(autouse=True)
def _demo_auth(monkeypatch):
    monkeypatch.setattr(jwt_mod, "AUTH_ENABLED", False)
    monkeypatch.setattr(deps_mod, "AUTH_ENABLED", False)
    yield


def _make_client(tmp_path, monkeypatch, cors_env: str):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test.db")
    monkeypatch.setenv("AI_ENABLED", "false")
    if cors_env is None:
        monkeypatch.delenv("CORS_ALLOWED_ORIGINS", raising=False)
    else:
        monkeypatch.setenv("CORS_ALLOWED_ORIGINS", cors_env)
    # main.py reads CORS_ALLOWED_ORIGINS at import time, so force a fresh
    # import of the module (and everything that already imported `app`)
    # for each variant under test.
    import sys
    for mod in list(sys.modules):
        if mod == "app.main" or mod.startswith("app.main."):
            del sys.modules[mod]
    from app.main import app
    return TestClient(app)


def test_no_origins_configured_grants_no_cross_origin_access(tmp_path, monkeypatch):
    with _make_client(tmp_path, monkeypatch, cors_env=None) as client:
        resp = client.get("/api/devices", headers={"Origin": "https://evil.example.com"})
        assert "access-control-allow-origin" not in {k.lower() for k in resp.headers.keys()}


def test_explicit_allowlist_grants_only_listed_origin_with_credentials(tmp_path, monkeypatch):
    with _make_client(tmp_path, monkeypatch, cors_env="https://app.example.com") as client:
        allowed = client.get("/api/devices", headers={"Origin": "https://app.example.com"})
        assert allowed.headers.get("access-control-allow-origin") == "https://app.example.com"
        assert allowed.headers.get("access-control-allow-credentials") == "true"

        blocked = client.get("/api/devices", headers={"Origin": "https://evil.example.com"})
        assert blocked.headers.get("access-control-allow-origin") != "https://evil.example.com"


def test_wildcard_disables_credentials_never_both(tmp_path, monkeypatch):
    """The one combination that must never happen: allow_origins including
    "*" together with allow_credentials=True."""
    with _make_client(tmp_path, monkeypatch, cors_env="*") as client:
        resp = client.get("/api/devices", headers={"Origin": "https://anything.example.com"})
        # Wildcard access is explicitly what was asked for here...
        assert resp.headers.get("access-control-allow-origin") in ("*", "https://anything.example.com")
        # ...but credentials must never be granted alongside it.
        assert resp.headers.get("access-control-allow-credentials") != "true"