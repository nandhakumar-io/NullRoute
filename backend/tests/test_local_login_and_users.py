"""Local login end to end: bootstrap admin, lockout, logout/password-change
invalidation, user administration, last-admin protection."""
import pytest
from fastapi.testclient import TestClient

from app.auth import dependencies as deps_mod
from app.auth import jwt as jwt_mod

ADMIN_PW = "bootstrap-admin-pw-1"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(jwt_mod, "AUTH_ENABLED", True)
    monkeypatch.setattr(deps_mod, "AUTH_ENABLED", True)
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("AUTH_JWT_SECRET", "test-secret-test-secret-test-secret")
    monkeypatch.setenv("BOOTSTRAP_ADMIN_PASSWORD", ADMIN_PW)
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/auth.db")
    monkeypatch.setenv("AI_ENABLED", "false")
    from app.main import app
    with TestClient(app) as c:
        yield c


def _login(c, user="admin", pw=ADMIN_PW):
    return c.post("/api/auth/login", json={"username": user, "password": pw})


def _h(tok):
    return {"Authorization": f"Bearer {tok}"}


def _tok(c, user="admin", pw=ADMIN_PW):
    r = _login(c, user, pw)
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def test_config_and_protected_routes(client):
    assert client.get("/api/auth/config").json() == {"auth_enabled": True}
    assert client.get("/api/auth/me").status_code == 401


def test_bootstrap_admin_login_me_logout(client):
    tok = _tok(client)
    me = client.get("/api/auth/me", headers=_h(tok)).json()
    assert me["username"] == "admin" and "admin" in me["roles"] and me["tenant_name"] == "SIH-Demo"
    assert client.post("/api/auth/logout", headers=_h(tok)).status_code == 200
    assert client.get("/api/auth/me", headers=_h(tok)).status_code == 401  # token now invalid


def test_wrong_password_and_lockout(client):
    assert _login(client, pw="nope-nope-nope-1").status_code == 401
    assert _login(client, "ghost", "whatever-whatever").status_code == 401
    for _ in range(5):
        _login(client, pw="nope-nope-nope-1")
    assert _login(client).status_code == 423  # locked even with the right password


def test_change_password_rotates_sessions(client):
    old = _tok(client)
    r = client.post("/api/auth/change-password", headers=_h(old),
                    json={"current_password": "wrong", "new_password": "a-brand-new-password"})
    assert r.status_code == 400
    r = client.post("/api/auth/change-password", headers=_h(old),
                    json={"current_password": ADMIN_PW, "new_password": "short"})
    assert r.status_code == 422
    r = client.post("/api/auth/change-password", headers=_h(old),
                    json={"current_password": ADMIN_PW, "new_password": "a-brand-new-password"})
    assert r.status_code == 200
    assert client.get("/api/auth/me", headers=_h(old)).status_code == 401
    assert client.get("/api/auth/me", headers=_h(r.json()["access_token"])).status_code == 200
    assert _login(client).status_code == 401
    assert _login(client, pw="a-brand-new-password").status_code == 200


def test_user_admin_flow(client):
    admin = _tok(client)
    r = client.post("/api/users", headers=_h(admin), json={"username": "vic", "password": "viewer-password-1", "roles": ["viewer"]})
    assert r.status_code == 200, r.text
    vid = r.json()["id"]
    assert client.post("/api/users", headers=_h(admin), json={"username": "vic", "password": "viewer-password-1", "roles": ["viewer"]}).status_code == 409
    assert client.post("/api/users", headers=_h(admin), json={"username": "x", "password": "short", "roles": ["viewer"]}).status_code == 422
    assert client.post("/api/users", headers=_h(admin), json={"username": "y", "password": "long-enough-pw-1", "roles": ["root"]}).status_code == 422

    vic = _tok(client, "vic", "viewer-password-1")
    assert client.get("/api/users", headers=_h(vic)).status_code == 403  # viewer can't administer
    assert {u["username"] for u in client.get("/api/users", headers=_h(admin)).json()} == {"admin", "vic"}

    # role change takes effect immediately (old token stops working)
    assert client.patch(f"/api/users/{vid}", headers=_h(admin), json={"roles": ["security_analyst"]}).json()["roles"] == ["security_analyst"]
    assert client.get("/api/auth/me", headers=_h(vic)).status_code == 401
    vic = _tok(client, "vic", "viewer-password-1")
    assert "security_analyst" in client.get("/api/auth/me", headers=_h(vic)).json()["roles"]

    # deactivate blocks login; reset password + reactivate restores it
    client.patch(f"/api/users/{vid}", headers=_h(admin), json={"is_active": False})
    assert _login(client, "vic", "viewer-password-1").status_code == 403
    client.patch(f"/api/users/{vid}", headers=_h(admin), json={"is_active": True})
    assert client.post(f"/api/users/{vid}/reset-password", headers=_h(admin), json={"new_password": "reset-password-99"}).status_code == 200
    assert _login(client, "vic", "reset-password-99").status_code == 200


def test_cannot_remove_last_admin(client):
    admin = _tok(client)
    aid = client.get("/api/users", headers=_h(admin)).json()[0]["id"]
    assert client.patch(f"/api/users/{aid}", headers=_h(admin), json={"is_active": False}).status_code == 400
    assert client.patch(f"/api/users/{aid}", headers=_h(admin), json={"roles": ["viewer"]}).status_code == 400
