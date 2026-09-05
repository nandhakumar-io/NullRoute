"""Regression test for a cross-tenant leak in routers/training.py and
routers/knowledge.py: CommandMapping.tenant_id's own docstring promises
"a training mapping learned for one tenant's fleet is never exposed to
another tenant's pipeline" (RULE 19), but list_pending/list_approved/
review_mapping/learned_mappings queried CommandMapping with no tenant
filter at all -- any authenticated user of any tenant could read, and
even approve/reject, another tenant's learned command mappings.

Fixed by threading get_current_tenant() through every endpoint, scoped
to (tenant_id == current tenant) OR (tenant_id IS NULL) since NULL
tenant_id is the intentional shared/global knowledge-base case."""
import pytest
from fastapi.testclient import TestClient

from app.auth import dependencies as deps_mod
from app.auth import jwt as jwt_mod


@pytest.fixture(autouse=True)
def _demo_auth(monkeypatch):
    monkeypatch.setattr(jwt_mod, "AUTH_ENABLED", False)
    monkeypatch.setattr(deps_mod, "AUTH_ENABLED", False)
    yield


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test.db")
    monkeypatch.setenv("AI_ENABLED", "false")
    from app.main import app

    with TestClient(app) as c:
        yield c


def _make_mapping(tenant_id, status="pending", mapping_id="map-other-tenant-1"):
    from app.db import SessionLocal
    from app.models.db import CommandMapping, Tenant

    db = SessionLocal()
    try:
        if tenant_id is not None:
            other_tenant = Tenant(id=tenant_id, name="OtherTenant")
            db.merge(other_tenant)
            db.commit()

        mapping = CommandMapping(
            id=mapping_id,
            tenant_id=tenant_id,
            vendor="cisco_ios",
            raw_command_pattern="ip ssh time-out 60",
            normalized_parameter="ssh_timeout",
            example_value="60",
            confidence=0.5,
            status=status,
        )
        db.add(mapping)
        db.commit()
        return mapping.id
    finally:
        db.close()


def test_list_pending_excludes_other_tenant(client):
    mapping_id = _make_mapping(tenant_id="other-tenant-1", status="pending")
    resp = client.get("/api/training/pending")
    assert resp.status_code == 200
    ids = [m["id"] for m in resp.json()]
    assert mapping_id not in ids


def test_list_approved_excludes_other_tenant(client):
    mapping_id = _make_mapping(tenant_id="other-tenant-2", status="approved")
    resp = client.get("/api/training/approved")
    assert resp.status_code == 200
    ids = [m["id"] for m in resp.json()]
    assert mapping_id not in ids


def test_review_mapping_404s_for_other_tenant(client):
    mapping_id = _make_mapping(tenant_id="other-tenant-3", status="pending")
    resp = client.post(
        f"/api/training/{mapping_id}/review",
        json={"action": "approve", "reviewer": "attacker@example.com"},
    )
    assert resp.status_code == 404


def test_knowledge_base_mappings_excludes_other_tenant(client):
    mapping_id = _make_mapping(tenant_id="other-tenant-4", status="approved")
    resp = client.get("/api/knowledge-base/mappings")
    assert resp.status_code == 200
    ids = [m["id"] for m in resp.json()]
    assert mapping_id not in ids


def test_null_tenant_mapping_is_visible_to_all_tenants(client):
    """NULL tenant_id is the intentional shared/global knowledge-base case
    (per the model docstring) and must remain visible -- confirms the fix
    scopes to (tenant OR NULL), not tenant-only."""
    mapping_id = _make_mapping(tenant_id=None, status="approved", mapping_id="map-global-1")
    resp = client.get("/api/knowledge-base/mappings")
    assert resp.status_code == 200
    ids = [m["id"] for m in resp.json()]
    assert mapping_id in ids