import pytest
from fastapi.testclient import TestClient
from app.auth import dependencies as deps_mod
from app.auth import jwt as jwt_mod

@pytest.fixture(autouse=True)
def _demo_auth(monkeypatch):
    monkeypatch.setattr(jwt_mod, "AUTH_ENABLED", False)
    monkeypatch.setattr(deps_mod, "AUTH_ENABLED", False)
    yield

def test_compliance_summary_no_longer_500s(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test.db")
    monkeypatch.setenv("AI_ENABLED", "false")
    from app.main import app
    with TestClient(app) as c:
        resp = c.get("/api/metrics/compliance-summary")
        assert resp.status_code == 200, resp.text
        assert "ai_health" in resp.json()