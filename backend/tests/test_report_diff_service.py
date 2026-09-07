"""app/services/report_diff_service.py -- diffs the compliance Findings of
two scans of the same device ("what changed since last audit").

Covers: no prior scan -> every current failure reported as newly_failing
with no crash; a control that flips PASS->FAIL between scans is
newly_failing; FAIL->PASS is resolved; FAIL->FAIL unchanged severity is
still_failing; FAIL->FAIL with a severity change lands in
severity_changed (and NOT also in still_failing); an unrelated PASS->PASS
control is counted but not listed; compliance_score delta is computed;
and find_previous_scan only ever returns a completed, earlier, same-
device, same-tenant scan.
"""
from __future__ import annotations

import pytest

from app.auth import dependencies as deps_mod
from app.auth import jwt as jwt_mod


@pytest.fixture(autouse=True)
def _demo_auth(monkeypatch):
    monkeypatch.setattr(jwt_mod, "AUTH_ENABLED", False)
    monkeypatch.setattr(deps_mod, "AUTH_ENABLED", False)
    yield


@pytest.fixture
def db_session(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test.db")
    monkeypatch.setenv("AI_ENABLED", "false")
    monkeypatch.setattr("app.services.fabric_service.FABRIC_ENABLED", False)
    from app.db import SessionLocal, init_db

    init_db()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _make_tenant(db, name="Acme"):
    from app.models.db import Tenant

    t = Tenant(name=name)
    db.add(t)
    db.commit()
    db.refresh(t)
    return t


def _make_scan(db, tenant_id, device_id="dev-1", score=None, created_at=None, status="completed"):
    from datetime import datetime

    from app.models.db import Scan

    s = Scan(
        tenant_id=tenant_id,
        device_id=device_id,
        status=status,
        compliance_score=score,
        created_at=created_at or datetime.utcnow(),
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    return s


def _make_finding(db, scan_id, control_id, result, severity="HIGH", framework="CIS"):
    from app.models.db import Finding

    f = Finding(
        scan_id=scan_id, framework=framework, control_id=control_id,
        title=control_id, severity=severity, result=result,
    )
    db.add(f)
    db.commit()
    db.refresh(f)
    return f


def test_no_baseline_reports_all_failures_as_newly_failing(db_session):
    from app.services import report_diff_service

    tenant = _make_tenant(db_session)
    scan = _make_scan(db_session, tenant.id, score=60.0)
    _make_finding(db_session, scan.id, "CIS-1.1", "FAIL")
    _make_finding(db_session, scan.id, "CIS-1.2", "PASS")

    diff = report_diff_service.build_report_diff(db_session, scan, None)

    assert diff.baseline_scan_id is None
    assert diff.score_delta is None
    assert [f["control_id"] for f in diff.newly_failing] == ["CIS-1.1"]
    assert diff.resolved == []
    assert diff.still_failing == []
    assert diff.severity_changed == []


def test_diff_categorizes_transitions_correctly(db_session):
    from datetime import datetime, timedelta

    from app.services import report_diff_service

    tenant = _make_tenant(db_session)
    t0 = datetime.utcnow() - timedelta(hours=1)
    baseline = _make_scan(db_session, tenant.id, score=50.0, created_at=t0)
    current = _make_scan(db_session, tenant.id, score=75.0, created_at=t0 + timedelta(hours=1))

    # Baseline scan findings.
    _make_finding(db_session, baseline.id, "CIS-1.1", "PASS")   # -> will newly fail
    _make_finding(db_session, baseline.id, "CIS-1.2", "FAIL", severity="HIGH")   # -> resolved
    _make_finding(db_session, baseline.id, "CIS-1.3", "FAIL", severity="MEDIUM")  # -> still failing, same severity
    _make_finding(db_session, baseline.id, "CIS-1.4", "FAIL", severity="LOW")     # -> severity escalates
    _make_finding(db_session, baseline.id, "CIS-1.5", "PASS")   # -> stays passing (unchanged)

    # Current scan findings.
    _make_finding(db_session, current.id, "CIS-1.1", "FAIL", severity="CRITICAL")
    _make_finding(db_session, current.id, "CIS-1.2", "PASS")
    _make_finding(db_session, current.id, "CIS-1.3", "FAIL", severity="MEDIUM")
    _make_finding(db_session, current.id, "CIS-1.4", "FAIL", severity="HIGH")
    _make_finding(db_session, current.id, "CIS-1.5", "PASS")

    diff = report_diff_service.build_report_diff(db_session, current, baseline)

    assert diff.baseline_scan_id == baseline.id
    assert diff.score_delta == 25.0

    assert {f["control_id"] for f in diff.newly_failing} == {"CIS-1.1"}
    assert {f["control_id"] for f in diff.resolved} == {"CIS-1.2"}
    assert {f["control_id"] for f in diff.still_failing} == {"CIS-1.3"}

    assert {f["control_id"] for f in diff.severity_changed} == {"CIS-1.4"}
    escalated = diff.severity_changed[0]
    assert escalated["previous_severity"] == "LOW"
    assert escalated["severity"] == "HIGH"
    # A severity-changed control must not be double-counted as still_failing.
    assert "CIS-1.4" not in {f["control_id"] for f in diff.still_failing}

    assert diff.unchanged_count == 1  # CIS-1.5, PASS -> PASS


def test_find_previous_scan_scopes_correctly(db_session):
    from datetime import datetime, timedelta

    from app.services import report_diff_service

    tenant_a = _make_tenant(db_session, "Acme")
    tenant_b = _make_tenant(db_session, "Globex")
    t0 = datetime.utcnow() - timedelta(hours=3)

    older_same_device = _make_scan(db_session, tenant_a.id, device_id="dev-1", created_at=t0)
    _make_scan(db_session, tenant_a.id, device_id="dev-2", created_at=t0 + timedelta(hours=1))  # other device
    _make_scan(db_session, tenant_b.id, device_id="dev-1", created_at=t0 + timedelta(hours=1))  # other tenant
    failed_same_device = _make_scan(
        db_session, tenant_a.id, device_id="dev-1", created_at=t0 + timedelta(hours=2), status="failed",
    )
    current = _make_scan(db_session, tenant_a.id, device_id="dev-1", created_at=t0 + timedelta(hours=3))

    prev = report_diff_service.find_previous_scan(db_session, current, tenant_a.id)

    assert prev is not None
    assert prev.id == older_same_device.id
    assert prev.id != failed_same_device.id
