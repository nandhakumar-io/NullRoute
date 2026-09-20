"""Per-stage deployment tracking (where exactly did it stop?) and the
human-in-the-loop approval policy (binding, override, four-eyes, expiry)."""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models.db import Base, ChangeRequest, Device
from app.services import change_request_service as crs
from app.services import config_merge, deployment_service, rollback_service
from app.services.collectors.base import CollectionResult
from app.services.deployment.base import DeploymentResult
from app.services.openbao_service import DeviceCredentials

CUR = "hostname r1\nip ssh version 1\ninterface Gi0/1\n shutdown\nntp server 1.1.1.1\n"
PROPOSED = CUR.replace("version 1", "version 2")
CUR_HASH = config_merge.config_hash(CUR)


@pytest.fixture
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/t.db", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


def _cr(db, **kw):
    dev = Device(tenant_id="t1", hostname="r1", vendor="cisco", management_address="10.0.0.1")
    db.add(dev)
    db.commit()
    base = dict(tenant_id="t1", device_id=dev.id, status="APPROVED", current_config_hash=CUR_HASH,
                proposed_config_hash=config_merge.config_hash(PROPOSED), proposed_config_object_key="k",
                current_config_object_key="cur", merge_commands=["ip ssh version 2"], created_by="alice")
    base.update(kw)
    cr = ChangeRequest(**base)
    db.add(cr)
    db.commit()
    return dev, cr


def _wire(monkeypatch, *, collect_fn=None, push_result=None):
    monkeypatch.setattr(deployment_service, "_resolve_credentials",
                        lambda *a, **k: DeviceCredentials(credential_type="ssh_password",
                                                          secret={"username": "u", "password": "p"}))
    monkeypatch.setattr(deployment_service.minio_service, "get_object", lambda k: PROPOSED.encode())
    n = {"i": 0}

    def default_collect(device, creds):
        n["i"] += 1
        raw = CUR if n["i"] == 1 else PROPOSED
        return CollectionResult(success=True, raw_config=raw, config_hash=config_merge.config_hash(raw))

    collect = collect_fn or default_collect
    monkeypatch.setattr(deployment_service, "get_collector",
                        lambda vendor, transport=None: type("C", (), {"collect_config": staticmethod(collect)})())
    monkeypatch.setattr(
        deployment_service, "get_deployer",
        lambda t: type("D", (), {
            "push_config": staticmethod(lambda d, c, lines: push_result or DeploymentResult(success=True, transport="ssh")),
            "confirm_commit": staticmethod(lambda d, c: DeploymentResult(success=True)),
        })(),
    )

    async def fake_pipeline(db_, scan, raw, framework="ALL"):
        scan.status = "completed"
        scan.opa_decision, scan.batfish_status = "PASS", "BATFISH_PASS"
        scan.risk_level, scan.final_decision = "LOW", "PASS"
        db_.commit()
        return scan
    monkeypatch.setattr(deployment_service, "run_pipeline", fake_pipeline)

    async def no_alert(*a, **k):
        return None  # alert channels would otherwise attempt real network calls
    for name in ("alert_collection_failure", "alert_rollback_required", "alert_rollback_failed"):
        monkeypatch.setattr(deployment_service.alert_service, name, no_alert)

    async def fake_diff(device, before, after, dr_id):
        return {"status": "BATFISH_PASS", "summary": "No behavioural difference detected.", "detail": {"status": "BATFISH_PASS"}}
    monkeypatch.setattr(deployment_service, "_batfish_before_after", fake_diff)


def _by_key(d):
    return {s["key"]: s for s in d["stages"]}


# ------------------------------------------------------------------ stages --
@pytest.mark.asyncio
async def test_success_marks_every_stage_passed(db, monkeypatch):
    _, cr = _cr(db)
    _wire(monkeypatch)
    dr = await deployment_service.deploy_change_request(db, cr, "op", transport="ssh")
    d = deployment_service.to_dict(dr)
    assert dr.status == "VERIFIED" and dr.started_at is not None
    assert [s["status"] for s in d["stages"]] == ["passed"] * 7
    assert d["failed_stage"] is None and d["stages_derived"] is False
    assert dr.batfish_diff_status == "BATFISH_PASS"
    full = deployment_service.to_dict_full(db, dr)
    assert full["post_validation"]["final_decision"] == "PASS"
    assert full["post_validation"]["batfish_diff_status"] == "BATFISH_PASS"


@pytest.mark.asyncio
async def test_unreachable_device_fails_at_connect_and_skips_the_rest(db, monkeypatch):
    _, cr = _cr(db)
    _wire(monkeypatch, collect_fn=lambda d, c: CollectionResult(success=False, error="Connection timed out: 10.0.0.1:22"))
    dr = await deployment_service.deploy_change_request(db, cr, "op", transport="ssh")
    d = deployment_service.to_dict(dr)
    st = _by_key(d)
    assert dr.status == "FAILED" and d["failed_stage"] == "connect" and d["failure_kind"] == "connection"
    assert st["credentials"]["status"] == "passed"
    assert all(st[k]["status"] == "skipped" for k in ("precheck", "plan", "commit", "verify", "postval"))


@pytest.mark.asyncio
async def test_stale_hash_fails_at_precheck(db, monkeypatch):
    _, cr = _cr(db, current_config_hash="0" * 64)
    _wire(monkeypatch)
    dr = await deployment_service.deploy_change_request(db, cr, "op", transport="ssh")
    d = deployment_service.to_dict(dr)
    assert dr.status == "ABORTED_STALE_HASH" and d["failed_stage"] == "precheck" and d["failure_kind"] == "stale_hash"
    assert _by_key(d)["connect"]["status"] == "passed"


@pytest.mark.asyncio
async def test_rejected_commit_fails_at_commit_with_kind(db, monkeypatch):
    _, cr = _cr(db)
    _wire(monkeypatch, push_result=DeploymentResult(success=False, transport="ssh", error="% Invalid input detected at '^' marker"))
    dr = await deployment_service.deploy_change_request(db, cr, "op", transport="ssh")
    d = deployment_service.to_dict(dr)
    assert d["failed_stage"] == "commit" and d["failure_kind"] == "commit_rejected"
    assert _by_key(d)["plan"]["status"] == "passed" and _by_key(d)["verify"]["status"] == "skipped"


@pytest.mark.asyncio
async def test_auth_failure_during_push_is_classified(db, monkeypatch):
    _, cr = _cr(db)
    _wire(monkeypatch, push_result=DeploymentResult(success=False, transport="ssh", error="Authentication failed: bad password"))
    dr = await deployment_service.deploy_change_request(db, cr, "op", transport="ssh")
    d = deployment_service.to_dict(dr)
    assert d["failed_stage"] == "commit" and d["failure_kind"] == "authentication"


@pytest.mark.asyncio
async def test_drift_fails_verify_but_postval_still_runs(db, monkeypatch):
    _, cr = _cr(db)
    n = {"i": 0}

    def collect(device, creds):
        n["i"] += 1
        raw = CUR if n["i"] == 1 else PROPOSED + "rogue-line\n"
        return CollectionResult(success=True, raw_config=raw, config_hash=config_merge.config_hash(raw))

    _wire(monkeypatch, collect_fn=collect)
    dr = await deployment_service.deploy_change_request(db, cr, "op", transport="ssh")
    d = deployment_service.to_dict(dr)
    st = _by_key(d)
    assert dr.status == "DRIFTED" and d["failed_stage"] == "verify" and d["failure_kind"] == "verification_mismatch"
    assert st["commit"]["status"] == "passed" and st["postval"]["status"] == "passed"  # evidence still gathered
    assert d["rollback_recommended"] is True


@pytest.mark.asyncio
async def test_crash_mid_deploy_is_recorded_not_left_deploying(db, monkeypatch):
    _, cr = _cr(db)
    _wire(monkeypatch)

    async def boom(*a, **k):
        raise RuntimeError("pipeline exploded")
    monkeypatch.setattr(deployment_service, "run_pipeline", boom)
    dr = await deployment_service.deploy_change_request(db, cr, "op", transport="ssh")
    d = deployment_service.to_dict(dr)
    assert dr.status == "FAILED" and d["failed_stage"] == "postval" and d["failure_kind"] == "internal"
    assert "pipeline exploded" in dr.error


def test_legacy_record_without_stages_gets_derived_stages(db):
    from app.models.db import DeploymentRecord
    _, cr = _cr(db)
    dr = DeploymentRecord(tenant_id="t1", change_request_id=cr.id, device_id=cr.device_id, status="FAILED",
                          error="Deployment push failed: Connection timed out: x")
    db.add(dr)
    db.commit()
    d = deployment_service.to_dict(dr)
    assert d["stages_derived"] is True and d["failed_stage"] == "commit" and d["failure_kind"] == "connection"


@pytest.mark.asyncio
async def test_rollback_records_stages(db, monkeypatch):
    dev, cr = _cr(db)
    _wire(monkeypatch)
    dr = await deployment_service.deploy_change_request(db, cr, "op", transport="ssh")

    monkeypatch.setattr(rollback_service, "_resolve_credentials",
                        lambda *a, **k: DeviceCredentials(credential_type="ssh_password", secret={"username": "u", "password": "p"}))
    monkeypatch.setattr(rollback_service.minio_service, "get_object", lambda k: CUR.encode())
    n = {"i": 0}

    def collect(device, creds):
        n["i"] += 1
        raw = PROPOSED if n["i"] == 1 else CUR
        return CollectionResult(success=True, raw_config=raw, config_hash=config_merge.config_hash(raw))
    monkeypatch.setattr(rollback_service, "get_collector",
                        lambda vendor, transport=None: type("C", (), {"collect_config": staticmethod(collect)})())
    monkeypatch.setattr(rollback_service, "get_deployer",
                        lambda t: type("D", (), {"push_config": staticmethod(lambda d, c, l: DeploymentResult(success=True, transport="ssh")),
                                                 "confirm_commit": staticmethod(lambda d, c: DeploymentResult(success=True))})())

    async def fake_pipeline(db_, scan, raw, framework="ALL"):
        scan.status, scan.final_decision, scan.opa_decision = "completed", "PASS", "PASS"
        db_.commit()
        return scan
    monkeypatch.setattr(rollback_service, "run_pipeline", fake_pipeline)

    async def noop(*a, **k):
        return None
    monkeypatch.setattr(rollback_service, "_anchor_rollback_event", noop)
    rb = await rollback_service.rollback_deployment(db, dr, "op", reason="manual revert")
    d = rollback_service.to_dict(rb)
    assert rb.status == "VERIFIED"
    assert [s["status"] for s in d["stages"]] == ["passed"] * 6 and d["failed_stage"] is None
    assert deployment_service.to_dict_full(db, dr)["rollbacks"][0]["id"] == rb.id


# -------------------------------------------------------------------- HITL --
def _pending(db, **kw):
    kw.setdefault("status", "PENDING_APPROVAL")
    kw.setdefault("final_decision", "PASS")
    kw.setdefault("risk_level", "LOW")
    return _cr(db, **kw)[1]


def test_plain_approval_records_binding_and_event(db):
    cr = _pending(db)
    crs.approve(db, cr, "bob", expected_revision=1, expected_hash=cr.proposed_config_hash)
    assert cr.status == "APPROVED" and cr.approved_revision == 1 and cr.approved_hash == cr.proposed_config_hash
    assert [e["action"] for e in cr.review_events] == ["approved"]


def test_stale_revision_cannot_be_approved(db):
    cr = _pending(db, revision=3)
    with pytest.raises(crs.HitlError) as ei:
        crs.approve(db, cr, "bob", expected_revision=2)
    assert ei.value.code == "stale_revision" and ei.value.http_status == 409
    assert cr.status == "PENDING_APPROVAL"


def test_blocked_change_needs_a_written_override(db):
    cr = _pending(db, final_decision="BLOCK", risk_level="HIGH")
    with pytest.raises(crs.HitlError) as ei:
        crs.approve(db, cr, "bob", comment="ok")
    assert ei.value.code == "note_required" and ei.value.http_status == 422
    crs.approve(db, cr, "bob", comment="Guest VLAN is being decommissioned, risk accepted (CHG-4411).")
    assert cr.status == "APPROVED" and "CHG-4411" in cr.override_justification
    assert cr.review_events[-1]["action"] == "override_approved"


def test_review_verdict_needs_note_but_pass_does_not(db):
    with pytest.raises(crs.HitlError):
        crs.approve(db, _pending(db, final_decision="REVIEW"), "bob")
    crs.approve(db, _pending(db), "bob")  # PASS/LOW: no note demanded


def test_four_eyes_blocks_self_approval_of_risky_change(db, monkeypatch):
    monkeypatch.setattr(crs, "_auth_enforced", lambda: True)
    cr = _pending(db, final_decision="REVIEW", risk_level="HIGH", created_by="alice")
    with pytest.raises(crs.HitlError) as ei:
        crs.approve(db, cr, "alice", comment="I know what I'm doing here, honest.")
    assert ei.value.code == "four_eyes" and ei.value.http_status == 403
    crs.approve(db, cr, "bob", comment="Reviewed the diff and the Batfish delta.")
    assert cr.approved_by == "bob"


def test_four_eyes_not_applied_to_low_risk_or_demo_mode(db, monkeypatch):
    monkeypatch.setattr(crs, "_auth_enforced", lambda: True)
    crs.approve(db, _pending(db, created_by="alice"), "alice")  # low risk: allowed
    monkeypatch.setattr(crs, "_auth_enforced", lambda: False)
    risky = _pending(db, final_decision="REVIEW", risk_level="HIGH", created_by="alice")
    crs.approve(db, risky, "alice", comment="Demo mode has a single implicit user.")


def test_four_eyes_always_mode(db, monkeypatch):
    monkeypatch.setattr(crs, "_auth_enforced", lambda: True)
    monkeypatch.setenv("HITL_FOUR_EYES", "always")
    with pytest.raises(crs.HitlError):
        crs.approve(db, _pending(db, created_by="alice"), "alice")


def test_reject_requires_a_reason_and_clears_binding(db):
    cr = _pending(db)
    with pytest.raises(crs.HitlError) as ei:
        crs.reject(db, cr, "bob", reason="  ")
    assert ei.value.code == "reason_required"
    crs.reject(db, cr, "bob", reason="Out of change window")
    assert cr.status == "REJECTED" and cr.rejection_reason == "Out of change window"
    assert cr.review_events[-1]["action"] == "rejected"


def test_approval_no_longer_valid_after_edit_or_expiry(db, monkeypatch):
    cr = _pending(db)
    crs.approve(db, cr, "bob")
    assert crs.approval_still_valid(cr) is None
    cr.proposed_config_hash = "changed-behind-the-approval"
    assert "no longer applies" in crs.approval_still_valid(cr)
    cr.proposed_config_hash = cr.approved_hash
    monkeypatch.setenv("HITL_APPROVAL_TTL_HOURS", "1")
    cr.approved_at = datetime.utcnow() - timedelta(hours=2)
    assert "expired" in crs.approval_still_valid(cr)


@pytest.mark.asyncio
async def test_deploy_refuses_when_approval_is_stale(db, monkeypatch):
    _, cr = _cr(db, approved_hash="something-else", approved_revision=1)
    _wire(monkeypatch)
    with pytest.raises(ValueError, match="no longer applies"):
        await deployment_service.deploy_change_request(db, cr, "op", transport="ssh")
