"""Delta-only deployment, admin proposal edits, compliance-score thresholds,
audit-log null tolerance and VAPID loading."""
from __future__ import annotations

import hashlib

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models.alerting import AlertChannel, ComplianceAlertThreshold
from app.models.db import AuditLog, Base, ChangeRequest, Device, DeploymentRecord, Scan
from app.schemas import AuditLogOut
from app.services import alert_channel_service, alert_service, change_request_service, config_merge, deployment_service
from app.services.collectors.base import CollectionResult
from app.services.deployment.base import DeploymentResult
from app.services.openbao_service import DeviceCredentials


@pytest.fixture
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/t.db", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


# ---------------------------------------------------------------- audit log --
def test_audit_log_row_with_null_resource_serializes(db):
    row = AuditLog(actor=None, action="audit_log.export", resource=None, object_type="audit_log", result="SUCCESS")
    db.add(row)
    db.commit()
    out = AuditLogOut.model_validate(row)
    assert out.resource is None and out.action == "audit_log.export"


# -------------------------------------------------------------- delta engine --
FULL_IOS = "hostname r1\nip ssh version 1\ninterface Gi0/1\n shutdown\nline vty 0 4\n transport input telnet\n" \
           "ip domain-name x\nlogging host 9.9.9.9\nntp server 1.1.1.1\n"


def test_delta_never_contains_unchanged_lines():
    new = FULL_IOS.replace("version 1", "version 2")
    plan = config_merge.delta_between(FULL_IOS, new, "cisco")
    assert plan.safe and plan.commands == ["ip ssh version 2"]


def test_resolve_prefers_merge_commands_then_snippet_then_diff():
    assert config_merge.resolve_deploy_commands(["a"], "x", "y", "cisco").commands == ["a"]
    p = config_merge.resolve_deploy_commands(None, None, "! c\nset system services password-encryption enable\ncommit\nwrite memory", "juniper")
    assert p.commands == ["set system services password-encryption enable"]  # 4-line legacy CR -> delta only
    assert config_merge.resolve_deploy_commands(None, "", FULL_IOS, "fortigate").safe is False


# --------------------------------------------------------------- deployment --
CUR = FULL_IOS
CUR_HASH = config_merge.config_hash(CUR)


def _scenario(db, merge_commands, proposed, vendor="cisco"):
    dev = Device(tenant_id="t1", hostname="r1", vendor=vendor, management_address="10.0.0.1")
    db.add(dev)
    db.commit()
    cr = ChangeRequest(tenant_id="t1", device_id=dev.id, status="APPROVED", current_config_hash=CUR_HASH,
                       proposed_config_hash=config_merge.config_hash(proposed), proposed_config_object_key="k",
                       merge_commands=merge_commands)
    db.add(cr)
    db.commit()
    return dev, cr


def _patch_deploy(monkeypatch, pushed, post_raw):
    monkeypatch.setattr(deployment_service, "_resolve_credentials",
                        lambda *a, **k: DeviceCredentials(credential_type="ssh_password", secret={"username": "u", "password": "p"}))
    monkeypatch.setattr(deployment_service.minio_service, "get_object", lambda k: PROPOSED.encode())
    calls = {"n": 0}

    def collect(device, creds):
        calls["n"] += 1
        raw = CUR if calls["n"] == 1 else post_raw
        return CollectionResult(success=True, raw_config=raw, config_hash=config_merge.config_hash(raw))
    monkeypatch.setattr(deployment_service, "get_collector",
                        lambda vendor, transport=None: type("C", (), {"collect_config": staticmethod(collect)})())

    def push(device, creds, lines):
        pushed.append(list(lines))
        return DeploymentResult(success=True, transport="ssh")
    monkeypatch.setattr(deployment_service, "get_deployer",
                        lambda t: type("D", (), {"push_config": staticmethod(push),
                                                 "confirm_commit": staticmethod(lambda d, c: DeploymentResult(success=True))})())

    async def fake_pipeline(db_, scan, raw, framework="ALL"):
        scan.status = "completed"
        return scan
    monkeypatch.setattr(deployment_service, "run_pipeline", fake_pipeline)


PROPOSED = CUR.replace("version 1", "version 2")


@pytest.mark.asyncio
async def test_deploy_pushes_only_delta_not_full_config(db, monkeypatch):
    dev, cr = _scenario(db, ["ip ssh version 2"], PROPOSED)
    pushed = []
    _patch_deploy(monkeypatch, pushed, PROPOSED)
    dr = await deployment_service.deploy_change_request(db, cr, "admin", transport="ssh", target_control_ids=["X-1"])
    assert pushed == [["ip ssh version 2"]]
    assert dr.status == "VERIFIED"


@pytest.mark.asyncio
async def test_deploy_reordered_but_identical_content_is_verified(db, monkeypatch):
    dev, cr = _scenario(db, ["ip ssh version 2"], PROPOSED)
    pushed = []
    lines = PROPOSED.strip().split("\n")
    _patch_deploy(monkeypatch, pushed, "\n".join(reversed(lines)) + "\n")
    dr = await deployment_service.deploy_change_request(db, cr, "admin", transport="ssh")
    assert dr.status == "VERIFIED"


@pytest.mark.asyncio
async def test_deploy_extra_unexpected_line_is_drift(db, monkeypatch):
    dev, cr = _scenario(db, ["ip ssh version 2"], PROPOSED)
    pushed = []
    _patch_deploy(monkeypatch, pushed, PROPOSED + "some-unapproved-line\n")
    dr = await deployment_service.deploy_change_request(db, cr, "admin", transport="ssh")
    assert dr.status == "DRIFTED"


@pytest.mark.asyncio
async def test_deploy_refuses_when_no_safe_delta(db, monkeypatch):
    cfg = "config system global\n set hostname f1\nend\n" + "config system interface\n edit port1\n next\nend\n" * 4
    dev, cr = _scenario(db, None, cfg + "\nversion 7", vendor="fortigate")
    pushed = []
    _patch_deploy(monkeypatch, pushed, cfg)
    monkeypatch.setattr(deployment_service.minio_service, "get_object", lambda k: (cfg + "\nhostname zz\n").encode())
    dr = await deployment_service.deploy_change_request(db, cr, "admin", transport="ssh")
    assert pushed == [] and dr.status == "FAILED" and "Refusing to deploy" in dr.error


# ------------------------------------------------------------ proposal edit --
@pytest.mark.asyncio
async def test_update_proposal_remerges_resets_approval_and_bumps_revision(db, monkeypatch):
    dev = Device(tenant_id="t1", hostname="r1", vendor="cisco", management_address="10.0.0.1")
    db.add(dev)
    db.commit()
    store = {"cur": CUR.encode()}
    monkeypatch.setattr(change_request_service.minio_service, "get_object", lambda k: store["cur"])
    monkeypatch.setattr(change_request_service.minio_service, "put_object",
                        lambda k, b, content_type=None: type("P", (), {"object_key": k})())
    seen = {}

    async def fake_validate(db_, cr, device, proposed, current):
        seen["proposed"] = proposed
        cr.status = "PENDING_APPROVAL"
    monkeypatch.setattr(change_request_service, "_validate", fake_validate)

    cr = ChangeRequest(tenant_id="t1", device_id=dev.id, status="APPROVED", approved_by="a",
                       current_config_object_key="cur", current_config_hash=CUR_HASH, proposed_config_hash="x")
    db.add(cr)
    db.commit()
    cr = await change_request_service.update_proposal(db, cr, dev, "admin1", snippet="ip ssh version 2\nwrite memory")
    assert cr.status == "PENDING_APPROVAL" and cr.approved_by is None
    assert cr.revision == 2 and cr.edited_by == "admin1"
    assert cr.merge_commands == ["ip ssh version 2"]
    assert "ip ssh version 2" in seen["proposed"] and "hostname r1" in seen["proposed"]  # merged, not replaced

    cr.status = "DEPLOYED"
    with pytest.raises(ValueError):
        await change_request_service.update_proposal(db, cr, dev, "admin1", snippet="x")


@pytest.mark.asyncio
async def test_legacy_snippet_as_proposed_config_is_treated_as_delta(db, monkeypatch):
    dev = Device(tenant_id="t1", hostname="r1", vendor="cisco", management_address="10.0.0.1")
    db.add(dev)
    db.commit()
    monkeypatch.setattr(change_request_service.minio_service, "put_object", lambda *a, **k: None)

    async def fake_validate(db_, cr, device, proposed, current):
        cr.status = "PENDING_APPROVAL"
    monkeypatch.setattr(change_request_service, "_validate", fake_validate)
    cr = await change_request_service.create_and_validate(
        db, tenant_id="t1", device=dev, proposed_config="ip ssh version 2", current_config=CUR)
    assert cr.snippet == "ip ssh version 2" and cr.merge_commands == ["ip ssh version 2"]


# --------------------------------------------------------------- thresholds --
async def _threshold_env(db, monkeypatch):
    dev = Device(tenant_id="t1", hostname="core1", vendor="cisco", management_address="10.0.0.1")
    db.add(dev)
    db.commit()
    routed = []

    async def fake_dispatch(alert):
        return {}

    async def fake_route(db_, alert, extra_channel_ids=None):
        routed.append(list(extra_channel_ids or []))
        return {}
    monkeypatch.setattr(alert_service, "_dispatch", fake_dispatch)
    monkeypatch.setattr(alert_channel_service, "route_and_dispatch", fake_route)
    return dev, routed


def _scan(db, dev, score, when=None):
    from datetime import datetime, timedelta
    s = Scan(tenant_id="t1", device_id=dev.id, framework="CIS", status="completed", compliance_score=score,
             created_at=when or datetime.utcnow())
    db.add(s)
    db.commit()
    return s


@pytest.mark.asyncio
async def test_threshold_fires_below_and_routes_to_selected_channels(db, monkeypatch):
    dev, routed = await _threshold_env(db, monkeypatch)
    db.add(ComplianceAlertThreshold(tenant_id="t1", name="min80", threshold=80, severity="HIGH", channel_ids=["ch1"]))
    db.commit()
    alerts = await alert_service.evaluate_compliance_thresholds(db, _scan(db, dev, 72.5))
    assert len(alerts) == 1 and alerts[0].category == "COMPLIANCE_SCORE_LOW" and alerts[0].severity == "HIGH"
    assert routed == [["ch1"]]
    assert await alert_service.evaluate_compliance_thresholds(db, _scan(db, dev, 80.0)) == []  # not below


@pytest.mark.asyncio
async def test_threshold_scope_and_only_on_crossing(db, monkeypatch):
    from datetime import datetime, timedelta
    dev, routed = await _threshold_env(db, monkeypatch)
    db.add(ComplianceAlertThreshold(tenant_id="t1", name="other-dev", threshold=90, device_id="nope"))
    db.add(ComplianceAlertThreshold(tenant_id="t1", name="cross", threshold=80, only_on_crossing=True))
    db.commit()
    t0 = datetime.utcnow() - timedelta(hours=3)
    _scan(db, dev, 95, t0)
    first_low = _scan(db, dev, 60, t0 + timedelta(hours=1))
    second_low = _scan(db, dev, 55, t0 + timedelta(hours=2))
    assert len(await alert_service.evaluate_compliance_thresholds(db, first_low)) == 1   # crossed
    assert await alert_service.evaluate_compliance_thresholds(db, second_low) == []      # still low


# --------------------------------------------------------------------- vapid --
def test_vapid_public_key_is_derived_and_path_error_is_clear(monkeypatch):
    import base64
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    k = ec.generate_private_key(ec.SECP256R1())
    raw = base64.urlsafe_b64encode(k.private_numbers().private_value.to_bytes(32, "big")).rstrip(b"=").decode()
    pub = base64.urlsafe_b64encode(k.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)).rstrip(b"=").decode()
    alert_channel_service._VAPID_CACHE.clear()
    monkeypatch.setenv("VAPID_PRIVATE_KEY", raw)
    monkeypatch.setenv("VAPID_PUBLIC_KEY", "stale-mismatched-key")
    assert alert_channel_service.get_vapid_public_key() == pub
    monkeypatch.setenv("VAPID_PRIVATE_KEY", "/home/someone/private_key.pem")
    with pytest.raises(alert_channel_service.ChannelError, match="does not exist inside this container"):
        alert_channel_service._load_vapid()
    assert alert_channel_service.get_vapid_public_key() is None
