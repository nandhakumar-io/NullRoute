"""Enterprise Network Scan UI pass -- execute_scan_job stage orchestration.

Stubs the three real backend calls execute_scan_job makes (nmap discovery,
credential/collector resolution, and the compliance pipeline -- each
already covered by their own dedicated tests elsewhere) so these tests
assert the ORCHESTRATION contract: real stage transitions, no fabricated
progress, one device's failure doesn't sink the job, and a job with
nothing to target skips (never fakes) the downstream stages.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.models.db import Device, NetworkScanJob, Scan, Tenant
from app.services import network_scan_service
from app.services.collectors.base import CollectionResult


@pytest.fixture
def db_session(tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.models.db import Base

    engine = create_engine(f"sqlite:///{tmp_path}/svc.db", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()
    yield db
    db.close()


def _tenant(db):
    t = Tenant(name="T1")
    db.add(t)
    db.commit()
    db.refresh(t)
    return t


def _device(db, tenant_id, **kwargs):
    d = Device(tenant_id=tenant_id, hostname=kwargs.pop("hostname", "sw1"), vendor=kwargs.pop("vendor", "cisco"), **kwargs)
    db.add(d)
    db.commit()
    db.refresh(d)
    return d


def _job(db, tenant_id, **kwargs):
    job = NetworkScanJob(
        tenant_id=tenant_id, status="PENDING", stages=network_scan_service.init_stages(), **kwargs
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def _patch_collection_chain(monkeypatch, *, collection_result, pipeline_side_effect=None):
    """Patches the three call sites execute_scan_job uses at module level:
    network_scan_service._resolve_credentials, get_collector, and run_pipeline."""
    import app.services.network_scan_service as svc
    import app.services.collectors.registry as registry
    import app.services.pipeline as pipeline

    monkeypatch.setattr(svc, "_resolve_credentials", lambda db, device, tenant_id, credential_ref_id=None: type("Creds", (), {"secret": {}})())
    monkeypatch.setattr(svc, "get_collector", lambda vendor, transport=None: SimpleNamespace(
        collect_config=lambda device, creds: collection_result
    ))
    monkeypatch.setattr(svc, "preferred_transport", lambda vendor: "ssh")

    async def _fake_pipeline(db, scan, raw_text, framework="ALL"):
        if pipeline_side_effect:
            pipeline_side_effect(scan)
        scan.status = "completed"
        scan.final_decision = "PASS"
        scan.compliance_score = 91.0
        scan.risk_level = "LOW"
        db.commit()
        return scan

    monkeypatch.setattr(pipeline, "run_pipeline", _fake_pipeline)


@pytest.mark.asyncio
async def test_job_with_no_targets_skips_downstream_stages(db_session):
    tenant = _tenant(db_session)
    job = _job(db_session, tenant.id, requested_device_ids=[], run_discovery=False, framework="ALL")

    await network_scan_service.execute_scan_job(db_session, job)

    assert job.stages["discovery"]["status"] == "SKIPPED"
    assert job.stages["device_identification"]["status"] == "DONE"
    for stage in ("configuration", "normalization", "compliance", "risk_analysis", "report"):
        assert job.stages[stage]["status"] == "SKIPPED"
    assert job.status == "FAILED"


@pytest.mark.asyncio
async def test_successful_scan_of_explicit_devices_completes_all_stages(db_session, monkeypatch):
    tenant = _tenant(db_session)
    device = _device(db_session, tenant.id, hostname="core-rtr-01", management_address="10.0.0.1")
    job = _job(
        db_session, tenant.id, requested_device_ids=[device.id], run_discovery=False, framework="ALL",
    )

    _patch_collection_chain(
        monkeypatch,
        collection_result=CollectionResult(success=True, raw_config="hostname core-rtr-01\n", transport="ssh"),
    )

    await network_scan_service.execute_scan_job(db_session, job)

    assert job.status == "COMPLETED"
    assert job.stages["device_identification"]["status"] == "DONE"
    assert job.stages["configuration"]["status"] == "DONE"
    assert job.stages["compliance"]["status"] == "DONE"
    assert job.resolved_device_ids == [device.id]
    assert len(job.scan_ids) == 1
    assert job.device_results[0]["success"] is True
    assert job.device_results[0]["final_decision"] == "PASS"

    persisted_scan = db_session.query(Scan).filter(Scan.id == job.scan_ids[0]).first()
    assert persisted_scan is not None
    assert persisted_scan.device_id == device.id


@pytest.mark.asyncio
async def test_device_collection_failure_marks_job_failed_but_does_not_crash(db_session, monkeypatch):
    tenant = _tenant(db_session)
    device = _device(db_session, tenant.id, hostname="unreachable-fw", management_address="10.0.0.9")
    job = _job(db_session, tenant.id, requested_device_ids=[device.id], run_discovery=False, framework="ALL")

    _patch_collection_chain(
        monkeypatch,
        collection_result=CollectionResult(success=False, error="connection timed out"),
    )

    await network_scan_service.execute_scan_job(db_session, job)

    assert job.status == "FAILED"
    assert job.device_results[0]["success"] is False
    assert "timed out" in job.device_results[0]["error"]
    for stage in ("normalization", "compliance", "risk_analysis", "report"):
        assert job.stages[stage]["status"] == "SKIPPED"


@pytest.mark.asyncio
async def test_discovery_matches_known_device_by_management_address(db_session, monkeypatch):
    tenant = _tenant(db_session)
    device = _device(db_session, tenant.id, hostname="sw-known", management_address="10.10.0.5")
    job = _job(
        db_session, tenant.id, requested_device_ids=[], run_discovery=True,
        target_cidr="10.10.0.0/24", framework="ALL",
    )

    fake_host = SimpleNamespace(to_dict=lambda: {
        "ip": "10.10.0.5", "hostname": "sw-known", "vendor_guess": "Cisco",
        "transport_hints": ["ssh"], "banner": None,
    })
    monkeypatch.setattr(
        network_scan_service.network_discovery, "scan_network",
        lambda cidr, ports=None, service_detection=True: [fake_host],
    )
    _patch_collection_chain(
        monkeypatch,
        collection_result=CollectionResult(success=True, raw_config="hostname sw-known\n", transport="ssh"),
    )

    await network_scan_service.execute_scan_job(db_session, job)

    assert job.stages["discovery"]["status"] == "DONE"
    assert job.resolved_device_ids == [device.id]
    assert job.status == "COMPLETED"


@pytest.mark.asyncio
async def test_discovery_failure_does_not_abort_explicit_device_targets(db_session, monkeypatch):
    tenant = _tenant(db_session)
    device = _device(db_session, tenant.id, hostname="explicit-target", management_address="10.20.0.1")
    job = _job(
        db_session, tenant.id, requested_device_ids=[device.id], run_discovery=True,
        target_cidr="10.20.0.0/24", framework="ALL",
    )

    def _boom(cidr, ports=None, service_detection=True):
        raise network_scan_service.network_discovery.NmapUnavailableError("nmap not installed")

    monkeypatch.setattr(network_scan_service.network_discovery, "scan_network", _boom)
    _patch_collection_chain(
        monkeypatch,
        collection_result=CollectionResult(success=True, raw_config="hostname explicit-target\n", transport="ssh"),
    )

    await network_scan_service.execute_scan_job(db_session, job)

    assert job.stages["discovery"]["status"] == "FAILED"
    assert job.resolved_device_ids == [device.id]
    assert job.status == "COMPLETED"
