"""Enterprise "Network Scan" orchestration (Discovery + Network Scan UI pass).

Ties together capabilities that already exist as separate primitives --
`services/network_discovery.scan_network`, the device collector registry,
and `services/pipeline.run_pipeline` (the SAME pipeline `/api/devices/{id}
/scan` and scheduled audits use -- RULE 11: no second compliance
implementation) -- into one auditable, multi-stage job:

    discovery -> device_identification -> configuration -> normalization
    -> compliance -> risk_analysis -> report

Like `services/scheduling_service.execute_schedule`, `execute_scan_job()`
is only ever called from the background worker
(app/workers/network_scan_worker.py) or tests, never from inside a FastAPI
request handler -- device collection and Batfish/OPA evaluation can take
long enough that running them synchronously in a request would block the
API for other tenants.

Progress reporting is real, not simulated: `stages[...]` is only updated
once that unit of work has actually executed against the real backend
(nmap subprocess, SSH/NETCONF/etc. collector, or the compliance pipeline),
and per-device configuration/normalization/compliance progress is derived
by polling the same `Scan.status` values the pipeline itself sets
(parsed/normalized/opa_evaluating/batfish_evaluating/completed/...), so two
concurrent viewers of the same job see the same real state.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import anyio
from sqlalchemy.orm import Session

from app.models.db import Device, NetworkScanJob, Scan
from app.services import network_discovery
from app.services.deployment_service import _resolve_credentials
from app.services.collectors.registry import get_collector, preferred_transport
from app.services.pipeline import run_pipeline

logger = logging.getLogger("network_scan_service")

STAGES = (
    "discovery",
    "device_identification",
    "configuration",
    "normalization",
    "compliance",
    "risk_analysis",
    "report",
)


def init_stages() -> Dict[str, Dict[str, Any]]:
    return {name: {"status": "PENDING", "detail": None} for name in STAGES}


def _set_stage(job: NetworkScanJob, db: Session, name: str, status: str, detail: Optional[str] = None) -> None:
    stages = dict(job.stages or {})
    stages[name] = {"status": status, "detail": detail}
    job.stages = stages
    job.updated_at = datetime.utcnow()
    db.commit()


async def execute_scan_job(db: Session, job: NetworkScanJob) -> None:
    """Runs every stage of `job` against the real backend, committing
    updated status after each real unit of work so GET /api/network-scans
    /{id} always reflects genuine progress."""
    job.status = "RUNNING"
    job.started_at = datetime.utcnow()
    job.stages = init_stages()
    db.commit()

    resolved_device_ids: List[str] = list(job.requested_device_ids or [])

    # ---- Stage 1: discovery -------------------------------------------
    if job.run_discovery and job.target_cidr:
        _set_stage(job, db, "discovery", "RUNNING", f"Scanning {job.target_cidr}")
        try:
            hosts = await anyio.to_thread.run_sync(
                lambda: network_discovery.scan_network(
                    job.target_cidr,
                    ports=job.discovery_ports or network_discovery.DEFAULT_PORTS,
                    service_detection=True,
                )
            )
            job.discovered_hosts = [h.to_dict() for h in hosts]
            db.commit()
            _set_stage(job, db, "discovery", "DONE", f"{len(hosts)} host(s) responded")
        except Exception as e:  # noqa: BLE001 - nmap missing/unreachable/etc.
            _set_stage(job, db, "discovery", "FAILED", str(e))
            job.discovered_hosts = []
            db.commit()
            # Discovery failing doesn't abort a job that also has explicit
            # device_ids to scan -- only skip the stages that depended on it.
    else:
        _set_stage(job, db, "discovery", "SKIPPED", "No discovery requested")

    # ---- Stage 2: device identification --------------------------------
    _set_stage(job, db, "device_identification", "RUNNING")
    known_by_ip = {
        d.management_address: d
        for d in db.query(Device).filter(Device.tenant_id == job.tenant_id).all()
        if d.management_address
    }
    matched_from_discovery = 0
    if job.discovered_hosts:
        for h in job.discovered_hosts:
            existing = known_by_ip.get(h.get("ip"))
            if existing and existing.id not in resolved_device_ids:
                resolved_device_ids.append(existing.id)
                matched_from_discovery += 1
    # De-dupe while preserving order, and drop anything not in this tenant.
    tenant_device_ids = {
        d.id for d in db.query(Device.id).filter(Device.tenant_id == job.tenant_id,
                                                   Device.id.in_(resolved_device_ids)).all()
    } if resolved_device_ids else set()
    resolved_device_ids = [d for d in dict.fromkeys(resolved_device_ids) if d in tenant_device_ids]
    job.resolved_device_ids = resolved_device_ids
    db.commit()
    _set_stage(
        job, db, "device_identification", "DONE",
        f"{len(resolved_device_ids)} known device(s) targeted "
        f"({matched_from_discovery} matched from discovery)"
        + ("" if resolved_device_ids else " -- nothing to scan; import discovered devices first"),
    )

    if not resolved_device_ids:
        for name in ("configuration", "normalization", "compliance", "risk_analysis", "report"):
            _set_stage(job, db, name, "SKIPPED", "No target devices")
        job.status = "COMPLETED" if job.discovered_hosts is not None else "FAILED"
        job.completed_at = datetime.utcnow()
        db.commit()
        return

    # ---- Stages 3-6: per-device configuration -> pipeline --------------
    _set_stage(job, db, "configuration", "RUNNING", f"0/{len(resolved_device_ids)} device(s) collected")
    results: List[Dict[str, Any]] = []
    scan_ids: List[str] = []
    collected_ok = 0

    for device_id in resolved_device_ids:
        device = db.query(Device).filter(Device.id == device_id, Device.tenant_id == job.tenant_id).first()
        if not device:
            results.append({"device_id": device_id, "success": False, "error": "device not found"})
            continue
        try:
            transport = preferred_transport(device.vendor)
            credentials = _resolve_credentials(db, device, job.tenant_id)
            collector = get_collector(device.vendor, transport=transport)
            device.collection_status = "IN_PROGRESS"
            db.commit()
            collection = await anyio.to_thread.run_sync(collector.collect_config, device, credentials)
            device.collection_status = "SUCCESS" if collection.success else "FAILED"
            device.last_collected_at = collection.collected_at
            device.last_collection_error = collection.error
            device.last_collection_transport = collection.transport
            db.commit()

            if not collection.success or not collection.raw_config:
                results.append({"device_id": device_id, "hostname": device.hostname,
                                 "success": False, "error": collection.error or "no configuration returned"})
                continue
            collected_ok += 1
            _set_stage(job, db, "configuration", "RUNNING",
                       f"{collected_ok}/{len(resolved_device_ids)} device(s) collected")

            scan = Scan(tenant_id=job.tenant_id, device_id=device.id, framework=job.framework, status="uploaded")
            db.add(scan)
            db.commit()
            db.refresh(scan)
            scan_ids.append(scan.id)
            job.scan_ids = scan_ids
            db.commit()

            # run_pipeline itself commits scan.status through
            # parsed -> normalized -> opa_evaluating -> batfish_evaluating
            # -> completed/review/blocked; those ARE stages 4-6 for this
            # device, observed for real by anyone polling GET
            # /api/scans/{scan_id} concurrently with this job.
            await run_pipeline(db, scan, collection.raw_config, framework=job.framework)
            db.refresh(scan)
            results.append({
                "device_id": device_id, "hostname": device.hostname, "success": True,
                "scan_id": scan.id, "final_decision": scan.final_decision,
                "compliance_score": scan.compliance_score, "risk_level": scan.risk_level,
            })
        except Exception as e:  # noqa: BLE001 - one device must never sink the whole job
            logger.exception("Network scan job %s: device %s failed", job.id, device_id)
            results.append({"device_id": device_id, "success": False, "error": str(e)})

        job.device_results = results
        db.commit()

    _set_stage(job, db, "configuration", "DONE", f"{collected_ok}/{len(resolved_device_ids)} device(s) collected")

    succeeded = [r for r in results if r.get("success")]
    failed = [r for r in results if not r.get("success")]
    if succeeded:
        _set_stage(job, db, "normalization", "DONE", f"{len(succeeded)} configuration(s) normalized")
        _set_stage(job, db, "compliance", "DONE", f"{len(succeeded)} device(s) evaluated against {job.framework}")
        _set_stage(job, db, "risk_analysis", "DONE",
                   f"{len(succeeded)} scan(s) scored" + (" (Batfish included)" if job.include_batfish else ""))
        _set_stage(job, db, "report", "DONE", "Scan reports available on each device's Compliance/Findings tabs")
    else:
        for name in ("normalization", "compliance", "risk_analysis", "report"):
            _set_stage(job, db, name, "SKIPPED", "No device produced a usable configuration")

    job.device_results = results
    job.status = "FAILED" if failed and not succeeded else ("PARTIAL" if failed else "COMPLETED")
    job.completed_at = datetime.utcnow()
    db.commit()