"""Non-blocking, pausable/resumable nmap discovery jobs.

`network_discovery.scan_network()` is a single blocking nmap invocation
over a whole CIDR -- fine for a handful of hosts, but there was previously
no endpoint wired to it at all (POST /api/devices/discover 404/405'd), and
a single blocking call has no natural point to pause or resume from
either.

This module runs discovery as a background asyncio task, in chunks of
`network_discovery.CHUNK_SIZE` addresses at a time (one nmap process per
chunk). Each chunk still blocks the *worker task* while nmap runs, but it
runs via `anyio.to_thread.run_sync`, so it never blocks the event loop --
other API requests (and polling GET /discover/{id} for this same job) are
served normally throughout. Between chunks the task checks for a
pause/cancel request, which is what gives an operator a real "pause" (not
just hiding a still-running scan) and a real "resume" (continuing with the
next un-scanned chunk, not starting over).

Jobs are kept in-process (a plain dict), not persisted to the database:
they're short-lived, single-node discovery runs, not audited compliance
data, and every result is presented to the operator for review before
`POST .../discover/import` decides anything durable. This does mean a job
is lost if the backend process restarts mid-scan -- acceptable for a
"quick discovery" utility; anything that needs to survive a restart should
go through the existing NetworkScanJob + network-scan-worker pipeline
(services/network_scan_service.py) instead.
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import anyio

from app.services import network_discovery

logger = logging.getLogger("discovery_job_service")

# Jobs are only ever touched from the asyncio event loop thread (route
# handlers + the background task itself), so a plain dict is safe -- no
# separate lock needed, unlike a real multi-threaded worker.
_jobs: Dict[str, "DiscoveryJob"] = {}
_tasks: Dict[str, asyncio.Task] = {}

# How long a paused job's loop sleeps between checks for resume/cancel.
_PAUSE_POLL_SECONDS = 0.5


@dataclass
class DiscoveryJob:
    id: str
    tenant_id: str
    cidr: str
    ports: str
    service_detection: bool
    os_detection: bool
    status: str = "PENDING"  # PENDING/RUNNING/PAUSED/COMPLETED/FAILED/CANCELLED
    total_targets: int = 0
    scanned_targets: int = 0
    hosts: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    pause_requested: bool = False
    cancel_requested: bool = False
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "cidr": self.cidr,
            "ports": self.ports,
            "service_detection": self.service_detection,
            "os_detection": self.os_detection,
            "status": self.status,
            "total_targets": self.total_targets,
            "scanned_targets": self.scanned_targets,
            "progress_pct": (
                round(100 * self.scanned_targets / self.total_targets)
                if self.total_targets else (100 if self.status == "COMPLETED" else 0)
            ),
            "host_count": len(self.hosts),
            "hosts": self.hosts,
            "error": self.error,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class JobNotFoundError(Exception):
    pass


def _touch(job: DiscoveryJob) -> None:
    job.updated_at = time.time()


async def _run_job(job: DiscoveryJob) -> None:
    try:
        targets = network_discovery.expand_targets(job.cidr)
        chunks = network_discovery.chunk_targets(targets)
        job.total_targets = len(targets)
        job.status = "RUNNING"
        _touch(job)

        for chunk in chunks:
            # Pause point: sit here (without holding any thread doing real
            # work) until resumed or cancelled, checked between -- never
            # in the middle of -- an nmap chunk, so "paused" always means
            # nothing is actually scanning.
            while job.pause_requested and not job.cancel_requested:
                job.status = "PAUSED"
                _touch(job)
                await asyncio.sleep(_PAUSE_POLL_SECONDS)

            if job.cancel_requested:
                job.status = "CANCELLED"
                _touch(job)
                return

            job.status = "RUNNING"
            try:
                discovered = await anyio.to_thread.run_sync(
                    lambda c=chunk: network_discovery.scan_network(
                        " ".join(c),
                        ports=job.ports or network_discovery.DEFAULT_PORTS,
                        service_detection=job.service_detection,
                        os_detection=job.os_detection,
                    )
                )
                job.hosts.extend(h.to_dict() for h in discovered)
            except network_discovery.NmapUnavailableError as e:
                job.status = "FAILED"
                job.error = str(e)
                _touch(job)
                return
            except Exception as e:  # noqa: BLE001 - one bad chunk must not lose prior results
                logger.exception("Discovery job %s: chunk failed", job.id)
                job.error = f"Partial failure scanning {len(chunk)} host(s): {e}"

            job.scanned_targets += len(chunk)
            _touch(job)

        job.status = "COMPLETED"
        _touch(job)
    except Exception as e:  # noqa: BLE001 - the task must never vanish silently
        logger.exception("Discovery job %s crashed", job.id)
        job.status = "FAILED"
        job.error = f"Unhandled error: {e}"
        _touch(job)
    finally:
        _tasks.pop(job.id, None)


def create_job(
    tenant_id: str,
    cidr: str,
    ports: str,
    service_detection: bool = True,
    os_detection: bool = False,
) -> DiscoveryJob:
    job = DiscoveryJob(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        cidr=cidr,
        ports=ports,
        service_detection=service_detection,
        os_detection=os_detection,
    )
    _jobs[job.id] = job
    # Fire-and-forget: kept alive via _tasks so it isn't garbage-collected
    # mid-scan, independent of the request/response that created it --
    # this is what makes discovery non-blocking (the POST returns as soon
    # as the job row exists, not once scanning finishes).
    _tasks[job.id] = asyncio.create_task(_run_job(job))
    return job


def get_job(job_id: str, tenant_id: str) -> DiscoveryJob:
    job = _jobs.get(job_id)
    if not job or job.tenant_id != tenant_id:
        raise JobNotFoundError(job_id)
    return job


def pause_job(job_id: str, tenant_id: str) -> DiscoveryJob:
    job = get_job(job_id, tenant_id)
    if job.status in ("RUNNING", "PENDING"):
        job.pause_requested = True
    _touch(job)
    return job


def resume_job(job_id: str, tenant_id: str) -> DiscoveryJob:
    job = get_job(job_id, tenant_id)
    if job.status == "PAUSED" or job.pause_requested:
        job.pause_requested = False
        job.status = "RUNNING"
    _touch(job)
    return job


def cancel_job(job_id: str, tenant_id: str) -> DiscoveryJob:
    job = get_job(job_id, tenant_id)
    job.cancel_requested = True
    job.pause_requested = False
    _touch(job)
    return job