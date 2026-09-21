"""API-side entry point into the Device Gateway (Part 1 / Part 11).

The API builds and signs a job envelope, publishes it on the appropriate
NATS JetStream subject for observability/other consumers, and then submits
it for execution. Job *execution* always goes through
`app.gateway.worker.process_job` -- the same function the standalone
gateway consumer process (`run_consumer`, for the real multi-process
docker-compose deployment) calls when it pulls a message off NATS. In this
single-process/demo/test configuration, submission calls `process_job`
directly (mirroring the offline-safe pattern already used by
`app.events.publish`), which is what makes the vertical slice work without
requiring a live NATS broker: NATS carries the message in production, but
correctness of the security checks and the execution result never depends
on whether the transport hop actually happened.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app import events
from app.gateway.envelope import build_envelope
from app.gateway.worker import process_job

SUBJECTS = {
    "AUDIT": ("netsec.device.audit.request", "netsec.device.audit.result"),
    "FETCH_CONFIG": ("netsec.device.config.request", "netsec.device.config.result"),
    "GET_FACTS": ("netsec.device.audit.request", "netsec.device.audit.result"),
    "GET_VERSION": ("netsec.device.audit.request", "netsec.device.audit.result"),
    "GET_INTERFACES": ("netsec.device.audit.request", "netsec.device.audit.result"),
    "GET_NEIGHBORS": ("netsec.device.audit.request", "netsec.device.audit.result"),
    "GET_HEALTH_METRICS": ("netsec.device.audit.request", "netsec.device.audit.result"),
}
ERROR_SUBJECT = "netsec.device.error"


async def submit_job(
    db: Session,
    tenant_id: str,
    requester_id: str,
    device_id: str,
    operation: str,
    protocol: str,
    payload: Optional[Dict[str, Any]] = None,
    approval_id: Optional[str] = None,
) -> dict:
    envelope = build_envelope(
        tenant_id=tenant_id,
        requester_id=requester_id,
        device_id=device_id,
        operation=operation,
        protocol=protocol,
        payload=payload,
        approval_id=approval_id,
    )
    request_subject, result_subject = SUBJECTS.get(operation, (None, None))
    if request_subject:
        # Best-effort: this never gates execution (see module docstring).
        # The envelope on the wire carries only the same fields already
        # covered by the signature -- no secret material.
        await events.publish(request_subject, envelope.to_dict())

    import asyncio
    result = await asyncio.to_thread(process_job, db, envelope)

    if result_subject:
        subject = result_subject if result.get("success") else ERROR_SUBJECT
        await events.publish(subject, result)

    return result