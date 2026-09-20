"""Device Gateway job processing (Part 1 / Part 11).

`process_job` is the single function both the synchronous dev/test path
(publisher.py calling straight through when NATS is unreachable, same
pattern as app/events.py) and the real NATS JetStream consumer loop
(`run_consumer`) funnel through -- there is exactly one code path that
touches a device, independent validation always runs first.
"""
from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from datetime import datetime, timedelta
from typing import Dict, Optional

from sqlalchemy.orm import Session

from app.gateway import connectors, metrics
from app.gateway.connectors import CONNECT_TIMEOUT_SECONDS, COMMAND_TIMEOUT_SECONDS, NormalizedResult
from app.gateway.envelope import JobEnvelope
from app.gateway.errors import GatewayError, GatewayErrorCode
from app.gateway.validator import validate_envelope
from app.models.db import Device, DeviceCredentialRef, GatewayJobRecord
from app.services import minio_service, openbao_service
from app.services.audit_service import record_system
from app.services.collectors.registry import credential_type_matches_transport

logger = logging.getLogger("device_gateway")

# One in-flight job per device at a time (Part 1 #17 "Limit concurrency per
# device"). Module-level dict of locks -- adequate for a single gateway
# process/replica; a multi-replica deployment would need a distributed lock
# (e.g. a Postgres advisory lock keyed by device_id) instead, noted as a
# follow-up rather than introducing new infra in this phase.
_device_locks: Dict[str, threading.Lock] = {}
_device_locks_guard = threading.Lock()

_executor = ThreadPoolExecutor(max_workers=16, thread_name_prefix="gateway-job")


def _lock_for(device_id: str) -> threading.Lock:
    with _device_locks_guard:
        lock = _device_locks.get(device_id)
        if lock is None:
            lock = threading.Lock()
            _device_locks[device_id] = lock
        return lock


def _resolve_credentials(db: Session, device: Device, tenant_id: str, protocol: Optional[str] = None):
    """Same transport/credential_type matching as routers/devices.py's
    _resolve_credentials -- a device with both ssh_password and
    snmp_community refs on file must not have the wrong one handed to the
    collector just because it's the most recently created row."""
    if connectors.GATEWAY_MOCK_CONNECTOR:
        return openbao_service.DeviceCredentials(credential_type="mock", secret={"username": "mock", "password": "mock"})

    candidates = (
        db.query(DeviceCredentialRef)
        .filter(DeviceCredentialRef.device_id == device.id, DeviceCredentialRef.tenant_id == tenant_id)
        .order_by(DeviceCredentialRef.created_at.desc())
        .all()
    )
    ref_row = None
    if protocol:
        ref_row = next((c for c in candidates if credential_type_matches_transport(c.credential_type, protocol)), None)
    if ref_row is None:
        ref_row = candidates[0] if candidates else None
    if not ref_row:
        raise GatewayError(GatewayErrorCode.CREDENTIAL_UNAVAILABLE, "No credential reference on file for this device")
    try:
        return openbao_service.get_device_credentials(tenant_id, ref_row.secret_path)
    except openbao_service.OpenBaoError as e:
        raise GatewayError(GatewayErrorCode.CREDENTIAL_UNAVAILABLE, f"Could not resolve credentials: {type(e).__name__}") from e


def _persist_record(db: Session, envelope: JobEnvelope, status: str, **kwargs) -> GatewayJobRecord:
    record = GatewayJobRecord(
        job_id=envelope.job_id,
        nonce=envelope.nonce,
        tenant_id=envelope.tenant_id,
        requester_id=envelope.requester_id,
        device_id=envelope.device_id,
        operation=envelope.operation,
        protocol=envelope.protocol,
        approval_id=envelope.approval_id,
        status=status,
        created_at=datetime.utcfromtimestamp(envelope.created_at),
        expires_at=datetime.utcfromtimestamp(envelope.expires_at),
        **kwargs,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def process_job(db: Session, envelope: JobEnvelope, secret: str = None) -> dict:
    """Validates and executes one job envelope end-to-end. Returns the
    normalized result dict (Part 1 common structure). Never raises for
    expected failure modes -- every GatewayError becomes a failed result
    dict instead, so a NATS consumer can ack the message and publish the
    error to `netsec.device.error` rather than retrying forever on a
    permanently-invalid job."""
    metrics.record_job_received()
    start_status = "RECEIVED"
    try:
        device = validate_envelope(db, envelope, secret=secret)
    except GatewayError as e:
        # A job that fails validation is still recorded (once we know it's
        # not itself a replay) so a resubmission with the same job_id/nonce
        # is rejected too -- but a REPLAYED_JOB rejection must NOT try to
        # insert a second row (that's the row that already exists).
        if e.code != GatewayErrorCode.REPLAYED_JOB:
            try:
                _persist_record(db, envelope, "REJECTED", error_code=e.code.value, error_message=e.message,
                                 completed_at=datetime.utcnow())
            except Exception:
                db.rollback()
        metrics.record_job_failed(envelope.protocol, 0.0)
        return _result_dict(envelope, success=False, error=e)

    record = _persist_record(db, envelope, "VALIDATED")

    lock = _lock_for(device.id)
    if not lock.acquire(blocking=False):
        err = GatewayError(GatewayErrorCode.CONCURRENCY_LIMIT, "Another job is already in progress for this device")
        record.status = "REJECTED"
        record.error_code = err.code.value
        record.error_message = err.message
        record.completed_at = datetime.utcnow()
        db.commit()
        metrics.record_job_failed(envelope.protocol, 0.0)
        return _result_dict(envelope, success=False, error=err)

    try:
        record.status = "RUNNING"
        db.commit()

        try:
            credentials = _resolve_credentials(db, device, envelope.tenant_id, envelope.protocol)
        except GatewayError as e:
            record.status = "FAILED"
            record.error_code = e.code.value
            record.error_message = e.message
            record.completed_at = datetime.utcnow()
            db.commit()
            metrics.record_job_failed(envelope.protocol, 0.0)
            return _result_dict(envelope, success=False, error=e)

        future = _executor.submit(connectors.execute, device, envelope.operation, envelope.protocol, credentials)
        try:
            result: NormalizedResult = future.result(timeout=CONNECT_TIMEOUT_SECONDS + COMMAND_TIMEOUT_SECONDS)
        except FutureTimeoutError:
            metrics.record_device_connection_failure()
            err = GatewayError(GatewayErrorCode.COMMAND_TIMEOUT, "Device operation exceeded the execution timeout")
            record.status = "FAILED"
            record.error_code = err.code.value
            record.error_message = err.message
            record.completed_at = datetime.utcnow()
            db.commit()
            metrics.record_job_failed(envelope.protocol, (CONNECT_TIMEOUT_SECONDS + COMMAND_TIMEOUT_SECONDS) * 1000)
            return _result_dict(envelope, success=False, error=err)
        # `credentials` goes out of scope here regardless of outcome.

        if not result.success:
            metrics.record_device_connection_failure()
            record.status = "FAILED"
            record.error_code = result.error_code
            record.error_message = result.error_message
            record.duration_ms = result.duration_ms
            record.completed_at = datetime.utcnow()
            db.commit()
            metrics.record_job_failed(envelope.protocol, result.duration_ms)
            return {
                "device_id": result.device_id,
                "protocol": result.protocol,
                "operation": result.operation,
                "success": False,
                "collected_at": result.collected_at.isoformat(),
                "raw_output_reference": None,
                "normalized_data": {},
                "error_code": result.error_code,
                "error_message": result.error_message,
                "job_id": envelope.job_id,
            }

        # Large raw output goes to MinIO, not through NATS/Postgres (Part 1
        # "Large/raw configuration output should be stored through the
        # existing MinIO/object-storage mechanism").
        object_key = None
        if result.raw_config:
            object_key = minio_service.object_key(envelope.tenant_id, device.id, envelope.job_id, "raw_config.txt")
            try:
                minio_service.put_object(object_key, result.raw_config.encode("utf-8"), content_type="text/plain")
            except Exception as e:  # noqa: BLE001 -- MinIO being down shouldn't lose an otherwise-successful job
                logger.warning("Failed to persist raw output for job %s to MinIO: %s", envelope.job_id, e)
                object_key = None

        record.status = "SUCCEEDED"
        record.result_object_key = object_key
        record.normalized_data = result.normalized_data
        record.duration_ms = result.duration_ms
        record.completed_at = datetime.utcnow()
        db.commit()
        metrics.record_job_completed(envelope.protocol, result.duration_ms)

        try:
            record_system(
                db,
                action=f"gateway.{envelope.operation.lower()}",
                tenant_id=envelope.tenant_id,
                object_type="device",
                object_id=device.id,
                result="SUCCESS",
                new_value={"job_id": envelope.job_id, "protocol": envelope.protocol, "requester_id": envelope.requester_id},
            )
        except Exception:  # noqa: BLE001 -- audit failure must never mask job success
            logger.warning("Failed to record audit event for job %s", envelope.job_id)

        return {
            "device_id": result.device_id,
            "protocol": result.protocol,
            "operation": result.operation,
            "success": True,
            "collected_at": result.collected_at.isoformat(),
            "raw_output_reference": object_key,
            "normalized_data": result.normalized_data,
            "error_code": None,
            "error_message": None,
            "job_id": envelope.job_id,
        }
    finally:
        lock.release()


def _result_dict(envelope: JobEnvelope, success: bool, error: GatewayError) -> dict:
    return {
        "device_id": envelope.device_id,
        "protocol": envelope.protocol,
        "operation": envelope.operation,
        "success": success,
        "collected_at": datetime.utcnow().isoformat(),
        "raw_output_reference": None,
        "normalized_data": {},
        "error_code": error.code.value,
        "error_message": error.message,
        "job_id": envelope.job_id,
    }