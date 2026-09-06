"""Independent job validation (Part 1).

Everything here re-derives trust from the database and the cryptographic
signature -- it never trusts a field just because the API payload set it.
This is deliberately the FIRST thing the gateway does with a job, before
any device connection is attempted, and every check short-circuits on the
first failure with a specific GatewayErrorCode (Part 12).
"""
from __future__ import annotations

import time
from typing import Optional

from sqlalchemy.orm import Session

from app.gateway.envelope import (JobEnvelope, PRIVILEGED_OPERATIONS,
                                   READ_ONLY_OPERATIONS, SUPPORTED_PROTOCOLS,
                                   verify_signature)
from app.gateway.errors import GatewayError, GatewayErrorCode
from app.models.db import Device, GatewayJobRecord, Tenant


def validate_envelope(db: Session, envelope: JobEnvelope, secret: Optional[str] = None) -> Device:
    """Runs every independent check in order and returns the validated
    Device row on success. Raises GatewayError on the first failure."""

    # 1. Malformed envelope -- required fields present.
    if not envelope.job_id or not envelope.tenant_id or not envelope.requester_id or not envelope.device_id:
        raise GatewayError(GatewayErrorCode.MALFORMED_ENVELOPE, "Job envelope missing required fields")

    # 2. Signature -- must be checked before anything else touches the DB
    # for this job, since a forged envelope shouldn't even influence a
    # replay-store lookup keyed by attacker-controlled fields.
    if not verify_signature(envelope, secret=secret):
        raise GatewayError(GatewayErrorCode.INVALID_JOB_SIGNATURE, "Job signature verification failed")

    # 3. Expiration.
    if envelope.expires_at <= time.time():
        raise GatewayError(GatewayErrorCode.EXPIRED_JOB, "Job envelope has expired")

    # 4. Replay: job_id and nonce must never have been seen before. This is
    # a DB unique-constraint-backed check (see GatewayJobRecord), not an
    # in-memory set, so it holds across gateway restarts/replicas.
    existing = db.query(GatewayJobRecord).filter(
        (GatewayJobRecord.job_id == envelope.job_id) | (GatewayJobRecord.nonce == envelope.nonce)
    ).first()
    if existing is not None:
        raise GatewayError(GatewayErrorCode.REPLAYED_JOB, "Job id or nonce has already been used")

    # 5. Tenant must exist independently of the claim in the envelope.
    tenant = db.query(Tenant).filter(Tenant.id == envelope.tenant_id).first()
    if tenant is None:
        raise GatewayError(GatewayErrorCode.TENANT_MISMATCH, "Unknown tenant")

    # 6. Requester identity: must be a non-empty, authenticated subject id.
    # (The gateway does not re-validate the Keycloak JWT itself -- the API
    # already did that -- but it requires the envelope to carry the
    # identity that came out of that validation, not a caller-chosen
    # string, which is enforced structurally: the API is the only holder
    # of JOB_SIGNING_SECRET, so requester_id can't be forged without also
    # forging the signature, already checked in step 2.)
    if not envelope.requester_id.strip():
        raise GatewayError(GatewayErrorCode.REQUESTER_INVALID, "Missing requester identity")

    # 7. Operation type.
    all_ops = READ_ONLY_OPERATIONS | PRIVILEGED_OPERATIONS
    if envelope.operation not in all_ops:
        raise GatewayError(GatewayErrorCode.OPERATION_UNSUPPORTED, f"Unsupported operation '{envelope.operation}'")
    if envelope.operation in PRIVILEGED_OPERATIONS:
        # Not reachable today (no caller can request these yet -- Part 1
        # keeps write/remediate/deploy behind an explicit capability check
        # that doesn't exist in this phase), but validated defensively so
        # enabling one later doesn't silently skip approval enforcement.
        if not envelope.approval_id:
            raise GatewayError(GatewayErrorCode.APPROVAL_REQUIRED, f"Operation '{envelope.operation}' requires approval")
        if envelope.approval_id == envelope.requester_id:
            raise GatewayError(GatewayErrorCode.APPROVAL_INVALID, "Requester cannot approve their own privileged job")

    # 8. Protocol.
    if envelope.protocol not in SUPPORTED_PROTOCOLS:
        raise GatewayError(GatewayErrorCode.PROTOCOL_UNSUPPORTED, f"Unsupported protocol '{envelope.protocol}'")

    # 9. Device ownership/tenant association -- device must belong to the
    # SAME tenant as the envelope, looked up independently.
    device = db.query(Device).filter(Device.id == envelope.device_id, Device.tenant_id == envelope.tenant_id).first()
    if device is None:
        raise GatewayError(GatewayErrorCode.DEVICE_NOT_FOUND, "Device not found for this tenant")

    return device