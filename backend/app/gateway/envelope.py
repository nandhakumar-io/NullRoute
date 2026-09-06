"""Signed device-operation job envelope (Part 1).

The API is the only party that signs envelopes; the Device Gateway only
ever verifies. Signing uses HMAC-SHA256 over a canonical JSON
representation of every security-sensitive field -- NOT a `trusted=true`
flag -- so a tampered field (tenant_id, device_id, operation, expiry, ...)
is detected by signature mismatch rather than trusted implicitly.

HMAC (shared-secret) is used rather than asymmetric signing because both
signer (API) and verifier (Device Gateway) are first-party services that
already share the deployment's secret material distribution mechanism
(the same OpenBao/K8s-secret channel used for JOB_SIGNING_SECRET below);
there is exactly one signer. If a second signer is ever introduced,
swap this for Ed25519 (verify-only public key on the gateway side)
without changing the envelope shape.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional

JOB_SIGNING_SECRET = os.getenv("JOB_SIGNING_SECRET", "")
DEFAULT_JOB_TTL_SECONDS = int(os.getenv("JOB_TTL_SECONDS", "120"))

# Operations enabled in this phase. WRITE/REMEDIATE/DEPLOY stay out of this
# set entirely -- the gateway does not merely gate them behind approval, it
# does not recognize them as valid operations at all until a future phase
# explicitly adds them here (Part 1: "do not enable automatic remediation
# deployment by default").
READ_ONLY_OPERATIONS = frozenset(
    {"AUDIT", "FETCH_CONFIG", "GET_FACTS", "GET_VERSION", "GET_INTERFACES", "GET_NEIGHBORS"}
)
# Reserved for a later phase; any operation in this set requires a valid,
# non-self approval_id even once implemented.
PRIVILEGED_OPERATIONS = frozenset({"WRITE", "REMEDIATE", "DEPLOY"})

SUPPORTED_PROTOCOLS = frozenset({"ssh", "netconf", "restconf", "gnmi", "snmp"})

# Fields covered by the signature. Anything not listed here can be added to
# the message freely without breaking older signatures, but every field
# the gateway makes a security decision on MUST be listed.
_SIGNED_FIELDS = (
    "job_id",
    "tenant_id",
    "requester_id",
    "device_id",
    "operation",
    "protocol",
    "payload",
    "created_at",
    "expires_at",
    "nonce",
    "approval_id",
)


@dataclass
class JobEnvelope:
    job_id: str
    tenant_id: str
    requester_id: str
    device_id: str
    operation: str
    protocol: str
    payload: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    nonce: str = field(default_factory=lambda: uuid.uuid4().hex)
    approval_id: Optional[str] = None
    signature: str = ""

    def canonical_bytes(self) -> bytes:
        """Deterministic, field-order-independent serialization of every
        signed field. Anything outside `_SIGNED_FIELDS` (e.g. `signature`
        itself) is excluded so verification doesn't depend on itself."""
        d = asdict(self)
        signed = {k: d[k] for k in _SIGNED_FIELDS}
        return json.dumps(signed, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "JobEnvelope":
        try:
            return cls(**{k: data.get(k) for k in (
                "job_id", "tenant_id", "requester_id", "device_id", "operation",
                "protocol", "payload", "created_at", "expires_at", "nonce",
                "approval_id", "signature",
            ) if data.get(k) is not None or k in ("payload", "approval_id", "signature")})
        except TypeError as e:
            raise ValueError(f"Malformed job envelope: {e}") from e


def _hmac(secret: str, message: bytes) -> str:
    if not secret:
        raise RuntimeError("JOB_SIGNING_SECRET is not configured")
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def sign(envelope: JobEnvelope, secret: Optional[str] = None) -> JobEnvelope:
    secret = secret if secret is not None else JOB_SIGNING_SECRET
    envelope.signature = _hmac(secret, envelope.canonical_bytes())
    return envelope


def verify_signature(envelope: JobEnvelope, secret: Optional[str] = None) -> bool:
    secret = secret if secret is not None else JOB_SIGNING_SECRET
    if not envelope.signature:
        return False
    expected = _hmac(secret, envelope.canonical_bytes())
    # Constant-time comparison -- signature checks must not leak timing info.
    return hmac.compare_digest(expected, envelope.signature)


def build_envelope(
    tenant_id: str,
    requester_id: str,
    device_id: str,
    operation: str,
    protocol: str,
    payload: Optional[Dict[str, Any]] = None,
    approval_id: Optional[str] = None,
    ttl_seconds: int = DEFAULT_JOB_TTL_SECONDS,
    secret: Optional[str] = None,
) -> JobEnvelope:
    now = time.time()
    env = JobEnvelope(
        job_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        requester_id=requester_id,
        device_id=device_id,
        operation=operation,
        protocol=protocol,
        payload=payload or {},
        created_at=now,
        expires_at=now + ttl_seconds,
        approval_id=approval_id,
    )
    return sign(env, secret=secret)