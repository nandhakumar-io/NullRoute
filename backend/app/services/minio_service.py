"""MinIO artifact storage service (Phase 8).

MinIO holds the actual bytes of raw configurations, evidence JSON,
reports, and optional Batfish artifacts. PostgreSQL only ever stores the
object key, its SHA-256 hash, and other metadata (RULE 7/12) -- never the
blob itself and never credentials (RULE 6): callers must not pass secret
material into `put_object`.

Object naming convention (see `object_key`):

    tenants/{tenant_id}/devices/{device_id}/scans/{scan_id}/raw.cfg
    tenants/{tenant_id}/devices/{device_id}/scans/{scan_id}/evidence.json
    tenants/{tenant_id}/devices/{device_id}/scans/{scan_id}/report.pdf

Configuration (env vars):
    MINIO_ENABLED               default "true"
    MINIO_ENDPOINT              default "minio:9000"
    MINIO_ACCESS_KEY            default "" (must be set when enabled)
    MINIO_SECRET_KEY            default "" (must be set when enabled)
    MINIO_BUCKET                default "compliance-evidence"
    MINIO_SECURE                default "false" (TLS to the MinIO endpoint)
    MINIO_OBJECT_LOCK_ENABLED   default "true" -- see "Tamper resistance" below
    MINIO_RETENTION_MODE        default "COMPLIANCE" ("COMPLIANCE"|"GOVERNANCE")
    MINIO_RETENTION_DAYS        default "2555" (~7 years)

Design:
    - Every write/read goes through this module -- nothing else in the
      codebase talks to MinIO directly.
    - Storage is best-effort on the write path: `put_object` never raises.
      A MinIO outage must not fail a scan/evidence generation; the caller
      falls back to persisting only the hash + key in PostgreSQL and can
      retry the upload later. `get_object` (retrieval) DOES raise, since a
      failed read has no safe silent fallback -- the caller asked for
      specific bytes back.
    - SHA-256 is always computed here, from the exact bytes handed to
      `put_object`, so the hash recorded in evidence/PostgreSQL matches
      what MinIO actually stored.

Tamper resistance (belt-and-suspenders alongside Fabric anchoring):
    Evidence integrity today has two independent layers, of different
    strength. Layer 1 (always on) is the SHA-256 hash recorded in
    PostgreSQL next to the evidence JSON -- real, but not tamper-*proof*
    on its own: an attacker with Postgres write access could edit the JSON
    and the hash column together and `verify_evidence()` would still pass.
    Layer 2 (opt-in, see fabric_service.py) is Hyperledger Fabric
    anchoring, which is genuinely tamper-proof but requires standing up a
    Fabric network -- real infrastructure most deployments won't run.

    This module adds a third, much cheaper layer that sits between those
    two: MinIO Object Lock (S3 WORM). When `put_object(..., immutable=True)`
    is used (evidence.json and report.* -- see evidence_service.py and
    routers/compliance.py), the object is written with a COMPLIANCE-mode
    retention lock, meaning *no* MinIO credential -- not even the root
    user -- can overwrite or delete it before the retention date, even via
    direct S3 API access that bypasses this FastAPI app entirely. It does
    not protect the Postgres row (still a real gap without Fabric), but it
    does mean the archived evidence bytes themselves can't be silently
    rewritten -- so `get_object()` on an old evidence/report key is
    guaranteed to return what was originally stored.

    Object Lock can only be enabled at *bucket creation time* in S3/MinIO;
    it cannot be retrofitted onto an existing bucket. If MINIO_BUCKET
    already exists without it (e.g. an upgrade from an earlier deployment
    of this app), `_ensure_bucket` detects this, does not silently
    downgrade to non-locked writes, and `health()` reports
    `object_lock: false` so this is visible on the System Health page
    rather than discovered later during an audit.
"""
from __future__ import annotations

import hashlib
import io
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

try:
    from minio import Minio
    from minio.commonconfig import COMPLIANCE, GOVERNANCE
    from minio.error import S3Error
    from minio.retention import Retention

    MINIO_LIB_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only when minio isn't installed
    Minio = None  # type: ignore[assignment]
    S3Error = Exception  # type: ignore[assignment,misc]
    Retention = None  # type: ignore[assignment]
    COMPLIANCE = "COMPLIANCE"  # type: ignore[assignment]
    GOVERNANCE = "GOVERNANCE"  # type: ignore[assignment]
    MINIO_LIB_AVAILABLE = False

logger = logging.getLogger("minio_service")

MINIO_ENABLED = os.getenv("MINIO_ENABLED", "true").lower() == "true"
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "minio:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "")
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "compliance-evidence")
MINIO_SECURE = os.getenv("MINIO_SECURE", "false").lower() == "true"

MINIO_OBJECT_LOCK_ENABLED = os.getenv("MINIO_OBJECT_LOCK_ENABLED", "true").lower() == "true"
MINIO_RETENTION_MODE = os.getenv("MINIO_RETENTION_MODE", "COMPLIANCE").strip().upper()
if MINIO_RETENTION_MODE not in ("COMPLIANCE", "GOVERNANCE"):
    raise ValueError(f"MINIO_RETENTION_MODE must be 'COMPLIANCE' or 'GOVERNANCE', got {MINIO_RETENTION_MODE!r}")
MINIO_RETENTION_DAYS = int(os.getenv("MINIO_RETENTION_DAYS", "2555"))

_client: Optional["Minio"] = None
_bucket_ready = False
# Set by _ensure_bucket the first time it runs: whether the bucket this
# process is writing to actually has Object Lock enabled. None until
# checked. Exposed via health() so a bucket created before this feature
# existed (and therefore can't retroactively get Object Lock) is visible
# as a real gap rather than a silent downgrade.
_bucket_object_lock_status: Optional[bool] = None


class ObjectStoreError(RuntimeError):
    """Raised by `get_object` when the object cannot be retrieved (disabled,
    misconfigured, missing, or a backend error). `put_object` never raises
    this -- see module docstring."""


@dataclass
class PutResult:
    object_key: str
    sha256: str
    size_bytes: int
    bucket: str


def object_key(tenant_id: str, device_id: str, scan_id: str, filename: str) -> str:
    """Canonical object naming convention used everywhere in the codebase.

    tenants/{tenant_id}/devices/{device_id}/scans/{scan_id}/{filename}
    """
    return f"tenants/{tenant_id}/devices/{device_id}/scans/{scan_id}/{filename}"


def _get_client() -> "Minio":
    global _client
    if _client is None:
        if not MINIO_LIB_AVAILABLE:
            raise ObjectStoreError("minio client library is not installed")
        if not MINIO_ACCESS_KEY or not MINIO_SECRET_KEY:
            raise ObjectStoreError("MINIO_ACCESS_KEY/MINIO_SECRET_KEY are not configured")
        _client = Minio(
            MINIO_ENDPOINT,
            access_key=MINIO_ACCESS_KEY,
            secret_key=MINIO_SECRET_KEY,
            secure=MINIO_SECURE,
        )
    return _client


def _ensure_bucket(client: "Minio") -> None:
    global _bucket_ready, _bucket_object_lock_status
    if _bucket_ready:
        return
    if not client.bucket_exists(MINIO_BUCKET):
        client.make_bucket(MINIO_BUCKET, object_lock=MINIO_OBJECT_LOCK_ENABLED)
        _bucket_object_lock_status = MINIO_OBJECT_LOCK_ENABLED
    else:
        # Bucket predates this feature (or Object Lock was never requested).
        # Object Lock cannot be enabled retroactively on an existing S3/MinIO
        # bucket -- detect the real state rather than assuming our env var
        # reflects reality.
        try:
            client.get_object_lock_config(MINIO_BUCKET)
            _bucket_object_lock_status = True
        except S3Error as e:
            if getattr(e, "code", "") == "ObjectLockConfigurationNotFoundError":
                _bucket_object_lock_status = False
                if MINIO_OBJECT_LOCK_ENABLED:
                    logger.warning(
                        "MINIO_OBJECT_LOCK_ENABLED=true but bucket %r was created without Object "
                        "Lock and it cannot be enabled retroactively. Evidence/report objects will "
                        "be written WITHOUT WORM protection until this bucket is recreated (or a "
                        "new MINIO_BUCKET name is configured) with object lock enabled. This gap "
                        "is also surfaced on GET /api/system/health.",
                        MINIO_BUCKET,
                    )
            else:
                raise
    _bucket_ready = True


def _immutable_object_lock_available() -> bool:
    return bool(MINIO_OBJECT_LOCK_ENABLED and MINIO_LIB_AVAILABLE and _bucket_object_lock_status)


def put_object(
    key: str, data: bytes, content_type: str = "application/octet-stream", immutable: bool = False,
) -> Optional[PutResult]:
    """Best-effort upload. Returns None (never raises) if MinIO is disabled,
    unreachable, or misconfigured -- callers must still persist the
    computed hash/key in PostgreSQL and treat storage as retryable.

    `immutable=True` additionally applies a COMPLIANCE-mode (by default;
    see MINIO_RETENTION_MODE) Object Lock retention to the object, so it
    cannot be overwritten or deleted -- by ANY credential, including the
    MinIO root user -- before the retention date, even via direct S3 API
    access outside this application. Pass this for evidence packages and
    generated reports (see evidence_service.store_evidence and
    routers/compliance.py); it is not appropriate for objects that are
    legitimately expected to be replaced (there are none of those today,
    but e.g. a future editable draft artifact should not set this).

    If the bucket wasn't created with Object Lock enabled (see
    `_ensure_bucket`), `immutable=True` is silently downgraded to a normal
    write rather than raising -- storage failures here must never fail a
    scan (module-level design rule) -- but the gap is visible via
    `health()`'s `object_lock` field."""
    sha256 = hashlib.sha256(data).hexdigest()
    if not MINIO_ENABLED:
        return None
    try:
        client = _get_client()
        _ensure_bucket(client)
        client.put_object(MINIO_BUCKET, key, io.BytesIO(data), len(data), content_type=content_type)
        if immutable and _immutable_object_lock_available():
            retention_class = COMPLIANCE if MINIO_RETENTION_MODE == "COMPLIANCE" else GOVERNANCE
            until = datetime.now(timezone.utc) + timedelta(days=MINIO_RETENTION_DAYS)
            client.set_object_retention(MINIO_BUCKET, key, config=Retention(retention_class, until))
        return PutResult(object_key=key, sha256=sha256, size_bytes=len(data), bucket=MINIO_BUCKET)
    except Exception:  # noqa: BLE001 - any backend/config failure degrades gracefully
        return None


def get_object(key: str) -> bytes:
    """Retrieve object bytes. Raises ObjectStoreError on any failure
    (disabled, misconfigured, missing object, backend error) -- there is
    no safe silent fallback for a caller that explicitly asked to read
    specific bytes back."""
    if not MINIO_ENABLED:
        raise ObjectStoreError("MinIO integration is disabled (MINIO_ENABLED=false)")
    try:
        client = _get_client()
        response = client.get_object(MINIO_BUCKET, key)
        try:
            return response.read()
        finally:
            response.close()
            response.release_conn()
    except ObjectStoreError:
        raise
    except Exception as e:  # noqa: BLE001
        raise ObjectStoreError(f"Could not read object {key}: {e}") from e


def health() -> Dict[str, Any]:
    """Best-effort health probe, mirrors app.services.openbao_service.health()."""
    if not MINIO_ENABLED:
        return {"status": "disabled"}
    if not MINIO_LIB_AVAILABLE:
        return {"status": "misconfigured", "reason": "minio library not installed"}
    if not MINIO_ACCESS_KEY or not MINIO_SECRET_KEY:
        return {"status": "misconfigured"}
    try:
        client = _get_client()
        _ensure_bucket(client)
        result: Dict[str, Any] = {
            "status": "available",
            "bucket": MINIO_BUCKET,
            "object_lock": bool(_bucket_object_lock_status),
        }
        if MINIO_OBJECT_LOCK_ENABLED and not _bucket_object_lock_status:
            result["object_lock_warning"] = (
                f"Bucket {MINIO_BUCKET!r} was created without Object Lock and it cannot be "
                "enabled retroactively -- evidence/report objects are stored WITHOUT WORM "
                "tamper protection. Recreate the bucket (or point MINIO_BUCKET at a new name) "
                "with object lock enabled to close this gap."
            )
        return result
    except Exception as e:  # noqa: BLE001
        return {"status": "unavailable", "error": str(e)}
