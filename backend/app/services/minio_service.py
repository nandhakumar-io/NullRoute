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
    MINIO_ENABLED       default "true"
    MINIO_ENDPOINT      default "minio:9000"
    MINIO_ACCESS_KEY    default "" (must be set when enabled)
    MINIO_SECRET_KEY    default "" (must be set when enabled)
    MINIO_BUCKET        default "compliance-evidence"
    MINIO_SECURE        default "false" (TLS to the MinIO endpoint)

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
"""
from __future__ import annotations

import hashlib
import io
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

try:
    from minio import Minio
    from minio.error import S3Error

    MINIO_LIB_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only when minio isn't installed
    Minio = None  # type: ignore[assignment]
    S3Error = Exception  # type: ignore[assignment,misc]
    MINIO_LIB_AVAILABLE = False

MINIO_ENABLED = os.getenv("MINIO_ENABLED", "true").lower() == "true"
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "minio:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "")
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "compliance-evidence")
MINIO_SECURE = os.getenv("MINIO_SECURE", "false").lower() == "true"

_client: Optional["Minio"] = None
_bucket_ready = False


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
    global _bucket_ready
    if _bucket_ready:
        return
    if not client.bucket_exists(MINIO_BUCKET):
        client.make_bucket(MINIO_BUCKET)
    _bucket_ready = True


def put_object(key: str, data: bytes, content_type: str = "application/octet-stream") -> Optional[PutResult]:
    """Best-effort upload. Returns None (never raises) if MinIO is disabled,
    unreachable, or misconfigured -- callers must still persist the
    computed hash/key in PostgreSQL and treat storage as retryable."""
    sha256 = hashlib.sha256(data).hexdigest()
    if not MINIO_ENABLED:
        return None
    try:
        client = _get_client()
        _ensure_bucket(client)
        client.put_object(MINIO_BUCKET, key, io.BytesIO(data), len(data))
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
        client.bucket_exists(MINIO_BUCKET)
        return {"status": "available", "bucket": MINIO_BUCKET}
    except Exception as e:  # noqa: BLE001
        return {"status": "unavailable", "error": str(e)}
