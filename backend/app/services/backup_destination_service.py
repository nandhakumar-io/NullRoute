"""Remote backup-destination service (enterprise config-backup/DR).

Pushes an already-collected configuration snapshot (a Scan's archived raw
config, retrieved from MinIO -- see services/minio_service.get_object) out
to an operator-configured destination: AWS S3, Azure Blob Storage, an
SFTP/remote server, or a local filesystem path on this box/volume.

Secret handling follows the existing OpenBao convention (RULE 6, see
services/openbao_service.py and models/db.py::DeviceCredentialRef):
BackupDestination.credential_ref points at an OpenBao KV entry holding
the actual access key / connection string / SSH credential. This module
is the only place besides openbao_service.py that ever sees that secret
material, and only for the duration of a single push call.

Every client library import is lazy/optional (mirrors minio_service's
`MINIO_LIB_AVAILABLE` pattern) so the app still boots and every other
feature keeps working even if boto3 / azure-storage-blob / paramiko is
missing from the environment -- the destination simply reports
"library not installed" on test/export instead of the whole app failing.
"""
from __future__ import annotations

import hashlib
import io
import logging
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from app.services import openbao_service

logger = logging.getLogger(__name__)

SUPPORTED_TYPES = ("s3", "azure_blob", "sftp", "local")

# Root directory for the "local" destination type -- a plain filesystem
# path on the machine/volume running this backend (e.g. a mounted NAS
# share or a dedicated backup disk/volume in the docker-compose topology).
# No credential is needed for this destination type; every push is
# confined to this root (see _local_path's traversal guard below).
LOCAL_BACKUP_ROOT = os.getenv("LOCAL_BACKUP_ROOT", "/data/local-backups")


class BackupDestinationError(RuntimeError):
    """Raised on any connectivity/config/upload failure talking to a
    remote backup destination. Callers must record this on the BackupJob
    row rather than letting it crash the request -- a destination outage
    must never take down the rest of the platform."""


@dataclass
class PushResult:
    remote_path: str
    bytes_written: int
    sha256: str
    duration_ms: int


# ---------------------------------------------------------------------------
# Credential helpers
# ---------------------------------------------------------------------------

def store_destination_secret(tenant_id: str, credential_type: str, secret: Dict[str, Any]) -> str:
    """Write destination secret material to OpenBao and return a fresh
    opaque credential_ref. Mirrors DeviceCredentialRef onboarding in
    routers/credentials.py. Raises BackupDestinationError if OpenBao is
    unreachable/misconfigured -- callers must not fall back to storing the
    secret anywhere else."""
    ref = openbao_service.generate_credential_ref()
    try:
        openbao_service.store_device_credentials(tenant_id, ref, credential_type, secret)
    except openbao_service.OpenBaoError as e:
        raise BackupDestinationError(f"Failed to store destination credentials: {e}") from e
    return ref


def rotate_destination_secret(tenant_id: str, credential_ref: str, credential_type: str, secret: Dict[str, Any]) -> None:
    try:
        openbao_service.rotate_device_credentials(tenant_id, credential_ref, credential_type, secret)
    except openbao_service.OpenBaoError as e:
        raise BackupDestinationError(f"Failed to rotate destination credentials: {e}") from e


def delete_destination_secret(tenant_id: str, credential_ref: str) -> None:
    try:
        openbao_service.delete_device_credentials(tenant_id, credential_ref)
    except openbao_service.OpenBaoError:
        # Best-effort: if OpenBao is down we still want the destination
        # row itself removable; the orphaned secret can be cleaned up
        # directly in OpenBao later.
        logger.warning("Could not delete OpenBao secret for ref %s (destination removed anyway)", credential_ref)


def _get_secret(tenant_id: str, credential_ref: Optional[str]) -> Dict[str, Any]:
    if not credential_ref:
        return {}
    try:
        creds = openbao_service.get_device_credentials(tenant_id, credential_ref)
        return creds.secret
    except openbao_service.OpenBaoError as e:
        raise BackupDestinationError(f"Failed to read destination credentials: {e}") from e


def _object_path(prefix: Optional[str], tenant_id: str, device_hostname: str, device_id: str, scan_id: str) -> str:
    prefix = (prefix or "netsec-auditor-backups").strip("/")
    safe_host = (device_hostname or device_id).replace("/", "_")
    return f"{prefix}/{tenant_id}/{safe_host}-{device_id}/{scan_id}.cfg"


# ---------------------------------------------------------------------------
# S3
# ---------------------------------------------------------------------------

def _push_s3(config: Dict[str, Any], secret: Dict[str, Any], remote_path: str, data: bytes) -> None:
    try:
        import boto3
        from botocore.config import Config as BotoConfig
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError as e:
        raise BackupDestinationError("boto3 is not installed") from e

    bucket = config.get("bucket")
    if not bucket:
        raise BackupDestinationError("S3 destination is missing 'bucket'")

    session_kwargs: Dict[str, Any] = {}
    if secret.get("access_key_id") and secret.get("secret_access_key"):
        session_kwargs["aws_access_key_id"] = secret["access_key_id"]
        session_kwargs["aws_secret_access_key"] = secret["secret_access_key"]
        if secret.get("session_token"):
            session_kwargs["aws_session_token"] = secret["session_token"]
    # else: fall back to the environment/instance-role credential chain,
    # which is a legitimate deployment mode for S3 (EC2/ECS instance
    # profiles) and shouldn't require an OpenBao entry at all.

    client_kwargs: Dict[str, Any] = {"region_name": config.get("region") or "us-east-1"}
    if config.get("endpoint_url"):
        client_kwargs["endpoint_url"] = config["endpoint_url"]
    if config.get("use_path_style"):
        client_kwargs["config"] = BotoConfig(s3={"addressing_style": "path"})

    try:
        client = boto3.client("s3", **session_kwargs, **client_kwargs)
        client.put_object(Bucket=bucket, Key=remote_path, Body=data, ContentType="text/plain")
    except (BotoCoreError, ClientError) as e:
        raise BackupDestinationError(f"S3 upload failed: {e}") from e


def _test_s3(config: Dict[str, Any], secret: Dict[str, Any]) -> str:
    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError as e:
        raise BackupDestinationError("boto3 is not installed") from e

    bucket = config.get("bucket")
    if not bucket:
        raise BackupDestinationError("S3 destination is missing 'bucket'")

    session_kwargs: Dict[str, Any] = {}
    if secret.get("access_key_id") and secret.get("secret_access_key"):
        session_kwargs["aws_access_key_id"] = secret["access_key_id"]
        session_kwargs["aws_secret_access_key"] = secret["secret_access_key"]
        if secret.get("session_token"):
            session_kwargs["aws_session_token"] = secret["session_token"]
    client_kwargs: Dict[str, Any] = {"region_name": config.get("region") or "us-east-1"}
    if config.get("endpoint_url"):
        client_kwargs["endpoint_url"] = config["endpoint_url"]

    try:
        client = boto3.client("s3", **session_kwargs, **client_kwargs)
        client.head_bucket(Bucket=bucket)
    except (BotoCoreError, ClientError) as e:
        raise BackupDestinationError(f"S3 connectivity check failed: {e}") from e
    return f"Connected to bucket '{bucket}'"


# ---------------------------------------------------------------------------
# Azure Blob Storage
# ---------------------------------------------------------------------------

def _blob_service_client(config: Dict[str, Any], secret: Dict[str, Any]):
    try:
        from azure.storage.blob import BlobServiceClient
    except ImportError as e:
        raise BackupDestinationError("azure-storage-blob is not installed") from e

    if secret.get("connection_string"):
        return BlobServiceClient.from_connection_string(secret["connection_string"])

    account_name = config.get("account_name")
    if not account_name:
        raise BackupDestinationError("Azure Blob destination is missing 'account_name'")
    suffix = config.get("endpoint_suffix") or "core.windows.net"
    account_url = f"https://{account_name}.blob.{suffix}"

    if secret.get("sas_token"):
        return BlobServiceClient(account_url=account_url, credential=secret["sas_token"])
    if secret.get("account_key"):
        return BlobServiceClient(account_url=account_url, credential=secret["account_key"])
    raise BackupDestinationError(
        "Azure Blob destination has no usable credential (connection_string, sas_token, or account_key)"
    )


def _push_azure_blob(config: Dict[str, Any], secret: Dict[str, Any], remote_path: str, data: bytes) -> None:
    container = config.get("container")
    if not container:
        raise BackupDestinationError("Azure Blob destination is missing 'container'")
    try:
        client = _blob_service_client(config, secret)
        blob = client.get_blob_client(container=container, blob=remote_path)
        blob.upload_blob(data, overwrite=True)
    except BackupDestinationError:
        raise
    except Exception as e:  # noqa: BLE001 - azure SDK raises its own exception hierarchy
        raise BackupDestinationError(f"Azure Blob upload failed: {e}") from e


def _test_azure_blob(config: Dict[str, Any], secret: Dict[str, Any]) -> str:
    container = config.get("container")
    if not container:
        raise BackupDestinationError("Azure Blob destination is missing 'container'")
    try:
        client = _blob_service_client(config, secret)
        container_client = client.get_container_client(container)
        container_client.get_container_properties()
    except BackupDestinationError:
        raise
    except Exception as e:  # noqa: BLE001
        raise BackupDestinationError(f"Azure Blob connectivity check failed: {e}") from e
    return f"Connected to container '{container}'"


# ---------------------------------------------------------------------------
# SFTP / remote server
# ---------------------------------------------------------------------------

def _sftp_connect(config: Dict[str, Any], secret: Dict[str, Any]):
    try:
        import paramiko
    except ImportError as e:
        raise BackupDestinationError("paramiko is not installed") from e

    host = config.get("host")
    if not host:
        raise BackupDestinationError("SFTP destination is missing 'host'")
    port = int(config.get("port") or 22)
    username = config.get("username") or secret.get("username")
    if not username:
        raise BackupDestinationError("SFTP destination is missing 'username'")

    transport = paramiko.Transport((host, port))
    try:
        if secret.get("private_key"):
            key_io = io.StringIO(secret["private_key"])
            try:
                pkey = paramiko.Ed25519Key.from_private_key(key_io, password=secret.get("private_key_passphrase") or None)
            except Exception:
                key_io.seek(0)
                pkey = paramiko.RSAKey.from_private_key(key_io, password=secret.get("private_key_passphrase") or None)
            transport.connect(username=username, pkey=pkey)
        elif secret.get("password"):
            transport.connect(username=username, password=secret["password"])
        else:
            raise BackupDestinationError("SFTP destination has no usable credential (password or private_key)")
    except BackupDestinationError:
        transport.close()
        raise
    except Exception as e:  # noqa: BLE001
        transport.close()
        raise BackupDestinationError(f"SFTP authentication failed: {e}") from e

    return transport


def _push_sftp(config: Dict[str, Any], secret: Dict[str, Any], remote_path: str, data: bytes) -> None:
    import paramiko

    transport = _sftp_connect(config, secret)
    try:
        sftp = paramiko.SFTPClient.from_transport(transport)
        base_dir = (config.get("remote_path") or "/").rstrip("/")
        full_path = f"{base_dir}/{remote_path}" if base_dir else f"/{remote_path}"
        # mkdir -p equivalent: create intermediate directories that don't exist yet.
        parts = full_path.strip("/").split("/")[:-1]
        cur = ""
        for part in parts:
            cur += f"/{part}"
            try:
                sftp.stat(cur)
            except IOError:
                sftp.mkdir(cur)
        with sftp.open(full_path, "wb") as f:
            f.write(data)
        sftp.close()
    except BackupDestinationError:
        raise
    except Exception as e:  # noqa: BLE001
        raise BackupDestinationError(f"SFTP upload failed: {e}") from e
    finally:
        transport.close()


def _test_sftp(config: Dict[str, Any], secret: Dict[str, Any]) -> str:
    transport = _sftp_connect(config, secret)
    try:
        import paramiko
        sftp = paramiko.SFTPClient.from_transport(transport)
        base_dir = config.get("remote_path") or "/"
        sftp.listdir(base_dir)
        sftp.close()
    except Exception as e:  # noqa: BLE001
        raise BackupDestinationError(f"SFTP connectivity check failed: {e}") from e
    finally:
        transport.close()
    return f"Connected to {config.get('host')}:{config.get('port') or 22}"


# ---------------------------------------------------------------------------
# Local filesystem
# ---------------------------------------------------------------------------

def _local_path(config: Dict[str, Any], remote_path: str) -> str:
    """Resolve `remote_path` under LOCAL_BACKUP_ROOT (or an operator-set
    subdirectory of it), guarding against path traversal -- `remote_path`
    is built entirely from server-side identifiers (see `_object_path`),
    never from unvalidated user input, but this stays defense-in-depth."""
    base_dir = (config.get("base_path") or "").strip().strip("/")
    root = os.path.abspath(LOCAL_BACKUP_ROOT)
    target_dir = os.path.abspath(os.path.join(root, base_dir)) if base_dir else root
    if os.path.commonpath([root, target_dir]) != root:
        raise BackupDestinationError("Local destination base_path escapes the local backup root")
    full_path = os.path.abspath(os.path.join(target_dir, remote_path))
    if os.path.commonpath([root, full_path]) != root:
        raise BackupDestinationError("Resolved local backup path escapes the local backup root")
    return full_path


def _push_local(config: Dict[str, Any], remote_path: str, data: bytes) -> None:
    full_path = _local_path(config, remote_path)
    try:
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        tmp_path = f"{full_path}.tmp-{os.getpid()}"
        with open(tmp_path, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, full_path)  # atomic on POSIX -- no half-written file is ever visible
    except OSError as e:
        raise BackupDestinationError(f"Local filesystem write failed: {e}") from e


def _test_local(config: Dict[str, Any]) -> str:
    base_dir = (config.get("base_path") or "").strip().strip("/")
    root = os.path.abspath(LOCAL_BACKUP_ROOT)
    target_dir = os.path.abspath(os.path.join(root, base_dir)) if base_dir else root
    if os.path.commonpath([root, target_dir]) != root:
        raise BackupDestinationError("Local destination base_path escapes the local backup root")
    try:
        os.makedirs(target_dir, exist_ok=True)
        probe = os.path.join(target_dir, f".netsec-auditor-write-test-{os.getpid()}")
        with open(probe, "wb") as f:
            f.write(b"ok")
        os.remove(probe)
    except OSError as e:
        raise BackupDestinationError(f"Local backup path is not writable: {e}") from e
    return f"Local path '{target_dir}' is writable"


def _get_local_disk_usage() -> Dict[str, Any]:
    """Best-effort free-space report for the local backup root, surfaced on
    System Health / the destination list so operators notice a full disk
    before it silently starts failing local exports."""
    root = os.path.abspath(LOCAL_BACKUP_ROOT)
    try:
        os.makedirs(root, exist_ok=True)
        usage = os.statvfs(root)
        total = usage.f_frsize * usage.f_blocks
        free = usage.f_frsize * usage.f_bavail
        return {"path": root, "total_bytes": total, "free_bytes": free, "used_pct": round(100 * (1 - free / total), 1) if total else None}
    except (OSError, AttributeError) as e:  # statvfs is POSIX-only
        return {"path": root, "error": str(e)}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def push_snapshot(
    *,
    tenant_id: str,
    destination_type: str,
    config: Dict[str, Any],
    credential_ref: Optional[str],
    data: bytes,
    device_hostname: str,
    device_id: str,
    scan_id: str,
) -> PushResult:
    """Push one snapshot's raw config bytes to a remote destination.
    Raises BackupDestinationError on any failure -- callers (routers/
    backups.py) record the failure on the BackupJob row rather than
    letting one destination outage break the response."""
    if destination_type not in SUPPORTED_TYPES:
        raise BackupDestinationError(f"Unsupported destination_type '{destination_type}'")

    started = time.monotonic()
    # "local" has no OpenBao-backed credential -- it's a filesystem path
    # on the box/volume this backend runs on.
    secret = {} if destination_type == "local" else _get_secret(tenant_id, credential_ref)
    remote_path = _object_path(config.get("path_prefix"), tenant_id, device_hostname, device_id, scan_id)

    if destination_type == "s3":
        _push_s3(config, secret, remote_path, data)
    elif destination_type == "azure_blob":
        _push_azure_blob(config, secret, remote_path, data)
    elif destination_type == "sftp":
        _push_sftp(config, secret, remote_path, data)
    elif destination_type == "local":
        _push_local(config, remote_path, data)

    duration_ms = int((time.monotonic() - started) * 1000)
    return PushResult(
        remote_path=remote_path,
        bytes_written=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        duration_ms=duration_ms,
    )


def test_connection(*, tenant_id: str, destination_type: str, config: Dict[str, Any], credential_ref: Optional[str]) -> str:
    """Verify connectivity/auth to a destination without writing any
    snapshot data. Returns a short human-readable success message;
    raises BackupDestinationError on failure."""
    if destination_type not in SUPPORTED_TYPES:
        raise BackupDestinationError(f"Unsupported destination_type '{destination_type}'")

    if destination_type == "local":
        return _test_local(config)

    secret = _get_secret(tenant_id, credential_ref)
    if destination_type == "s3":
        return _test_s3(config, secret)
    if destination_type == "azure_blob":
        return _test_azure_blob(config, secret)
    return _test_sftp(config, secret)


# ---------------------------------------------------------------------------
# DB-aware orchestration -- creates/updates BackupJob rows around a push.
# Shared by the manual "export" endpoint and the auto-export-after-scan
# hook (see routers/devices.py::run_scan), so both paths produce the same
# job-history record (RULE 11 -- no second implementation).
# ---------------------------------------------------------------------------

def run_export_job(db, destination, device, scan, *, trigger: str, triggered_by: Optional[str] = None):
    """Execute one destination push for one snapshot and persist a
    BackupJob row recording the outcome. Never raises -- failures are
    captured on the job row's status/error fields so one bad destination
    never breaks a bulk export or a scan response."""
    from datetime import datetime as _dt

    from app.models.backup import BackupJob
    from app.services import minio_service

    job = BackupJob(
        tenant_id=device.tenant_id,
        destination_id=destination.id,
        device_id=device.id,
        scan_id=scan.id,
        trigger=trigger,
        triggered_by=triggered_by,
        status="RUNNING",
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    try:
        if not scan.raw_config_path:
            raise BackupDestinationError("This snapshot has no archived raw configuration to export")
        raw_bytes = minio_service.get_object(scan.raw_config_path)
        result = push_snapshot(
            tenant_id=device.tenant_id,
            destination_type=destination.destination_type,
            config=destination.config or {},
            credential_ref=destination.credential_ref,
            data=raw_bytes,
            device_hostname=device.hostname or device.id,
            device_id=device.id,
            scan_id=scan.id,
        )
        job.status = "SUCCESS"
        job.remote_path = result.remote_path
        job.bytes_written = result.bytes_written
        job.sha256 = result.sha256
        job.duration_ms = result.duration_ms
        destination.last_export_status = "SUCCESS"
    except Exception as e:  # noqa: BLE001 - any destination/library failure lands on the job row
        job.status = "FAILED"
        job.error = str(e)[:2000]
        destination.last_export_status = "FAILED"
        logger.warning("Backup export failed (destination=%s device=%s scan=%s): %s",
                        destination.id, device.id, scan.id, e)
    finally:
        job.completed_at = _dt.utcnow()
        destination.last_export_at = _dt.utcnow()
        db.add(job)
        db.add(destination)
        db.commit()
        db.refresh(job)

    return job


def auto_export_after_scan(db, device, scan) -> None:
    """Best-effort: push a freshly collected snapshot to every enabled
    destination with auto_export_enabled=True whose scope includes this
    device. Called from routers/devices.py::run_scan right after a scan's
    raw config is archived to MinIO. Never raises -- a destination outage
    must never fail the scan itself."""
    from app.models.backup import BackupDestination

    try:
        destinations = (
            db.query(BackupDestination)
            .filter(
                BackupDestination.tenant_id == device.tenant_id,
                BackupDestination.enabled == True,  # noqa: E712
                BackupDestination.auto_export_enabled == True,  # noqa: E712
            )
            .all()
        )
    except Exception:  # noqa: BLE001 - table may not exist yet on an un-migrated DB
        return

    for destination in destinations:
        scope = destination.auto_export_scope or {}
        in_scope = scope.get("all") or (device.id in (scope.get("device_ids") or []))
        if not in_scope:
            continue
        try:
            run_export_job(db, destination, device, scan, trigger="auto_on_backup")
        except Exception as e:  # noqa: BLE001
            logger.warning("Auto-export hook failed for destination %s: %s", destination.id, e)