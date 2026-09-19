"""Enterprise config-backup destinations (NCO backup/DR).

A BackupDestination is an operator-configured remote target (AWS S3,
Azure Blob Storage, or an SFTP/remote server) that approved configuration
snapshots (Scan rows with a raw_config_path already archived to MinIO --
see routers/devices.py::run_scan) can be exported/replicated to, on top
of the primary MinIO copy. This gives the platform an actual off-box,
enterprise-style backup/DR story instead of only ever holding one copy
of a device's configuration.

Design mirrors the existing DeviceCredentialRef / OpenBao pattern (RULE 6):
this table NEVER stores secret material (access keys, SAS tokens, SSH
passwords/private keys) -- only a `credential_ref` pointing at OpenBao.
`config` only holds non-secret connection details (bucket/container name,
region, endpoint, host, port, remote path, username where the transport
allows a non-secret identity).

BackupJob is the append-only ledger of every export attempt -- one row
per (destination, snapshot) push -- so the Backups page can show real
job history/status rather than a fire-and-forget action with no record
(same spirit as GatewayJobRecord for device-gateway jobs).
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.models.db import Base


def gen_uuid() -> str:
    return str(uuid.uuid4())


class BackupDestination(Base):
    """A configured remote backup target. `destination_type` is one of
    "s3" | "azure_blob" | "sftp". Secret material referenced by
    `credential_ref` lives only in OpenBao (see
    services/backup_destination_service.py)."""

    __tablename__ = "backup_destinations"

    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    name = Column(String, nullable=False)
    destination_type = Column(String, nullable=False)  # s3 | azure_blob | sftp
    enabled = Column(Boolean, nullable=False, default=True)

    # Non-secret connection details only. Shape depends on destination_type:
    #   s3:         {bucket, region, endpoint_url?, path_prefix, use_path_style?}
    #   azure_blob: {account_name, container, path_prefix, endpoint_suffix?}
    #   sftp:       {host, port, remote_path, username}
    config = Column(JSON, nullable=False, default=dict)

    # Secret material used to be here (credential_ref). Now stored fully in Postgres.
    secret_data = Column(JSON, nullable=True)

    # Auto-export: when true, every newly collected snapshot for the
    # given scope is pushed to this destination automatically right
    # after collection (see services/backup_destination_service.py::
    # auto_export_snapshot, invoked from routers/devices.py::run_scan).
    auto_export_enabled = Column(Boolean, nullable=False, default=False)
    auto_export_scope = Column(JSON, nullable=True)  # {"device_ids": [...]} or {"all": true}
    retention_days = Column(Integer, nullable=True)  # informational; enforced by the remote system

    last_test_status = Column(String, nullable=True)  # SUCCESS | FAILED | NEVER_TESTED
    last_test_at = Column(DateTime, nullable=True)
    last_test_message = Column(Text, nullable=True)

    last_export_status = Column(String, nullable=True)  # SUCCESS | FAILED
    last_export_at = Column(DateTime, nullable=True)

    created_by = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    jobs = relationship("BackupJob", back_populates="destination", cascade="all, delete-orphan")


class BackupJob(Base):
    """One export attempt of a single configuration snapshot (Scan) to a
    single BackupDestination. Immutable once terminal (RULE 15 spirit --
    history is never overwritten); a retry creates a new row."""

    __tablename__ = "backup_jobs"

    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    destination_id = Column(String, ForeignKey("backup_destinations.id", ondelete="CASCADE"), nullable=False, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False, index=True)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False, index=True)  # the snapshot exported

    trigger = Column(String, nullable=False, default="manual")  # manual | auto_on_backup | scheduled
    status = Column(String, nullable=False, default="PENDING", index=True)  # PENDING/RUNNING/SUCCESS/FAILED
    remote_path = Column(String, nullable=True)  # object key / blob path / remote file path actually written
    bytes_written = Column(Integer, nullable=True)
    sha256 = Column(String, nullable=True)
    error = Column(Text, nullable=True)
    duration_ms = Column(Integer, nullable=True)

    triggered_by = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    completed_at = Column(DateTime, nullable=True)

    destination = relationship("BackupDestination", back_populates="jobs")