"""Add network_scan_jobs table (enterprise Discovery + Network Scan UI).

Backs the new POST/GET /api/network-scans endpoints and the
app/workers/network_scan_worker.py background worker. One row per
orchestrated "discover -> collect -> normalize -> comply -> risk -> report"
run, tracked with real per-stage status polled by the frontend (see
app/models/db.NetworkScanJob docstring) -- no fabricated progress.

Revision ID: h2i3j4k5l6m7
Revises: g1h2i3j4k5l6
Create Date: 2026-09-06 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = 'h2i3j4k5l6m7'
down_revision = 'g1h2i3j4k5l6'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "network_scan_jobs",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), sa.ForeignKey("tenants.id"), nullable=False, index=True),
        sa.Column("name", sa.String(), nullable=True),
        sa.Column("target_cidr", sa.String(), nullable=True),
        sa.Column("run_discovery", sa.Boolean(), server_default=sa.false()),
        sa.Column("discovery_ports", sa.String(), nullable=True),
        sa.Column("requested_device_ids", sa.JSON(), nullable=True),
        sa.Column("framework", sa.String(), server_default="ALL"),
        sa.Column("include_batfish", sa.Boolean(), server_default=sa.true()),
        sa.Column("status", sa.String(), server_default="PENDING"),
        sa.Column("stages", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("discovered_hosts", sa.JSON(), nullable=True),
        sa.Column("resolved_device_ids", sa.JSON(), nullable=True),
        sa.Column("scan_ids", sa.JSON(), nullable=True),
        sa.Column("device_results", sa.JSON(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_network_scan_jobs_tenant_id", "network_scan_jobs", ["tenant_id"])
    op.create_index("ix_network_scan_jobs_status", "network_scan_jobs", ["status"])


def downgrade():
    op.drop_index("ix_network_scan_jobs_status", table_name="network_scan_jobs")
    op.drop_index("ix_network_scan_jobs_tenant_id", table_name="network_scan_jobs")
    op.drop_table("network_scan_jobs")
