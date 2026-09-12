"""add device_metric_snapshots (metrics history & interface utilization)

Revision ID: q2r3s4t5u6v7
Revises: p1q2r3s4t5u6
Create Date: 2026-09-11
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "q2r3s4t5u6v7"
down_revision = "p1q2r3s4t5u6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "device_metric_snapshots",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), sa.ForeignKey("tenants.id"), nullable=False, index=True),
        sa.Column("device_id", sa.String(), sa.ForeignKey("devices.id"), nullable=False, index=True),
        sa.Column("collected_at", sa.DateTime(), nullable=True),
        sa.Column("source", sa.String(), nullable=False, server_default="snmp"),
        sa.Column("success", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("cpu_average_pct", sa.Float(), nullable=True),
        sa.Column("memory_used_pct", sa.Float(), nullable=True),
        sa.Column("memory_total_bytes", sa.Float(), nullable=True),
        sa.Column("memory_used_bytes", sa.Float(), nullable=True),
        sa.Column("interface_counters", sa.JSON(), nullable=True),
        sa.Column("interface_utilization", sa.JSON(), nullable=True),
        sa.Column("environmental", sa.JSON(), nullable=True),
    )
    op.create_index("ix_device_metric_snapshots_tenant_id", "device_metric_snapshots", ["tenant_id"])
    op.create_index("ix_device_metric_snapshots_device_id", "device_metric_snapshots", ["device_id"])
    op.create_index("ix_device_metric_snapshots_collected_at", "device_metric_snapshots", ["collected_at"])
    op.create_index(
        "ix_device_metric_snapshots_device_collected",
        "device_metric_snapshots", ["device_id", "collected_at"],
    )
    op.create_table(
        "tenant_settings",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), sa.ForeignKey("tenants.id"), nullable=False, index=True),
        sa.Column("key", sa.String(), nullable=False, index=True),
        sa.Column("value", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_tenant_settings_tenant_id", "tenant_settings", ["tenant_id"])
    op.create_index("ix_tenant_settings_key", "tenant_settings", ["key"])
    op.create_unique_constraint("uq_tenant_settings_tenant_key", "tenant_settings", ["tenant_id", "key"])


def downgrade() -> None:
    op.drop_table("tenant_settings")
    op.drop_index("ix_device_metric_snapshots_device_collected", table_name="device_metric_snapshots")
    op.drop_index("ix_device_metric_snapshots_collected_at", table_name="device_metric_snapshots")
    op.drop_index("ix_device_metric_snapshots_device_id", table_name="device_metric_snapshots")
    op.drop_index("ix_device_metric_snapshots_tenant_id", table_name="device_metric_snapshots")
    op.drop_table("device_metric_snapshots")