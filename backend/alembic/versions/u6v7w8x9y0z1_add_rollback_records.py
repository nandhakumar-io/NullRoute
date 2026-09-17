"""add rollback_records table + deployment_records.rolled_back (Phase 15b
-- section 12 of the Part 3 integration brief: DEPLOY -> VERIFY -> FAIL ->
ROLLBACK -> VERIFY ROLLBACK -> EVIDENCE was previously unimplemented; only
an advisory rollback *recommendation* (advanced_drift_service) and the
unrelated AI model-registry rollback existed. This adds the actual device
configuration rollback record, mirroring deployment_records.

Revision ID: u6v7w8x9y0z1
Revises: t5u6v7w8x9y0
Create Date: 2026-09-16 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = "u6v7w8x9y0z1"
down_revision = "t5u6v7w8x9y0"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "deployment_records",
        sa.Column("rolled_back", sa.Boolean(), nullable=False, server_default=sa.false()),
    )

    op.create_table(
        "rollback_records",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), sa.ForeignKey("tenants.id"), nullable=False, index=True),
        sa.Column("deployment_record_id", sa.String(), sa.ForeignKey("deployment_records.id"), nullable=False, index=True),
        sa.Column("change_request_id", sa.String(), sa.ForeignKey("change_requests.id"), nullable=False, index=True),
        sa.Column("device_id", sa.String(), sa.ForeignKey("devices.id"), nullable=False, index=True),
        sa.Column("initiated_by", sa.String(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("transport", sa.String(), nullable=True),
        sa.Column("target_config_hash", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=True),
        sa.Column("post_rollback_hash", sa.String(), nullable=True),
        sa.Column("post_rollback_verified", sa.Boolean(), nullable=True),
        sa.Column("post_rollback_scan_id", sa.String(), sa.ForeignKey("scans.id"), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_rollback_records_status", "rollback_records", ["status"])


def downgrade():
    op.drop_index("ix_rollback_records_status", table_name="rollback_records")
    op.drop_table("rollback_records")
    op.drop_column("deployment_records", "rolled_back")
