"""Add post-validation columns to deployment_records.

Adds target-control PASS verification and a real Batfish before/after
verdict to a deployment, instead of only a config-hash comparison.

Revision ID: b4c5d6e7f8a9
Revises: a3b4c5d6e7f8
Create Date: 2026-09-19
"""
from alembic import op
import sqlalchemy as sa

revision = "b4c5d6e7f8a9"
down_revision = "a3b4c5d6e7f8"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("deployment_records", sa.Column("target_control_ids", sa.JSON(), nullable=True))
    op.add_column("deployment_records", sa.Column("target_controls_result", sa.JSON(), nullable=True))
    op.add_column("deployment_records", sa.Column("target_controls_passed", sa.Boolean(), nullable=True))
    op.add_column("deployment_records", sa.Column("batfish_diff_status", sa.String(), nullable=True))
    op.add_column("deployment_records", sa.Column("batfish_diff_summary", sa.Text(), nullable=True))
    op.add_column("deployment_records", sa.Column("batfish_diff_detail", sa.JSON(), nullable=True))


def downgrade():
    op.drop_column("deployment_records", "batfish_diff_detail")
    op.drop_column("deployment_records", "batfish_diff_summary")
    op.drop_column("deployment_records", "batfish_diff_status")
    op.drop_column("deployment_records", "target_controls_passed")
    op.drop_column("deployment_records", "target_controls_result")
    op.drop_column("deployment_records", "target_control_ids")
