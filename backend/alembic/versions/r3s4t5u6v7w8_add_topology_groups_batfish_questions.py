"""add datacenters/racks/network_groups/batfish_questions

Revision ID: r3s4t5u6v7w8
Revises: q2r3s4t5u6v7
Create Date: 2026-09-11
"""
from alembic import op
import sqlalchemy as sa

revision = "r3s4t5u6v7w8"
down_revision = "q2r3s4t5u6v7"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "datacenters",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), sa.ForeignKey("tenants.id"), nullable=False, index=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("location", sa.String(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
    )

    op.create_table(
        "racks",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), sa.ForeignKey("tenants.id"), nullable=False, index=True),
        sa.Column("datacenter_id", sa.String(), sa.ForeignKey("datacenters.id"), nullable=False, index=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("row", sa.String(), nullable=True),
        sa.Column("unit_count", sa.Integer(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
    )

    op.create_table(
        "network_groups",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), sa.ForeignKey("tenants.id"), nullable=False, index=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("datacenter_id", sa.String(), sa.ForeignKey("datacenters.id"), nullable=True),
        sa.Column("rack_id", sa.String(), sa.ForeignKey("racks.id"), nullable=True),
        sa.Column("last_batfish_status", sa.String(), nullable=True),
        sa.Column("last_batfish_run_at", sa.DateTime(), nullable=True),
        sa.Column("last_batfish_result", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
    )

    op.create_table(
        "network_group_members",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("group_id", sa.String(), sa.ForeignKey("network_groups.id"), nullable=False, index=True),
        sa.Column("device_id", sa.String(), sa.ForeignKey("devices.id"), nullable=False, index=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )

    op.create_table(
        "batfish_questions",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), sa.ForeignKey("tenants.id"), nullable=False, index=True),
        sa.Column("group_id", sa.String(), sa.ForeignKey("network_groups.id"), nullable=False, index=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(), nullable=False, server_default="MEDIUM"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("question_type", sa.String(), nullable=False),
        sa.Column("params", sa.JSON(), nullable=True),
        sa.Column("created_by", sa.String(), nullable=True),
        sa.Column("last_status", sa.String(), nullable=True),
        sa.Column("last_result", sa.JSON(), nullable=True),
        sa.Column("last_run_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
    )

    op.add_column("devices", sa.Column("datacenter_id", sa.String(), sa.ForeignKey("datacenters.id"), nullable=True))
    op.add_column("devices", sa.Column("rack_id", sa.String(), sa.ForeignKey("racks.id"), nullable=True))


def downgrade():
    op.drop_column("devices", "rack_id")
    op.drop_column("devices", "datacenter_id")
    op.drop_table("batfish_questions")
    op.drop_table("network_group_members")
    op.drop_table("network_groups")
    op.drop_table("racks")
    op.drop_table("datacenters")
