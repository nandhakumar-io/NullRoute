"""add custom_controls table (SIH26155 Part 2 §10/§C: tenant-defined custom policy)

Revision ID: v7w8x9y0z1a2
Revises: u6v7w8x9y0z1
Create Date: 2026-09-16
"""
from alembic import op
import sqlalchemy as sa

revision = "v7w8x9y0z1X9"
down_revision = "u6v7w8x9y0z1"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "custom_controls",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), sa.ForeignKey("tenants.id"), nullable=False, index=True),
        sa.Column("control_id", sa.String(), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("parameter", sa.String(), nullable=False),
        sa.Column("operator", sa.String(), nullable=False),
        sa.Column("expected_json", sa.JSON(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False, server_default="MEDIUM"),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("status", sa.String(), nullable=False, server_default="pending_review"),
        sa.Column("created_by", sa.String(), nullable=True),
        sa.Column("approved_by", sa.String(), nullable=True),
        sa.Column("approved_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_custom_controls_tenant_id", "custom_controls", ["tenant_id"])
    op.create_index("ix_custom_controls_status", "custom_controls", ["status"])
    # One control_id per tenant — same uniqueness expectation as the
    # built-in catalog (catalog_parity.py's duplicate-ID check), scoped to
    # the tenant instead of global.
    op.create_unique_constraint(
        "uq_custom_controls_tenant_control_id", "custom_controls", ["tenant_id", "control_id"]
    )


def downgrade():
    op.drop_constraint("uq_custom_controls_tenant_control_id", "custom_controls", type_="unique")
    op.drop_index("ix_custom_controls_status", table_name="custom_controls")
    op.drop_index("ix_custom_controls_tenant_id", table_name="custom_controls")
    op.drop_table("custom_controls")