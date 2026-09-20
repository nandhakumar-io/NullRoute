"""add time_of_day column to audit_schedules

Revision ID: x9y0z1a2b3c4
Revises: w8x9y0z1a2b3
Create Date: 2026-09-20
"""
from alembic import op
import sqlalchemy as sa

revision = "x9y0z1a2b3c4"
down_revision = "w8x9y0z1a2b3"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "audit_schedules",
        sa.Column("time_of_day", sa.String(), nullable=True),
    )


def downgrade():
    op.drop_column("audit_schedules", "time_of_day")