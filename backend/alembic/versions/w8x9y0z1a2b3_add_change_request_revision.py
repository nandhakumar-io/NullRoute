"""add revision column to change_requests (fixes AttributeError on admin edit/save)

Revision ID: w8x9y0z1a2b3
Revises: v7w8x9y0z1X9
Create Date: 2026-09-20
"""
from alembic import op
import sqlalchemy as sa

revision = "w8x9y0z1a2b3"
down_revision = "v7w8x9y0z1X9"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "change_requests",
        sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
    )


def downgrade():
    op.drop_column("change_requests", "revision")
