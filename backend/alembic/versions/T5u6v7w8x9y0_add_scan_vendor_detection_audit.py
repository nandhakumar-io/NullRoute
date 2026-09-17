"""add vendor detection audit columns to scans (SIH26155 Part 1 section 4)

Revision ID: t5u6v7w8x9y0
Revises: s4t5u6v7w8x9
Create Date: 2026-09-16
"""
from alembic import op
import sqlalchemy as sa

revision = "t5u6v7w8x9y0"
down_revision = "s4t5u6v7w8x9"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("scans", sa.Column("vendor_detection_confidence", sa.Float(), nullable=True))
    op.add_column("scans", sa.Column("vendor_detection_method", sa.String(), nullable=True))
    op.add_column("scans", sa.Column("vendor_detection_evidence", sa.JSON(), nullable=True))
    op.add_column("scans", sa.Column("vendor_review_required", sa.Boolean(), nullable=True))


def downgrade():
    op.drop_column("scans", "vendor_review_required")
    op.drop_column("scans", "vendor_detection_evidence")
    op.drop_column("scans", "vendor_detection_method")
    op.drop_column("scans", "vendor_detection_confidence")