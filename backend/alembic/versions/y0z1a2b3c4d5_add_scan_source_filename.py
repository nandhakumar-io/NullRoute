"""add scans.source_filename

Revision ID: y0z1a2b3c4d5
Revises: x9y0z1a2b3c5
Create Date: 2026-09-20

Records the original file name of an uploaded configuration (single and bulk
upload) so the Validation list can tell apart scans that all share the one
"Ad-Hoc Config Uploads" sandbox device.
"""
from alembic import op
import sqlalchemy as sa

revision = "y0z1a2b3c4d5"
down_revision = "x9y0z1a2b3c5"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("scans", sa.Column("source_filename", sa.String(), nullable=True))


def downgrade():
    op.drop_column("scans", "source_filename")
