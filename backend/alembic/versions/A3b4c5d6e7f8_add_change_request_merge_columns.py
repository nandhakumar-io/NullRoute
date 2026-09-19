"""Add merge-engine columns to change_requests.

Wires services/config_merge.py (previously written but never called from
anywhere) into the Change Request create/preview flow: a CR created from a
CLI remediation delta records the delta itself (`snippet`) plus what the
merge engine did with it, so the detail endpoint can show the same
applied-commands/confidence/warnings breakdown the preview endpoint showed.

Revision ID: a3b4c5d6e7f8
Revises: z2a3b4c5d6e7
Create Date: 2026-09-19
"""
from alembic import op
import sqlalchemy as sa

revision = "a3b4c5d6e7f8"
down_revision = "z2a3b4c5d6e7"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("change_requests", sa.Column("snippet", sa.Text(), nullable=True))
    op.add_column("change_requests", sa.Column("merge_style", sa.String(), nullable=True))
    op.add_column("change_requests", sa.Column("merge_confidence", sa.String(), nullable=True))
    op.add_column("change_requests", sa.Column("merge_applied", sa.JSON(), nullable=True))
    op.add_column("change_requests", sa.Column("merge_warnings", sa.JSON(), nullable=True))
    op.add_column("change_requests", sa.Column("merge_commands", sa.JSON(), nullable=True))


def downgrade():
    op.drop_column("change_requests", "merge_commands")
    op.drop_column("change_requests", "merge_warnings")
    op.drop_column("change_requests", "merge_applied")
    op.drop_column("change_requests", "merge_confidence")
    op.drop_column("change_requests", "merge_style")
    op.drop_column("change_requests", "snippet")
