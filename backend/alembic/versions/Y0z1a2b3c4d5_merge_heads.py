"""merge heads (evidence_scan_id_nullable branch + schedule_time_of_day branch)

These two migration chains were already separate heads before this change
(pre-existing branch split, unrelated to the change_request.revision /
schedule.time_of_day work) -- `alembic upgrade head` fails with "Multiple
heads are present" until they're merged. No schema changes of its own.

Revision ID: y0z1a2b3c4d5
Revises: c5d6e7f8a9b0, x9y0z1a2b3c4
Create Date: 2026-09-20
"""
from alembic import op
import sqlalchemy as sa

revision = "y0z1a2b3c4d5"
down_revision = ("c5d6e7f8a9b0", "x9y0z1a2b3c4")
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass