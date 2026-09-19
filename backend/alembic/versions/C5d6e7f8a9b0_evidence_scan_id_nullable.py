"""Make evidence_records.scan_id nullable.

Needed so deployment/rollback events (services/evidence_service.py::
anchor_event, called from deployment_service.py and rollback_service.py)
can be anchored even when they fail before a post-deploy/post-rollback
Scan exists -- e.g. a push failure or a pre-deploy stale-hash abort. The
audit trail for a *failed* deployment is exactly the kind of event this
ledger exists to preserve, not just successful scans.

Revision ID: c5d6e7f8a9b0
Revises: b4c5d6e7f8a9
Create Date: 2026-09-19
"""
from alembic import op
import sqlalchemy as sa

revision = "c5d6e7f8a9b0"
down_revision = "b4c5d6e7f8a9"
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column("evidence_records", "scan_id", existing_type=sa.String(), nullable=True)


def downgrade():
    op.execute("DELETE FROM evidence_records WHERE scan_id IS NULL")
    op.alter_column("evidence_records", "scan_id", existing_type=sa.String(), nullable=False)
