"""Add EvidenceRecord.last_verified_at / last_verification_status

Supports the new periodic evidence-verification worker (app/workers/
evidence_verification_worker.py), which sweeps EvidenceRecord rows on a
schedule (oldest-checked first) instead of relying on someone to click
"Verify" in the Evidence Ledger UI.

Revision ID: o0p1q2r3s4t5
Revises: n9o0p1q2r3s4
Create Date: 2026-09-07 00:00:02.000000
"""
from alembic import op
import sqlalchemy as sa


revision = 'o0p1q2r3s4t5'
down_revision = 'n9o0p1q2r3s4'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('evidence_records', sa.Column('last_verified_at', sa.DateTime(), nullable=True))
    op.add_column('evidence_records', sa.Column('last_verification_status', sa.String(), nullable=True))


def downgrade():
    op.drop_column('evidence_records', 'last_verification_status')
    op.drop_column('evidence_records', 'last_verified_at')