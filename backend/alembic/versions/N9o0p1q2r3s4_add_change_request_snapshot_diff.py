"""Add ChangeRequest.snapshot_diff (Batfish CURRENT vs PROPOSED diff)

Wires batfish_service.compare_network_snapshots() into the Change Request
validation flow: services/change_request_service.py now builds a CURRENT
(last known device config) vs PROPOSED (the change request's proposed
config) Batfish snapshot pair and stores the diff here so an analyst can
see e.g. "this proposed ACL change makes Guest reach Management" before
approving, instead of discovering it after deployment.

Revision ID: n9o0p1q2r3s4
Revises: m8n9o0p1q2r3
Create Date: 2026-09-07 00:00:01.000000
"""
from alembic import op
import sqlalchemy as sa


revision = 'n9o0p1q2r3s4'
down_revision = 'L1m2n3o4p5q6'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'change_requests',
        sa.Column('snapshot_diff', sa.JSON(), nullable=True),
    )


def downgrade():
    op.drop_column('change_requests', 'snapshot_diff')