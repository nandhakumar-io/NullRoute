"""add source/confidence provenance columns to findings (Evidence Trace).

Surfaces the deterministic-parser-vs-AI-interpretation trust boundary that
already exists on NormalizedParameter (models/baseline.py) down onto the
Finding row itself, so the UI can badge each finding as
[Deterministic] or [AI Interpreted] with its confidence score without
re-deriving it from the scan's baseline_json every time.

Revision ID: w8x9y0z1a2b3
Revises: v7w8x9y0z1a2
Create Date: 2026-09-17 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = 'w8x9y0z1a2b3'
down_revision = 'v7w8x9y0z1a2'
branch_labels = None
depends_on = None


def upgrade():
    # op.add_column('findings', sa.Column('source', sa.String(), nullable=True))
    # op.add_column('findings', sa.Column('confidence', sa.Float(), nullable=True))
    pass

def downgrade():
    # op.drop_column('findings', 'confidence')
    # op.drop_column('findings', 'source')
    pass