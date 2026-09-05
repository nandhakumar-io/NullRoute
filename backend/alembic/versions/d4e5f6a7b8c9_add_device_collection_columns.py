"""add device collection columns (Phase 7 live device collection)

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-09-04 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = 'd4e5f6a7b8c9'
down_revision = 'c3d4e5f6a7b8'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('devices', sa.Column('management_address', sa.String(), nullable=True))
    op.add_column('devices', sa.Column('collection_status', sa.String(), nullable=True))
    op.add_column('devices', sa.Column('last_collected_at', sa.DateTime(), nullable=True))
    op.add_column('devices', sa.Column('last_collection_error', sa.Text(), nullable=True))
    op.add_column('devices', sa.Column('last_collection_transport', sa.String(), nullable=True))


def downgrade():
    op.drop_column('devices', 'last_collection_transport')
    op.drop_column('devices', 'last_collection_error')
    op.drop_column('devices', 'last_collected_at')
    op.drop_column('devices', 'collection_status')
    op.drop_column('devices', 'management_address')
