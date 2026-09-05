"""add drift_events table (Phase 11 -- configuration drift).

Revision ID: a1b2c3d4e5f6
Revises: b8c9d0e1f2a3
Create Date: 2026-09-04 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = 'a1b2c3d4e5f6'
down_revision = 'b8c9d0e1f2a3'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'drift_events',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('tenant_id', sa.String(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('device_id', sa.String(), sa.ForeignKey('devices.id'), nullable=False),
        sa.Column('previous_scan_id', sa.String(), sa.ForeignKey('scans.id'), nullable=True),
        sa.Column('current_scan_id', sa.String(), sa.ForeignKey('scans.id'), nullable=False),
        sa.Column('previous_config_hash', sa.String(), nullable=True),
        sa.Column('current_config_hash', sa.String(), nullable=False),
        sa.Column('added_lines', sa.JSON(), nullable=True),
        sa.Column('removed_lines', sa.JSON(), nullable=True),
        sa.Column('changed_sections', sa.JSON(), nullable=True),
        sa.Column('security_impacting', sa.Boolean(), nullable=True),
        sa.Column('affected_controls', sa.JSON(), nullable=True),
        sa.Column('pipeline_rerun_triggered', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_drift_events_tenant_id', 'drift_events', ['tenant_id'])
    op.create_index('ix_drift_events_device_id', 'drift_events', ['device_id'])
    op.create_index('ix_drift_events_created_at', 'drift_events', ['created_at'])


def downgrade():
    op.drop_index('ix_drift_events_created_at', table_name='drift_events')
    op.drop_index('ix_drift_events_device_id', table_name='drift_events')
    op.drop_index('ix_drift_events_tenant_id', table_name='drift_events')
    op.drop_table('drift_events')