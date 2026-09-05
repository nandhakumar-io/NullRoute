"""add alerts table (Phase 13 -- alerting).

Revision ID: d1e2f3a4b5c6
Revises: c9d0e1f2a3b4
Create Date: 2026-09-04 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = 'd1e2f3a4b5c6'
down_revision = 'c9d0e1f2a3b4'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'alerts',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('tenant_id', sa.String(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('category', sa.String(), nullable=False),
        sa.Column('severity', sa.String(), nullable=False, server_default='MEDIUM'),
        sa.Column('title', sa.String(), nullable=False),
        sa.Column('detail', sa.Text(), nullable=True),
        sa.Column('scan_id', sa.String(), sa.ForeignKey('scans.id'), nullable=True),
        sa.Column('device_id', sa.String(), sa.ForeignKey('devices.id'), nullable=True),
        sa.Column('extra', sa.JSON(), nullable=True),
        sa.Column('status', sa.String(), server_default='OPEN'),
        sa.Column('acknowledged_by', sa.String(), nullable=True),
        sa.Column('acknowledged_at', sa.DateTime(), nullable=True),
        sa.Column('dispatch_results', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_alerts_tenant_id', 'alerts', ['tenant_id'])
    op.create_index('ix_alerts_category', 'alerts', ['category'])
    op.create_index('ix_alerts_created_at', 'alerts', ['created_at'])


def downgrade():
    op.drop_index('ix_alerts_created_at', table_name='alerts')
    op.drop_index('ix_alerts_category', table_name='alerts')
    op.drop_index('ix_alerts_tenant_id', table_name='alerts')
    op.drop_table('alerts')