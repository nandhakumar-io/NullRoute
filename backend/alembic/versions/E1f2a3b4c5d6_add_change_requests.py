"""add change_requests table (Phase 14 -- change management + remediation).

Revision ID: e1f2a3b4c5d6
Revises: d1e2f3a4b5c6
Create Date: 2026-09-04 00:00:00.000000

NOTE: re-parented onto d1e2f3a4b5c6 (add_alerts) instead of its original
c9d0e1f2a3b4 -- both this migration and d1e2f3a4b5c6 had forked off
c9d0e1f2a3b4 independently, producing two alembic heads. Chaining them in
sequence (audit_schedules -> alerts -> change_requests -> deployment/
exceptions) restores a single linear head.
"""
from alembic import op
import sqlalchemy as sa


revision = 'e1f2a3b4c5d6'
down_revision = 'd1e2f3a4b5c6'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'change_requests',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('tenant_id', sa.String(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('device_id', sa.String(), sa.ForeignKey('devices.id'), nullable=False),
        sa.Column('created_by', sa.String(), nullable=True),
        sa.Column('source', sa.String(), server_default='manual'),
        sa.Column('current_config_object_key', sa.String(), nullable=True),
        sa.Column('current_config_hash', sa.String(), nullable=True),
        sa.Column('proposed_config_object_key', sa.String(), nullable=True),
        sa.Column('proposed_config_hash', sa.String(), nullable=False),
        sa.Column('status', sa.String(), server_default='DRAFT'),
        sa.Column('syntax_status', sa.String(), nullable=True),
        sa.Column('opa_decision', sa.String(), nullable=True),
        sa.Column('batfish_status', sa.String(), nullable=True),
        sa.Column('risk_score', sa.Integer(), nullable=True),
        sa.Column('risk_level', sa.String(), nullable=True),
        sa.Column('final_decision', sa.String(), nullable=True),
        sa.Column('final_reason', sa.Text(), nullable=True),
        sa.Column('validation_detail', sa.JSON(), nullable=True),
        sa.Column('approval_required', sa.Boolean(), server_default=sa.true()),
        sa.Column('approved_by', sa.String(), nullable=True),
        sa.Column('approved_at', sa.DateTime(), nullable=True),
        sa.Column('rejected_by', sa.String(), nullable=True),
        sa.Column('rejected_at', sa.DateTime(), nullable=True),
        sa.Column('rejection_reason', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_change_requests_tenant_id', 'change_requests', ['tenant_id'])
    op.create_index('ix_change_requests_device_id', 'change_requests', ['device_id'])
    op.create_index('ix_change_requests_status', 'change_requests', ['status'])
    op.create_index('ix_change_requests_created_at', 'change_requests', ['created_at'])


def downgrade():
    op.drop_index('ix_change_requests_created_at', table_name='change_requests')
    op.drop_index('ix_change_requests_status', table_name='change_requests')
    op.drop_index('ix_change_requests_device_id', table_name='change_requests')
    op.drop_index('ix_change_requests_tenant_id', table_name='change_requests')
    op.drop_table('change_requests')