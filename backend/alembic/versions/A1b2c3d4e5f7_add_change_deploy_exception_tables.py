"""add deployment_records, compliance_exceptions
(Phase 15 deployment, Phase 16 exceptions).

NOTE: this migration originally also created 'change_requests', but that
table is already created by e1f2a3b4c5d6_add_change_requests.py (a sibling
migration that forked off the same parent, c9d0e1f2a3b4, on a different
branch). Having two migrations both create 'change_requests' produced two
alembic heads and, if both were ever applied, a duplicate-table failure —
and the schema created here didn't even match what
app/services/change_request_service.py actually uses (e.g. 'source',
'syntax_status', 'validation_detail', 'current_config_object_key' live in
e1f2a3b4c5d6's version, not this one). Fixed by re-parenting this
migration onto e1f2a3b4c5d6 and dropping its 'change_requests' table
creation, keeping only the two tables that don't exist anywhere else.

Revision ID: a1b2c3d4e5f7
Revises: e1f2a3b4c5d6
Create Date: 2026-09-04 00:00:01.000000
"""
from alembic import op
import sqlalchemy as sa


revision = 'a1b2c3d4e5f7'
down_revision = 'e1f2a3b4c5d6'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'deployment_records',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('tenant_id', sa.String(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('change_request_id', sa.String(), sa.ForeignKey('change_requests.id'), nullable=False),
        sa.Column('device_id', sa.String(), sa.ForeignKey('devices.id'), nullable=False),
        sa.Column('initiated_by', sa.String(), nullable=True),
        sa.Column('transport', sa.String(), nullable=True),
        sa.Column('expected_pre_hash', sa.String(), nullable=True),
        sa.Column('observed_pre_hash', sa.String(), nullable=True),
        sa.Column('status', sa.String(), server_default='PENDING'),
        sa.Column('post_config_hash', sa.String(), nullable=True),
        sa.Column('post_verification_passed', sa.Boolean(), nullable=True),
        sa.Column('post_scan_id', sa.String(), sa.ForeignKey('scans.id'), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_deployment_records_tenant_id', 'deployment_records', ['tenant_id'])
    op.create_index('ix_deployment_records_change_request_id', 'deployment_records', ['change_request_id'])
    op.create_index('ix_deployment_records_device_id', 'deployment_records', ['device_id'])

    op.create_table(
        'compliance_exceptions',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('tenant_id', sa.String(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('device_id', sa.String(), sa.ForeignKey('devices.id'), nullable=False),
        sa.Column('control_id', sa.String(), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('created_by', sa.String(), nullable=True),
        sa.Column('approved_by', sa.String(), nullable=True),
        sa.Column('approved_at', sa.DateTime(), nullable=True),
        sa.Column('rejected_by', sa.String(), nullable=True),
        sa.Column('rejected_at', sa.DateTime(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('status', sa.String(), server_default='PENDING'),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_compliance_exceptions_tenant_id', 'compliance_exceptions', ['tenant_id'])
    op.create_index('ix_compliance_exceptions_device_id', 'compliance_exceptions', ['device_id'])
    op.create_index('ix_compliance_exceptions_control_id', 'compliance_exceptions', ['control_id'])
    op.create_index('ix_compliance_exceptions_status', 'compliance_exceptions', ['status'])


def downgrade():
    op.drop_table('compliance_exceptions')
    op.drop_table('deployment_records')