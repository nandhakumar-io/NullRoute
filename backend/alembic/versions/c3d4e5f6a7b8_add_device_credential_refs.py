"""add device_credential_refs table (Phase 6 OpenBao credential references)

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-09-04 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = 'c3d4e5f6a7b8'
down_revision = 'b2c3d4e5f6a7'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'device_credential_refs',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('tenant_id', sa.String(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('device_id', sa.String(), sa.ForeignKey('devices.id'), nullable=False),
        sa.Column('credential_ref', sa.String(), nullable=False, unique=True),
        sa.Column('credential_type', sa.String(), nullable=False),
        sa.Column('created_by', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('rotated_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_device_credential_refs_tenant_id', 'device_credential_refs', ['tenant_id'])
    op.create_index('ix_device_credential_refs_device_id', 'device_credential_refs', ['device_id'])


def downgrade():
    op.drop_index('ix_device_credential_refs_device_id', table_name='device_credential_refs')
    op.drop_index('ix_device_credential_refs_tenant_id', table_name='device_credential_refs')
    op.drop_table('device_credential_refs')
