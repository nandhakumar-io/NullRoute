"""multi-tenancy: tenant_id on command_mappings/audit_log + tenant indexes

Revision ID: b2c3d4e5f6a7
Revises: a1f2b3c4d5e6
Create Date: 2026-09-04 01:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'b2c3d4e5f6a7'
down_revision = 'a1f2b3c4d5e6'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('command_mappings', sa.Column('tenant_id', sa.String(), nullable=True))
    op.create_index('ix_command_mappings_tenant_id', 'command_mappings', ['tenant_id'])

    op.add_column('audit_log', sa.Column('tenant_id', sa.String(), nullable=True))
    op.create_index('ix_audit_log_tenant_id', 'audit_log', ['tenant_id'])

    op.create_index('ix_devices_tenant_id', 'devices', ['tenant_id'])
    op.create_index('ix_scans_tenant_id', 'scans', ['tenant_id'])
    op.create_index('ix_evidence_records_tenant_id', 'evidence_records', ['tenant_id'])
    # ai_analyses.tenant_id was already indexed in a1f2b3c4d5e6 — nothing to add here.


def downgrade():
    op.drop_index('ix_evidence_records_tenant_id', table_name='evidence_records')
    op.drop_index('ix_scans_tenant_id', table_name='scans')
    op.drop_index('ix_devices_tenant_id', table_name='devices')

    op.drop_index('ix_audit_log_tenant_id', table_name='audit_log')
    op.drop_column('audit_log', 'tenant_id')

    op.drop_index('ix_command_mappings_tenant_id', table_name='command_mappings')
    op.drop_column('command_mappings', 'tenant_id')