"""Add backup_destinations and backup_jobs tables (enterprise config backup/DR)

Revision ID: b9c1d2e3f4a5
Revises: 17135e725e5f
Create Date: 2026-09-09 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = 'b9c1d2e3f4a5'
down_revision = '17135e725e5f'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'backup_destinations',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('tenant_id', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('destination_type', sa.String(), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('config', sa.JSON(), nullable=False),
        sa.Column('credential_ref', sa.String(), nullable=True),
        sa.Column('auto_export_enabled', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('auto_export_scope', sa.JSON(), nullable=True),
        sa.Column('retention_days', sa.Integer(), nullable=True),
        sa.Column('last_test_status', sa.String(), nullable=True),
        sa.Column('last_test_at', sa.DateTime(), nullable=True),
        sa.Column('last_test_message', sa.Text(), nullable=True),
        sa.Column('last_export_status', sa.String(), nullable=True),
        sa.Column('last_export_at', sa.DateTime(), nullable=True),
        sa.Column('created_by', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_backup_destinations_tenant_id'), 'backup_destinations', ['tenant_id'], unique=False)

    op.create_table(
        'backup_jobs',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('tenant_id', sa.String(), nullable=False),
        sa.Column('destination_id', sa.String(), nullable=False),
        sa.Column('device_id', sa.String(), nullable=False),
        sa.Column('scan_id', sa.String(), nullable=False),
        sa.Column('trigger', sa.String(), nullable=False, server_default='manual'),
        sa.Column('status', sa.String(), nullable=False, server_default='PENDING'),
        sa.Column('remote_path', sa.String(), nullable=True),
        sa.Column('bytes_written', sa.Integer(), nullable=True),
        sa.Column('sha256', sa.String(), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
        sa.Column('triggered_by', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
        sa.ForeignKeyConstraint(['destination_id'], ['backup_destinations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_backup_jobs_tenant_id'), 'backup_jobs', ['tenant_id'], unique=False)
    op.create_index(op.f('ix_backup_jobs_destination_id'), 'backup_jobs', ['destination_id'], unique=False)
    op.create_index(op.f('ix_backup_jobs_device_id'), 'backup_jobs', ['device_id'], unique=False)
    op.create_index(op.f('ix_backup_jobs_scan_id'), 'backup_jobs', ['scan_id'], unique=False)
    op.create_index(op.f('ix_backup_jobs_status'), 'backup_jobs', ['status'], unique=False)
    op.create_index(op.f('ix_backup_jobs_created_at'), 'backup_jobs', ['created_at'], unique=False)


def downgrade():
    op.drop_table('backup_jobs')
    op.drop_table('backup_destinations')