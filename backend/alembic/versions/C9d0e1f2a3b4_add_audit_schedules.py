"""add audit_schedules table (Phase 12 -- scheduled audits).

This is the migration app/models/db.py's AuditSchedule model and
app/workers/scheduler_worker.py depend on. It was missing entirely --
the next migration in the chain (d1e2f3a4b5c6_add_alerts) already
pointed its down_revision at this revision id, so this file closes that
gap rather than opening a new branch.

Revision ID: c9d0e1f2a3b4
Revises: a1b2c3d4e5f6
Create Date: 2026-09-04 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = 'c9d0e1f2a3b4'
down_revision = 'a1b2c3d4e5f6'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'audit_schedules',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('tenant_id', sa.String(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('scope', sa.JSON(), nullable=False),
        sa.Column('frequency', sa.String(), nullable=False, server_default='manual'),
        sa.Column('enabled', sa.Boolean(), server_default=sa.true()),
        sa.Column('framework', sa.String(), server_default='ALL'),
        sa.Column('created_by', sa.String(), nullable=True),
        sa.Column('last_run', sa.DateTime(), nullable=True),
        sa.Column('next_run', sa.DateTime(), nullable=True),
        sa.Column('last_run_status', sa.String(), nullable=True),
        sa.Column('last_run_detail', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_audit_schedules_tenant_id', 'audit_schedules', ['tenant_id'])
    op.create_index('ix_audit_schedules_next_run', 'audit_schedules', ['next_run'])


def downgrade():
    op.drop_index('ix_audit_schedules_next_run', table_name='audit_schedules')
    op.drop_index('ix_audit_schedules_tenant_id', table_name='audit_schedules')
    op.drop_table('audit_schedules')
