"""add report_artifacts table (Phase 8 -- MinIO artifact storage for
generated PDF/JSON/CSV reports). Referenced by routers/compliance.py
get_report(), which was already writing to this table before the ORM
model/migration existed.

Revision ID: a7b8c9d0e1f2
Revises: f6a7b8c9d0e1
Create Date: 2026-09-04 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = 'a7b8c9d0e1f2'
down_revision = 'f6a7b8c9d0e1'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'report_artifacts',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('tenant_id', sa.String(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('scan_id', sa.String(), sa.ForeignKey('scans.id'), nullable=False),
        sa.Column('format', sa.String(), nullable=False),
        sa.Column('object_key', sa.String(), nullable=True),
        sa.Column('object_bucket', sa.String(), nullable=True),
        sa.Column('sha256', sa.String(), nullable=False),
        sa.Column('size_bytes', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_report_artifacts_tenant_id', 'report_artifacts', ['tenant_id'])
    op.create_index('ix_report_artifacts_scan_id', 'report_artifacts', ['scan_id'])


def downgrade():
    op.drop_index('ix_report_artifacts_scan_id', table_name='report_artifacts')
    op.drop_index('ix_report_artifacts_tenant_id', table_name='report_artifacts')
    op.drop_table('report_artifacts')
