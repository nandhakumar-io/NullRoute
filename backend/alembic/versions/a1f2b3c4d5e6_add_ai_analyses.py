"""add ai_analyses table (Phase 1/2 trained-AI persistence)

Revision ID: a1f2b3c4d5e6
Revises: 0cecc91f91a6
Create Date: 2026-09-04 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'a1f2b3c4d5e6'
down_revision = '0cecc91f91a6'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'ai_analyses',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('scan_id', sa.String(), sa.ForeignKey('scans.id'), nullable=False),
        sa.Column('device_id', sa.String(), sa.ForeignKey('devices.id'), nullable=True),
        sa.Column('tenant_id', sa.String(), nullable=True),
        sa.Column('raw_command_hash', sa.String(), nullable=False),
        sa.Column('intent', sa.String(), nullable=False),
        sa.Column('classifier_confidence', sa.Float(), nullable=False),
        sa.Column('semantic_similarity', sa.Float(), nullable=False),
        sa.Column('nearest_intent', sa.String(), nullable=True),
        sa.Column('nearest_vendor', sa.String(), nullable=True),
        sa.Column('models_agree', sa.Boolean(), nullable=True),
        sa.Column('decision', sa.String(), nullable=False),
        sa.Column('requires_review', sa.Boolean(), nullable=True),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('model_version', sa.String(), nullable=True),
        sa.Column('inference_latency_ms', sa.Float(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_ai_analyses_scan_id', 'ai_analyses', ['scan_id'])
    op.create_index('ix_ai_analyses_tenant_id', 'ai_analyses', ['tenant_id'])


def downgrade():
    op.drop_index('ix_ai_analyses_tenant_id', table_name='ai_analyses')
    op.drop_index('ix_ai_analyses_scan_id', table_name='ai_analyses')
    op.drop_table('ai_analyses')
