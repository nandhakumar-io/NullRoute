"""Add alert_channels, alert_rules, push_subscriptions tables (enterprise alerting)

Revision ID: c0d1e2f3a4b6
Revises: b9c1d2e3f4a5
Create Date: 2026-09-09 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = 'c0d1e2f3a4b6'
down_revision = 'b9c1d2e3f4a5'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'alert_channels',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('tenant_id', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('channel_type', sa.String(), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('config', sa.JSON(), nullable=False),
        sa.Column('credential_ref', sa.String(), nullable=True),
        sa.Column('last_test_status', sa.String(), nullable=True),
        sa.Column('last_test_at', sa.DateTime(), nullable=True),
        sa.Column('last_test_message', sa.Text(), nullable=True),
        sa.Column('created_by', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_alert_channels_tenant_id', 'alert_channels', ['tenant_id'])

    op.create_table(
        'alert_rules',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('tenant_id', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('match_categories', sa.JSON(), nullable=True),
        sa.Column('match_severities', sa.JSON(), nullable=True),
        sa.Column('channel_ids', sa.JSON(), nullable=False),
        sa.Column('options', sa.JSON(), nullable=True),
        sa.Column('created_by', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_alert_rules_tenant_id', 'alert_rules', ['tenant_id'])

    op.create_table(
        'push_subscriptions',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('tenant_id', sa.String(), nullable=False),
        sa.Column('user_subject', sa.String(), nullable=True),
        sa.Column('endpoint', sa.Text(), nullable=False),
        sa.Column('p256dh', sa.String(), nullable=False),
        sa.Column('auth', sa.String(), nullable=False),
        sa.Column('user_agent', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('endpoint', name='uq_push_subscriptions_endpoint'),
    )
    op.create_index('ix_push_subscriptions_tenant_id', 'push_subscriptions', ['tenant_id'])


def downgrade():
    op.drop_index('ix_push_subscriptions_tenant_id', table_name='push_subscriptions')
    op.drop_table('push_subscriptions')
    op.drop_index('ix_alert_rules_tenant_id', table_name='alert_rules')
    op.drop_table('alert_rules')
    op.drop_index('ix_alert_channels_tenant_id', table_name='alert_channels')
    op.drop_table('alert_channels')