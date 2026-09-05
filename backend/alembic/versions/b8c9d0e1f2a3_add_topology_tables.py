"""add inventory/topology tables: network_interfaces, vlans, vrfs,
network_routes, network_links (Phase 9)

Revision ID: b8c9d0e1f2a3
Revises: a7b8c9d0e1f2
Create Date: 2026-09-04 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = 'b8c9d0e1f2a3'
down_revision = 'a7b8c9d0e1f2'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'network_interfaces',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('tenant_id', sa.String(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('device_id', sa.String(), sa.ForeignKey('devices.id'), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('ip_address', sa.String(), nullable=True),
        sa.Column('subnet_mask', sa.String(), nullable=True),
        sa.Column('vlan', sa.String(), nullable=True),
        sa.Column('vrf', sa.String(), nullable=True),
        sa.Column('admin_state', sa.String(), nullable=True),
        sa.Column('scan_id', sa.String(), sa.ForeignKey('scans.id'), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_network_interfaces_tenant_id', 'network_interfaces', ['tenant_id'])
    op.create_index('ix_network_interfaces_device_id', 'network_interfaces', ['device_id'])

    op.create_table(
        'vlans',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('tenant_id', sa.String(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('device_id', sa.String(), sa.ForeignKey('devices.id'), nullable=False),
        sa.Column('vlan_id', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=True),
        sa.Column('scan_id', sa.String(), sa.ForeignKey('scans.id'), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_vlans_tenant_id', 'vlans', ['tenant_id'])
    op.create_index('ix_vlans_device_id', 'vlans', ['device_id'])

    op.create_table(
        'vrfs',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('tenant_id', sa.String(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('device_id', sa.String(), sa.ForeignKey('devices.id'), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('route_distinguisher', sa.String(), nullable=True),
        sa.Column('scan_id', sa.String(), sa.ForeignKey('scans.id'), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_vrfs_tenant_id', 'vrfs', ['tenant_id'])
    op.create_index('ix_vrfs_device_id', 'vrfs', ['device_id'])

    op.create_table(
        'network_routes',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('tenant_id', sa.String(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('device_id', sa.String(), sa.ForeignKey('devices.id'), nullable=False),
        sa.Column('destination', sa.String(), nullable=False),
        sa.Column('mask', sa.String(), nullable=True),
        sa.Column('next_hop', sa.String(), nullable=True),
        sa.Column('vrf', sa.String(), nullable=True),
        sa.Column('scan_id', sa.String(), sa.ForeignKey('scans.id'), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_network_routes_tenant_id', 'network_routes', ['tenant_id'])
    op.create_index('ix_network_routes_device_id', 'network_routes', ['device_id'])

    op.create_table(
        'network_links',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('tenant_id', sa.String(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('source_device_id', sa.String(), sa.ForeignKey('devices.id'), nullable=False),
        sa.Column('source_interface', sa.String(), nullable=True),
        sa.Column('target_device_id', sa.String(), sa.ForeignKey('devices.id'), nullable=False),
        sa.Column('target_interface', sa.String(), nullable=True),
        sa.Column('link_type', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_network_links_tenant_id', 'network_links', ['tenant_id'])


def downgrade():
    op.drop_index('ix_network_links_tenant_id', table_name='network_links')
    op.drop_table('network_links')
    op.drop_index('ix_network_routes_device_id', table_name='network_routes')
    op.drop_index('ix_network_routes_tenant_id', table_name='network_routes')
    op.drop_table('network_routes')
    op.drop_index('ix_vrfs_device_id', table_name='vrfs')
    op.drop_index('ix_vrfs_tenant_id', table_name='vrfs')
    op.drop_table('vrfs')
    op.drop_index('ix_vlans_device_id', table_name='vlans')
    op.drop_index('ix_vlans_tenant_id', table_name='vlans')
    op.drop_table('vlans')
    op.drop_index('ix_network_interfaces_device_id', table_name='network_interfaces')
    op.drop_index('ix_network_interfaces_tenant_id', table_name='network_interfaces')
    op.drop_table('network_interfaces')
