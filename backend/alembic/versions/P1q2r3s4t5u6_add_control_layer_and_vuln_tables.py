"""Add unified control layer + vulnerability management tables.

Revision ID: p1q2r3s4t5u6
Revises: c0d1e2f3a4b6
Create Date: 2026-09-10 00:00:00.000000

NOTE: down_revision corrected during audit. o0p1q2r3s4t5 is NOT the true
head -- it already has a child (3e117b3e0a3d -> 17135e725e5f ->
b9c1d2e3f4a5 -> c0d1e2f3a4b6). Chaining off o0p1q2r3s4t5 directly created
two branch heads (p1q2r3s4t5u6 and c0d1e2f3a4b6), which `alembic upgrade
head` refuses to resolve. Chaining off the real current head instead.
"""
from alembic import op
import sqlalchemy as sa


revision = 'p1q2r3s4t5u6'
down_revision = 'c0d1e2f3a4b6'
branch_labels = None
depends_on = None


def upgrade():
    # -----------------------------------------------------------------------
    # Part 1: Unified Control Layer
    # -----------------------------------------------------------------------
    op.create_table(
        'unified_controls',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('tenant_id', sa.String(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('objective', sa.Text(), nullable=True),
        sa.Column('domain', sa.String(), nullable=True),
        sa.Column('source_text', sa.Text(), nullable=True),
        sa.Column('normalized_description', sa.Text(), nullable=True),
        sa.Column('status', sa.String(), nullable=False, server_default='pending_review'),
        sa.Column('source_document', sa.String(), nullable=True),
        sa.Column('created_by', sa.String(), nullable=True),
        sa.Column('approved_by', sa.String(), nullable=True),
        sa.Column('approved_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_unified_controls_tenant_id', 'unified_controls', ['tenant_id'])
    op.create_index('ix_unified_controls_domain', 'unified_controls', ['domain'])
    op.create_index('ix_unified_controls_status', 'unified_controls', ['status'])

    op.create_table(
        'framework_mappings',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('control_id', sa.String(), sa.ForeignKey('unified_controls.id'), nullable=False),
        sa.Column('framework', sa.String(), nullable=False),
        sa.Column('external_id', sa.String(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_framework_mappings_control_id', 'framework_mappings', ['control_id'])
    op.create_index('ix_framework_mappings_framework', 'framework_mappings', ['framework'])

    op.create_table(
        'config_concepts',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('control_id', sa.String(), sa.ForeignKey('unified_controls.id'), nullable=False),
        sa.Column('concept_name', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_config_concepts_control_id', 'config_concepts', ['control_id'])

    op.create_table(
        'vendor_config_patterns',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('concept_id', sa.String(), sa.ForeignKey('config_concepts.id'), nullable=False),
        sa.Column('vendor', sa.String(), nullable=False),
        sa.Column('pattern', sa.String(), nullable=False),
        sa.Column('example_snippet', sa.Text(), nullable=True),
        sa.Column('created_by', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_vendor_config_patterns_concept_id', 'vendor_config_patterns', ['concept_id'])
    op.create_index('ix_vendor_config_patterns_vendor', 'vendor_config_patterns', ['vendor'])

    op.create_table(
        'control_reviews',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('control_id', sa.String(), sa.ForeignKey('unified_controls.id'), nullable=False),
        sa.Column('reviewer', sa.String(), nullable=False),
        sa.Column('original_text', sa.Text(), nullable=True),
        sa.Column('proposed_change', sa.Text(), nullable=True),
        sa.Column('decision', sa.String(), nullable=False),
        sa.Column('correction_json', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_control_reviews_control_id', 'control_reviews', ['control_id'])

    # -----------------------------------------------------------------------
    # Part 2: Vulnerability Management Layer
    # -----------------------------------------------------------------------
    op.create_table(
        'vulnerabilities',
        sa.Column('cve_id', sa.String(), primary_key=True),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('severity', sa.String(), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('affected_cpe_ranges', sa.JSON(), nullable=True),
        sa.Column('kev_flag', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('published_date', sa.DateTime(), nullable=True),
        sa.Column('last_modified_date', sa.DateTime(), nullable=True),
        sa.Column('source', sa.String(), nullable=False, server_default='nvd'),
        sa.Column('remediation_advice', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_vulnerabilities_severity', 'vulnerabilities', ['severity'])

    op.create_table(
        'device_vulnerability_matches',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('tenant_id', sa.String(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('device_id', sa.String(), sa.ForeignKey('devices.id'), nullable=False),
        sa.Column('cve_id', sa.String(), sa.ForeignKey('vulnerabilities.cve_id'), nullable=False),
        sa.Column('matched_via', sa.String(), nullable=False),
        sa.Column('risk_priority_score', sa.Float(), nullable=True),
        sa.Column('status', sa.String(), nullable=False, server_default='open'),
        sa.Column('evidence', sa.JSON(), nullable=True),
        sa.Column('justification', sa.Text(), nullable=True),
        sa.Column('reviewed_by', sa.String(), nullable=True),
        sa.Column('reviewed_at', sa.DateTime(), nullable=True),
        sa.Column('linked_control_id', sa.String(), sa.ForeignKey('unified_controls.id'), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_device_vulnerability_matches_tenant_id', 'device_vulnerability_matches', ['tenant_id'])
    op.create_index('ix_device_vulnerability_matches_device_id', 'device_vulnerability_matches', ['device_id'])
    op.create_index('ix_device_vulnerability_matches_cve_id', 'device_vulnerability_matches', ['cve_id'])
    op.create_index('ix_device_vulnerability_matches_status', 'device_vulnerability_matches', ['status'])
    op.create_index('ix_device_vulnerability_matches_created_at', 'device_vulnerability_matches', ['created_at'])
    op.create_index('ix_device_vulnerability_matches_linked_control_id', 'device_vulnerability_matches', ['linked_control_id'])

    op.create_table(
        'document_ingestion_jobs',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('tenant_id', sa.String(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('filename', sa.String(), nullable=False),
        sa.Column('source_path', sa.String(), nullable=True),
        sa.Column('status', sa.String(), nullable=False, server_default='queued'),
        sa.Column('llm_used', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('controls_created', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('sections_found', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('warning', sa.Text(), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('created_by', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_document_ingestion_jobs_tenant_id', 'document_ingestion_jobs', ['tenant_id'])
    op.create_index('ix_document_ingestion_jobs_status', 'document_ingestion_jobs', ['status'])


def downgrade():
    op.drop_index('ix_document_ingestion_jobs_status', table_name='document_ingestion_jobs')
    op.drop_index('ix_document_ingestion_jobs_tenant_id', table_name='document_ingestion_jobs')
    op.drop_table('document_ingestion_jobs')

    op.drop_index('ix_device_vulnerability_matches_linked_control_id', table_name='device_vulnerability_matches')
    op.drop_index('ix_device_vulnerability_matches_created_at', table_name='device_vulnerability_matches')
    op.drop_index('ix_device_vulnerability_matches_status', table_name='device_vulnerability_matches')
    op.drop_index('ix_device_vulnerability_matches_cve_id', table_name='device_vulnerability_matches')
    op.drop_index('ix_device_vulnerability_matches_device_id', table_name='device_vulnerability_matches')
    op.drop_index('ix_device_vulnerability_matches_tenant_id', table_name='device_vulnerability_matches')
    op.drop_table('device_vulnerability_matches')

    op.drop_index('ix_vulnerabilities_severity', table_name='vulnerabilities')
    op.drop_table('vulnerabilities')

    op.drop_index('ix_control_reviews_control_id', table_name='control_reviews')
    op.drop_table('control_reviews')

    op.drop_index('ix_vendor_config_patterns_vendor', table_name='vendor_config_patterns')
    op.drop_index('ix_vendor_config_patterns_concept_id', table_name='vendor_config_patterns')
    op.drop_table('vendor_config_patterns')

    op.drop_index('ix_config_concepts_control_id', table_name='config_concepts')
    op.drop_table('config_concepts')

    op.drop_index('ix_framework_mappings_framework', table_name='framework_mappings')
    op.drop_index('ix_framework_mappings_control_id', table_name='framework_mappings')
    op.drop_table('framework_mappings')

    op.drop_index('ix_unified_controls_status', table_name='unified_controls')
    op.drop_index('ix_unified_controls_domain', table_name='unified_controls')
    op.drop_index('ix_unified_controls_tenant_id', table_name='unified_controls')
    op.drop_table('unified_controls')