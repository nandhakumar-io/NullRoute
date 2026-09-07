"""Add Hitl training, datasets, models tables

Revision ID: L1m2n3o4p5q6
Revises: h2i3j4k5l6m7
Create Date: 2026-09-06 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'L1m2n3o4p5q6'
down_revision = 'network_scan_jobs'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "training_examples",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), sa.ForeignKey("tenants.id"), nullable=True, index=True),
        sa.Column("source_scan_id", sa.String(), sa.ForeignKey("scans.id"), nullable=True),
        sa.Column("source_device_id", sa.String(), sa.ForeignKey("devices.id"), nullable=True),
        sa.Column("source_mapping_id", sa.String(), sa.ForeignKey("command_mappings.id"), nullable=True),
        sa.Column("raw_config_hash", sa.String(), nullable=False),
        sa.Column("raw_config_redacted", sa.Text(), nullable=False),
        sa.Column("vendor", sa.String(), nullable=True),
        sa.Column("intent", sa.String(), nullable=True),
        sa.Column("normalized_facts", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("human_action", sa.String(), nullable=False),
        sa.Column("correction_reason", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("dataset_version", sa.String(), nullable=True),
        sa.Column("embedding_id", sa.String(), nullable=True),
        sa.Column("validation_status", sa.String(), server_default="PENDING"),
    )
    op.create_index("ix_training_examples_tenant_id", "training_examples", ["tenant_id"])
    op.create_index("ix_training_examples_created_at", "training_examples", ["created_at"])

    op.create_table(
        "dataset_versions",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("version", sa.String(), nullable=False),
        sa.Column("tenant_id", sa.String(), sa.ForeignKey("tenants.id"), nullable=True, index=True),
        sa.Column("created_by", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("example_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("label_distribution", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("vendor_distribution", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("source_distribution", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("validation_status", sa.String(), nullable=True),
        sa.Column("training_status", sa.String(), nullable=True),
        sa.Column("dataset_hash", sa.String(), nullable=False),
        sa.Column("is_immutable", sa.Boolean(), server_default=sa.true()),
    )
    op.create_index("ix_dataset_versions_version", "dataset_versions", ["version"], unique=True)
    op.create_index("ix_dataset_versions_tenant_id", "dataset_versions", ["tenant_id"])

    op.create_table(
        "training_jobs",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), sa.ForeignKey("tenants.id"), nullable=True, index=True),
        sa.Column("dataset_version_id", sa.String(), sa.ForeignKey("dataset_versions.id"), nullable=False),
        sa.Column("base_model_version", sa.String(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("status", sa.String(), server_default="QUEUED"),
        sa.Column("artifact_path", sa.String(), nullable=True),
        sa.Column("metrics", sa.JSON(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(), nullable=False),
    )
    op.create_index("ix_training_jobs_tenant_id", "training_jobs", ["tenant_id"])
    op.create_index("ix_training_jobs_status", "training_jobs", ["status"])

    op.create_table(
        "model_registry_entries",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("model_name", sa.String(), nullable=False),
        sa.Column("model_type", sa.String(), nullable=False),
        sa.Column("dataset_version", sa.String(), nullable=False),
        sa.Column("base_model_version", sa.String(), nullable=True),
        sa.Column("artifact_path", sa.String(), nullable=True),
        sa.Column("model_hash", sa.String(), nullable=True),
        sa.Column("metrics", sa.JSON(), nullable=True, server_default="{}"),
        sa.Column("training_timestamp", sa.DateTime(), nullable=True),
        sa.Column("status", sa.String(), server_default="CANDIDATE"),
        sa.Column("created_by", sa.String(), nullable=False),
        sa.Column("approved_by", sa.String(), nullable=True),
        sa.Column("approved_at", sa.DateTime(), nullable=True),
        sa.Column("training_job_id", sa.String(), sa.ForeignKey("training_jobs.id"), nullable=True),
    )
    op.create_index("ix_model_registry_entries_status", "model_registry_entries", ["status"])


def downgrade():
    op.drop_index("ix_model_registry_entries_status", table_name="model_registry_entries")
    op.drop_table("model_registry_entries")

    op.drop_index("ix_training_jobs_status", table_name="training_jobs")
    op.drop_index("ix_training_jobs_tenant_id", table_name="training_jobs")
    op.drop_table("training_jobs")

    op.drop_index("ix_dataset_versions_tenant_id", table_name="dataset_versions")
    op.drop_index("ix_dataset_versions_version", table_name="dataset_versions")
    op.drop_table("dataset_versions")

    op.drop_index("ix_training_examples_created_at", table_name="training_examples")
    op.drop_index("ix_training_examples_tenant_id", table_name="training_examples")
    op.drop_table("training_examples")
