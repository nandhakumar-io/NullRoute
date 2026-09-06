"""Add gateway_jobs table (Device Gateway job ledger).

Backs replay/idempotency detection (job_id + nonce uniqueness) and the
audit trail of every job the Device Gateway has validated, independent of
in-memory state so it holds across gateway restarts/replicas.
"""
from alembic import op
import sqlalchemy as sa

revision = "i3j4k5l6m7n8"
down_revision = "h2i3j4k5l6m7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "gateway_jobs",
        sa.Column("job_id", sa.String(), primary_key=True),
        sa.Column("nonce", sa.String(), nullable=False, unique=True),
        sa.Column("tenant_id", sa.String(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("requester_id", sa.String(), nullable=False),
        sa.Column("device_id", sa.String(), sa.ForeignKey("devices.id"), nullable=False),
        sa.Column("operation", sa.String(), nullable=False),
        sa.Column("protocol", sa.String(), nullable=False),
        sa.Column("approval_id", sa.String(), nullable=True),
        sa.Column("status", sa.String(), server_default="RECEIVED"),
        sa.Column("error_code", sa.String(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("result_object_key", sa.String(), nullable=True),
        sa.Column("normalized_data", sa.JSON(), nullable=True),
        sa.Column("duration_ms", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_gateway_jobs_nonce", "gateway_jobs", ["nonce"])
    op.create_index("ix_gateway_jobs_tenant_id", "gateway_jobs", ["tenant_id"])
    op.create_index("ix_gateway_jobs_device_id", "gateway_jobs", ["device_id"])
    op.create_index("ix_gateway_jobs_created_at", "gateway_jobs", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_gateway_jobs_created_at", table_name="gateway_jobs")
    op.drop_index("ix_gateway_jobs_device_id", table_name="gateway_jobs")
    op.drop_index("ix_gateway_jobs_tenant_id", table_name="gateway_jobs")
    op.drop_index("ix_gateway_jobs_nonce", table_name="gateway_jobs")
    op.drop_table("gateway_jobs")