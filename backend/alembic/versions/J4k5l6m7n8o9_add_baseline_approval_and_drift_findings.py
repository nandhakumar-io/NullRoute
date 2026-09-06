"""Add baseline_approvals and security_drift_findings tables (Phase 2:
golden/approved baseline + normalized security baseline drift).
"""
from alembic import op
import sqlalchemy as sa

revision = "j4k5l6m7n8o9"
down_revision = "i3j4k5l6m7n8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "baseline_approvals",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("device_id", sa.String(), sa.ForeignKey("devices.id"), nullable=False),
        sa.Column("scan_id", sa.String(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("approved_by", sa.String(), nullable=False),
        sa.Column("approved_at", sa.DateTime(), nullable=True),
        sa.Column("approval_reason", sa.Text(), nullable=True),
    )
    op.create_index("ix_baseline_approvals_tenant_id", "baseline_approvals", ["tenant_id"])
    op.create_index("ix_baseline_approvals_device_id", "baseline_approvals", ["device_id"])

    op.create_table(
        "security_drift_findings",
        sa.Column("drift_id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("device_id", sa.String(), sa.ForeignKey("devices.id"), nullable=False),
        sa.Column("previous_scan_id", sa.String(), sa.ForeignKey("scans.id"), nullable=True),
        sa.Column("current_scan_id", sa.String(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("baseline_parameter", sa.String(), nullable=False),
        sa.Column("previous_value", sa.JSON(), nullable=True),
        sa.Column("current_value", sa.JSON(), nullable=True),
        sa.Column("drift_type", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=True),
        sa.Column("compliance_controls", sa.JSON(), nullable=True),
        sa.Column("evidence_reference", sa.String(), nullable=True),
        sa.Column("detected_at", sa.DateTime(), nullable=True),
        sa.Column("status", sa.String(), server_default="OPEN"),
        sa.Column("status_updated_by", sa.String(), nullable=True),
        sa.Column("status_updated_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_security_drift_findings_tenant_id", "security_drift_findings", ["tenant_id"])
    op.create_index("ix_security_drift_findings_device_id", "security_drift_findings", ["device_id"])
    op.create_index("ix_security_drift_findings_baseline_parameter", "security_drift_findings", ["baseline_parameter"])
    op.create_index("ix_security_drift_findings_detected_at", "security_drift_findings", ["detected_at"])


def downgrade() -> None:
    op.drop_index("ix_security_drift_findings_detected_at", table_name="security_drift_findings")
    op.drop_index("ix_security_drift_findings_baseline_parameter", table_name="security_drift_findings")
    op.drop_index("ix_security_drift_findings_device_id", table_name="security_drift_findings")
    op.drop_index("ix_security_drift_findings_tenant_id", table_name="security_drift_findings")
    op.drop_table("security_drift_findings")

    op.drop_index("ix_baseline_approvals_device_id", table_name="baseline_approvals")
    op.drop_index("ix_baseline_approvals_tenant_id", table_name="baseline_approvals")
    op.drop_table("baseline_approvals")