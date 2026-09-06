"""Section 12: extend audit_log with structured who/what/when/source-IP/
object/old-value/new-value/result columns.

Revision ID: h2i3j4k5l6m7
Revises: g1h2i3j4k5l6
Create Date: 2026-09-06
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "h2i3j4k5l6m7"
down_revision = "g1h2i3j4k5l6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("audit_log") as batch_op:
        batch_op.add_column(sa.Column("user_id", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("username", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("source_ip", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("object_type", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("object_id", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("old_value", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("new_value", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("result", sa.String(), nullable=True))

    op.create_index("ix_audit_log_user_id", "audit_log", ["user_id"])
    op.create_index("ix_audit_log_object_type", "audit_log", ["object_type"])
    op.create_index("ix_audit_log_object_id", "audit_log", ["object_id"])
    op.create_index("ix_audit_log_result", "audit_log", ["result"])
    op.create_index("ix_audit_log_created_at", "audit_log", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_audit_log_created_at", table_name="audit_log")
    op.drop_index("ix_audit_log_result", table_name="audit_log")
    op.drop_index("ix_audit_log_object_id", table_name="audit_log")
    op.drop_index("ix_audit_log_object_type", table_name="audit_log")
    op.drop_index("ix_audit_log_user_id", table_name="audit_log")
    with op.batch_alter_table("audit_log") as batch_op:
        batch_op.drop_column("result")
        batch_op.drop_column("new_value")
        batch_op.drop_column("old_value")
        batch_op.drop_column("object_id")
        batch_op.drop_column("object_type")
        batch_op.drop_column("source_ip")
        batch_op.drop_column("username")
        batch_op.drop_column("user_id")