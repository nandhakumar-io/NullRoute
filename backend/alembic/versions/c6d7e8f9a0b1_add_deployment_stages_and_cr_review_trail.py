"""Deployment/rollback stage tracking + change-request HITL binding.

Adds:
  deployment_records.stages / rollback_records.stages   ordered per-stage progress
  change_requests.approved_revision / approved_hash     what the reviewer actually approved
  change_requests.review_comment / override_justification / review_events

The target_control_* / batfish_diff_* deployment columns were added by
b4c5d6e7f8a9 but never mapped on the model; they are mapped now.

Revision ID: c6d7e8f9a0b1
Revises: y0z1a2b3c4d5
Create Date: 2026-09-20
"""
from alembic import op
import sqlalchemy as sa

revision = "c6d7e8f9a0b1"
down_revision = "y0z1a2b3c4d5"
branch_labels = None
depends_on = None


def _has_col(table: str, column: str) -> bool:
    insp = sa.inspect(op.get_bind())
    return column in {c["name"] for c in insp.get_columns(table)}


def _add(table: str, column: sa.Column) -> None:
    if not _has_col(table, column.name):
        op.add_column(table, column)


def upgrade():
    _add("deployment_records", sa.Column("stages", sa.JSON(), nullable=True))
    _add("rollback_records", sa.Column("stages", sa.JSON(), nullable=True))
    _add("change_requests", sa.Column("approved_revision", sa.Integer(), nullable=True))
    _add("change_requests", sa.Column("approved_hash", sa.String(), nullable=True))
    _add("change_requests", sa.Column("review_comment", sa.Text(), nullable=True))
    _add("change_requests", sa.Column("override_justification", sa.Text(), nullable=True))
    _add("change_requests", sa.Column("review_events", sa.JSON(), nullable=True))


def downgrade():
    for table, col in (
        ("change_requests", "review_events"), ("change_requests", "override_justification"),
        ("change_requests", "review_comment"), ("change_requests", "approved_hash"),
        ("change_requests", "approved_revision"),
        ("rollback_records", "stages"), ("deployment_records", "stages"),
    ):
        if _has_col(table, col):
            op.drop_column(table, col)
