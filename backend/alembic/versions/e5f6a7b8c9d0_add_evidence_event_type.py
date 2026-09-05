"""add event_type to evidence_records (bugfix -- column was written by
evidence_service.store_evidence() but never existed on the ORM model,
raising TypeError on every scan that reached evidence generation)

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-09-04 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = 'e5f6a7b8c9d0'
down_revision = 'd4e5f6a7b8c9'
branch_labels = None
depends_on = None


def upgrade():
    # NOTE: the initial_schema migration (0cecc91f91a6) already creates
    # evidence_records.event_type -- this migration predates that fix being
    # backported into initial_schema and would otherwise fail with
    # "duplicate column" on a fresh database. Guarded so `alembic upgrade
    # head` works both against a pre-existing DB from before the backport
    # (real add) and a fresh one (no-op).
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_columns = {c["name"] for c in inspector.get_columns("evidence_records")}
    if "event_type" not in existing_columns:
        op.add_column('evidence_records', sa.Column('event_type', sa.String(), nullable=True))


def downgrade():
    op.drop_column('evidence_records', 'event_type')