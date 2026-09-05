"""add evidence_object_key to evidence_records (Phase 8 -- MinIO artifact
storage). Stores the MinIO object key for the canonical evidence.json copy;
PostgreSQL keeps the JSON + hash regardless of whether the MinIO upload
succeeded (best-effort, see services/minio_service.py).

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-09-04 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = 'f6a7b8c9d0e1'
down_revision = 'e5f6a7b8c9d0'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('evidence_records', sa.Column('evidence_object_key', sa.String(), nullable=True))


def downgrade():
    op.drop_column('evidence_records', 'evidence_object_key')
