"""add OpenConfig/gNMI + pyATS/Genie metadata columns to deployment_records
(spec sections 22-34, 47, 53).

Additive-only migration: adds nullable columns to the existing
deployment_records table so pre-existing SSH-transport deployment rows
remain valid with these fields NULL. Never stores credentials -- only
request hash, model/paths/operation actually sent, and supplemental
pyATS/Genie verification status.

Revision ID: f7a8b9c0d1e2
Revises: a1b2c3d4e5f7
Create Date: 2026-09-05 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "f7a8b9c0d1e2"
down_revision = "a1b2c3d4e5f7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("deployment_records", sa.Column("request_hash", sa.String(), nullable=True))
    op.add_column("deployment_records", sa.Column("model_name", sa.String(), nullable=True))
    op.add_column("deployment_records", sa.Column("paths", sa.JSON(), nullable=True))
    op.add_column("deployment_records", sa.Column("operation", sa.String(), nullable=True))
    op.add_column("deployment_records", sa.Column("verification_engine", sa.String(), nullable=True))
    op.add_column("deployment_records", sa.Column("verification_result", sa.String(), nullable=True))
    op.add_column("deployment_records", sa.Column("verification_metadata", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("deployment_records", "verification_metadata")
    op.drop_column("deployment_records", "verification_result")
    op.drop_column("deployment_records", "verification_engine")
    op.drop_column("deployment_records", "operation")
    op.drop_column("deployment_records", "paths")
    op.drop_column("deployment_records", "model_name")
    op.drop_column("deployment_records", "request_hash")