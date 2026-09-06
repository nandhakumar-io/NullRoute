"""Enterprise device inventory fields.

Adds the fields the /devices management UI needs beyond what live
collection (Phase 7) required: a display `name` distinct from `hostname`,
`site`/`environment` for fleet segmentation, a preferred `protocol` hint,
free-text `description`, `tags` (JSON list), an `enabled` flag for
soft-disabling a device without deleting its history, and `updated_at` for
audit/sort purposes. All nullable (or defaulted) so existing rows need no
backfill -- this is additive inventory metadata, not a new subsystem, and
does not touch DeviceCredentialRef (Phase 6) or any collection/compliance
table.

Revision ID: k5l6m7n8o9p0
Revises: j4k5l6m7n8o9
Create Date: 2026-09-06 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = 'k5l6m7n8o9p0'
down_revision = 'j4k5l6m7n8o9'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("devices", sa.Column("name", sa.String(), nullable=True))
    op.add_column("devices", sa.Column("site", sa.String(), nullable=True))
    op.add_column("devices", sa.Column("environment", sa.String(), nullable=True))
    op.add_column("devices", sa.Column("protocol", sa.String(), nullable=True))
    op.add_column("devices", sa.Column("description", sa.Text(), nullable=True))
    op.add_column("devices", sa.Column("tags", sa.JSON(), nullable=True))
    op.add_column(
        "devices",
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.add_column("devices", sa.Column("updated_at", sa.DateTime(), nullable=True))

    op.create_index("ix_devices_enabled", "devices", ["enabled"], unique=False)
    op.create_index("ix_devices_site", "devices", ["site"], unique=False)
    op.create_index("ix_devices_environment", "devices", ["environment"], unique=False)


def downgrade():
    op.drop_index("ix_devices_environment", table_name="devices")
    op.drop_index("ix_devices_site", table_name="devices")
    op.drop_index("ix_devices_enabled", table_name="devices")

    op.drop_column("devices", "updated_at")
    op.drop_column("devices", "enabled")
    op.drop_column("devices", "tags")
    op.drop_column("devices", "description")
    op.drop_column("devices", "protocol")
    op.drop_column("devices", "environment")
    op.drop_column("devices", "site")
    op.drop_column("devices", "name")