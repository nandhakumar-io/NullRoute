"""Fix the ad-hoc-upload vendor bug.

The shared "Ad-Hoc Config Uploads" placeholder device (created by
routers/scans.py for anonymous, no-hostname config uploads) used to be
created with the literal string `vendor="Ad-Hoc"`. Every downstream
consumer treats a non-null `device.vendor` as an already-known, real
vendor (`device.vendor or guess.vendor` in pipeline.py, batfish_service,
remediation vendor hints, the baseline sent to OPA, and the denormalized
Finding.vendor used by vendor_scores / the cross-vendor compliance
matrix), so "Ad-Hoc" silently won every one of those checks and shadowed
the real per-upload vendor detect_vendor() computed for each file.

This adds a dedicated `is_adhoc_placeholder` flag so the row can still be
found/reused without overloading `vendor`, and repairs any existing row(s)
that have the bogus vendor value.

Revision ID: z2a3b4c5d6e7
Revises: y1z2a3b4c5d6
Create Date: 2026-09-19
"""
from alembic import op
import sqlalchemy as sa

revision = "z2a3b4c5d6e7"
down_revision = "x9y0z1a2b3c4"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "devices",
        sa.Column("is_adhoc_placeholder", sa.Boolean(), nullable=False, server_default="false"),
    )
    conn = op.get_bind()
    conn.execute(sa.text(
        "UPDATE devices SET is_adhoc_placeholder = TRUE, vendor = NULL "
        "WHERE hostname = 'Ad-Hoc Config Uploads' AND vendor = 'Ad-Hoc'"
    ))


def downgrade():
    op.drop_column("devices", "is_adhoc_placeholder")
