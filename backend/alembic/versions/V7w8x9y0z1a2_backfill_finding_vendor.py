"""Backfill Finding.vendor for pre-existing rows.

opa_decision_to_findings() (services/compliance.py) computed `vendor` from
the scan's baseline but never attached it to the dict it returned, so
every OPA-sourced Finding was written with vendor=NULL; the Batfish
finding-creation path in services/pipeline.py had the same gap. Both are
now fixed at the write site (see those files), but rows written before
that fix still have vendor=NULL, which silently empties two dashboard
views that filter/group on Finding.vendor:
  - GET /api/dashboard (vendor_scores)
  - GET /api/dashboard/compliance-matrix (the cross-vendor heatmap)
This one-time backfill sets vendor = Device.vendor (via Scan) for any
Finding row where it's still missing, so historical scans populate those
views immediately instead of only new scans going forward.

Revision ID: v7w8x9y0z1a2
Revises: u6v7w8x9y0z1
Create Date: 2026-09-17 00:00:00.000000
"""
from alembic import op

revision = "v7w8x9y0z1a2"
down_revision = "c6d7e8f9a0b1"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(
        """
        UPDATE findings
        SET vendor = devices.vendor
        FROM scans, devices
        WHERE findings.scan_id = scans.id
          AND scans.device_id = devices.id
          AND (findings.vendor IS NULL OR findings.vendor = '')
          AND devices.vendor IS NOT NULL
          AND devices.vendor <> ''
        """
    )


def downgrade():
    # Backfill is not reversible (original NULLs are not distinguishable
    # from real historical gaps); no-op.
    pass