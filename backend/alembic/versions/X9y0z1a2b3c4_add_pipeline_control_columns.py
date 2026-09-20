"""add pipeline pause/stop/resume control columns to scans

Revision ID: x9y0z1a2b3c4
Revises: w8x9y0z1a2b3
Create Date: 2026-09-18

Adds the columns services/pipeline.py needs to support pausing, stopping,
and resuming a scan's pipeline at a stage boundary (spec: "add options to
pause / stop and resume the pipeline at any stage"):

  - control_state: the operator-facing control signal (RUNNING /
    PAUSE_REQUESTED / PAUSED / STOP_REQUESTED / STOPPED). An operator sets
    it to *_REQUESTED via the API; the running pipeline task is the only
    thing that ever moves it to PAUSED/STOPPED, at the next safe checkpoint.
  - pipeline_stage: which stage the pipeline is at/paused at (see
    pipeline.STAGE_ORDER) -- what resume_pipeline() reads to know where to
    pick back up, and what the UI shows as "Paused at: OPA evaluation".
  - paused_at / resumed_at / stopped_at: timestamps for the audit trail.
"""
from alembic import op
import sqlalchemy as sa

revision = "x9y0z1a2b3c5"
down_revision = "v7w8x9y0z1a2"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("scans", sa.Column("control_state", sa.String(), nullable=True, server_default="RUNNING"))
    op.add_column("scans", sa.Column("pipeline_stage", sa.String(), nullable=True))
    op.add_column("scans", sa.Column("paused_at", sa.DateTime(), nullable=True))
    op.add_column("scans", sa.Column("resumed_at", sa.DateTime(), nullable=True))
    op.add_column("scans", sa.Column("stopped_at", sa.DateTime(), nullable=True))


def downgrade():
    op.drop_column("scans", "stopped_at")
    op.drop_column("scans", "resumed_at")
    op.drop_column("scans", "paused_at")
    op.drop_column("scans", "pipeline_stage")
    op.drop_column("scans", "control_state")