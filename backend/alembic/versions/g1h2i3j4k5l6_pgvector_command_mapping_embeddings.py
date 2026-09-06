"""Real pgvector semantic retrieval for the Training Center knowledge base.

Converts command_mappings.embedding from a plain JSON list (a stand-in
noted directly in the model's docstring: "pgvector column in real PG
migration") into a native pgvector `vector(384)` column with an ivfflat
cosine index, so CommandMapping -> embedding -> pgvector -> cosine
similarity -> similar approved mappings (services/vector_search.py) is a
real vector-database query instead of a full-table Python scan.

Also adds indexes that were missing on hot lookup columns and were a
direct contributor to slow page loads: findings.scan_id (every scan-detail
page load queries by this), and command_mappings.status/vendor (every
Training Center list/approve view filters by these).

Postgres-only for the vector column/index (CREATE EXTENSION + `vector`
type don't exist on SQLite) -- guarded the same way every other
Postgres-specific DDL in this migration set is, by checking the bind's
dialect name before running it. SQLite dev/test installs keep the plain
JSON column (see app/models/db.py + services/vector_search.py's fallback
path), so this migration never breaks the offline path.

Revision ID: g1h2i3j4k5l6
Revises: f7a8b9c0d1e2
Create Date: 2026-09-06 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = 'g1h2i3j4k5l6'
down_revision = 'f7a8b9c0d1e2'
branch_labels = None
depends_on = None

EMBEDDING_DIM = 384


def upgrade():
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        # SQLite dev/test: nothing to do, embedding stays a plain JSON
        # column and app/services/vector_search.py uses its Python-side
        # cosine fallback instead of pgvector's <=> operator.
        return

    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    # Existing rows may have JSON-array embeddings (list[float] serialized
    # as JSON text) or NULL. `USING` re-casts non-null values through text
    # (a pgvector literal has the same `[1,2,3]` textual shape as a JSON
    # array of numbers, so this cast is lossless) rather than dropping data.
    op.execute(
        f"""
        ALTER TABLE command_mappings
        ALTER COLUMN embedding TYPE vector({EMBEDDING_DIM})
        USING (CASE WHEN embedding IS NULL THEN NULL ELSE embedding::text::vector({EMBEDDING_DIM}) END)
        """
    )

    # ivfflat requires at least some rows to build meaningful lists; lists=100
    # is a reasonable default for a knowledge base in the thousands-of-rows
    # range and can be re-tuned later without touching the column itself.
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_command_mappings_embedding_cosine
        ON command_mappings USING ivfflat (embedding vector_cosine_ops)
        WITH (lists = 100)
        """
    )

    op.create_index("ix_findings_scan_id", "findings", ["scan_id"], unique=False)
    op.create_index("ix_command_mappings_status", "command_mappings", ["status"], unique=False)
    op.create_index("ix_command_mappings_vendor", "command_mappings", ["vendor"], unique=False)


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    op.drop_index("ix_command_mappings_vendor", table_name="command_mappings")
    op.drop_index("ix_command_mappings_status", table_name="command_mappings")
    op.drop_index("ix_findings_scan_id", table_name="findings")
    op.execute("DROP INDEX IF EXISTS ix_command_mappings_embedding_cosine")
    op.execute(
        """
        ALTER TABLE command_mappings
        ALTER COLUMN embedding TYPE json USING embedding::text::json
        """
    )
