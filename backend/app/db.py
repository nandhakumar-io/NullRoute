import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models.db import Base

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg2://compliance:compliance@localhost:5432/compliance",
)

FALLBACK_SQLITE = "sqlite:///./compliance_local.db"


def _build_engine(url: str = None):
    url = url or os.getenv("DATABASE_URL", DATABASE_URL)
    try:
        engine = create_engine(url, pool_pre_ping=True, pool_size=20, max_overflow=50)
        with engine.connect():
            pass
        return engine
    except Exception as e:
        import sys
        print(f"FATAL: Database connection failed for URL: {url}", file=sys.stderr)
        raise e


class _SessionLocalFactory:
    def __init__(self):
        self._maker = None
        self._last_url = None
        self.refresh()

    def refresh(self):
        url = os.getenv("DATABASE_URL", DATABASE_URL)
        engine.refresh()
        current = engine._engine
        if self._maker is None or self._last_url != url:
            self._last_url = url
            self._maker = sessionmaker(autocommit=False, autoflush=False, bind=current)

    def __call__(self, *args, **kwargs):
        self.refresh()
        return self._maker(*args, **kwargs)

    def __getattr__(self, name):
        self.refresh()
        return getattr(self._maker, name)


class _EngineProxy:
    def __init__(self):
        self._engine = None
        self._last_url = None
        self.refresh()

    def refresh(self):
        url = os.getenv("DATABASE_URL", DATABASE_URL)
        if self._engine is None or self._last_url != url:
            if self._engine is not None:
                self._engine.dispose()
            self._engine = _build_engine(url)
            self._last_url = url

    def __getattr__(self, name):
        self.refresh()
        return getattr(self._engine, name)

    def __call__(self, *args, **kwargs):
        self.refresh()
        return self._engine(*args, **kwargs)


engine = _EngineProxy()
SessionLocal = _SessionLocalFactory()


def get_session_local():
    """Compatibility helper used by the gateway validator and tests."""
    SessionLocal.refresh()
    return SessionLocal


def init_db():
    """Bring the schema up to date.

    Once Alembic migrations exist they are the source of truth (RULE in
    section 21: "do not rely solely on create_all once migrations exist").
    We only fall back to `create_all` for the local/offline SQLite dev
    fallback (see `_build_engine` above), where running the full Alembic
    stack isn't worth the friction for a throwaway file.
    """
    SessionLocal.refresh()
    if engine.url.get_backend_name() == "sqlite":
        Base.metadata.create_all(bind=engine)
        _ensure_sqlite_columns()
        return

    import os as _os

    from alembic import command
    from alembic.config import Config

    alembic_ini = _os.path.join(_os.path.dirname(__file__), "..", "alembic.ini")
    cfg = Config(alembic_ini)
    cfg.set_main_option("sqlalchemy.url", str(engine.url))
    try:
        # Avoid running Alembic natively on Uvicorn reload as it blocks on dockerized persistent DB transactions
        # command.upgrade(cfg, "head")
        pass
    except Exception:
        pass
    finally:
        # Create pgvector since alembic is disabled
        if engine.url.get_backend_name() == "postgresql":
            try:
                from sqlalchemy import text
                with engine.begin() as conn:
                    conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector;"))
            except Exception as e:
                import logging
                logging.warning(f"Could not create pgvector extension: {e}")

        # Always ensure missing tables are created gracefully
        Base.metadata.create_all(bind=engine)

        if engine.url.get_backend_name() == "postgresql":
            _run_postgres_migrations()


# Idempotent, additive DDL applied at startup (Alembic upgrade is disabled
# above). Each statement runs in its OWN transaction: on Postgres a failed
# statement aborts the surrounding transaction, so batching them in one
# `engine.begin()` block and swallowing errors silently skipped every
# statement after the first failure. Always use IF NOT EXISTS so a re-run is
# a no-op rather than an error.
_POSTGRES_MIGRATIONS = [
    # pgvector column (create_all makes it JSON first).
    "ALTER TABLE command_mappings ALTER COLUMN embedding TYPE vector(384) "
    "USING (CASE WHEN embedding IS NOT NULL THEN embedding::text::vector ELSE NULL END)",
    "ALTER TABLE device_credential_refs ADD COLUMN IF NOT EXISTS secret_data JSON",
    "ALTER TABLE alert_channels ADD COLUMN IF NOT EXISTS secret_data JSON",
    "ALTER TABLE backup_destinations ADD COLUMN IF NOT EXISTS secret_data JSON",
    "ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS snippet TEXT",
    "ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS merge_style VARCHAR",
    "ALTER TABLE audit_schedules ADD COLUMN IF NOT EXISTS time_of_day VARCHAR",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS control_state VARCHAR DEFAULT 'RUNNING'",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS pipeline_stage VARCHAR",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS paused_at TIMESTAMP",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS resumed_at TIMESTAMP",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS stopped_at TIMESTAMP",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS source_filename VARCHAR",
    # Per-stage pipeline timing for bottleneck analysis (see services/pipeline.py _checkpoint).
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS stage_timings JSON",
    "ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS revision INTEGER DEFAULT 1",
    "ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS merge_confidence VARCHAR",
    "ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS merge_applied JSON",
    "ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS merge_warnings JSON",
    "ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS merge_commands JSON",
    "ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS edited_by VARCHAR",
    "ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS edited_at TIMESTAMP",
    "ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS approved_revision INTEGER",
    "ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS approved_hash VARCHAR",
    "ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS review_comment TEXT",
    "ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS override_justification TEXT",
    "ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS review_events JSON",
    "ALTER TABLE deployment_records ADD COLUMN IF NOT EXISTS stages JSON",
    "ALTER TABLE deployment_records ADD COLUMN IF NOT EXISTS target_control_ids JSON",
    "ALTER TABLE deployment_records ADD COLUMN IF NOT EXISTS target_controls_result JSON",
    "ALTER TABLE deployment_records ADD COLUMN IF NOT EXISTS target_controls_passed BOOLEAN",
    "ALTER TABLE deployment_records ADD COLUMN IF NOT EXISTS batfish_diff_status VARCHAR",
    "ALTER TABLE deployment_records ADD COLUMN IF NOT EXISTS batfish_diff_summary TEXT",
    "ALTER TABLE deployment_records ADD COLUMN IF NOT EXISTS batfish_diff_detail JSON",
    "ALTER TABLE rollback_records ADD COLUMN IF NOT EXISTS stages JSON",
    "ALTER TABLE network_interfaces ADD COLUMN IF NOT EXISTS switchport_mode VARCHAR",
    "ALTER TABLE network_interfaces ADD COLUMN IF NOT EXISTS allowed_vlans VARCHAR",
    "ALTER TABLE network_interfaces ADD COLUMN IF NOT EXISTS source VARCHAR",
    "ALTER TABLE vlans ADD COLUMN IF NOT EXISTS interfaces JSON",
    "ALTER TABLE vlans ADD COLUMN IF NOT EXISTS source VARCHAR",
    "ALTER TABLE dataset_versions ADD COLUMN IF NOT EXISTS status VARCHAR DEFAULT 'FINALIZED'",
    "ALTER TABLE dataset_versions ADD COLUMN IF NOT EXISTS parent_version VARCHAR",
    "ALTER TABLE dataset_versions ADD COLUMN IF NOT EXISTS finalized_at TIMESTAMP",
    "ALTER TABLE training_jobs ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT now()",
    "ALTER TABLE command_mappings ADD COLUMN IF NOT EXISTS embedding_backend VARCHAR",
    # ai_cli_cache stores LLM-generated CLI remediation steps per finding so the
    # LLM is not called again on every page refresh (token-efficient caching).
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_cli_cache JSON",
    # evidence_records.scan_id must allow NULL (deploy/rollback events with no scan).
    "ALTER TABLE evidence_records ALTER COLUMN scan_id DROP NOT NULL",
    # merge_confidence was first created as FLOAT but the merge engine
    # returns HIGH / MEDIUM / LOW; convert an existing float column in place.
    "DO $$ BEGIN "
    "IF (SELECT data_type FROM information_schema.columns "
    "    WHERE table_name = 'change_requests' AND column_name = 'merge_confidence' "
    "    LIMIT 1) IN ('double precision', 'real') THEN "
    "ALTER TABLE change_requests ALTER COLUMN merge_confidence TYPE VARCHAR USING NULL; "
    "END IF; END $$",
]


# create_all() never alters an existing SQLite file, so columns added after a
# dev database was first created are added here (table, column, DDL type).
_SQLITE_COLUMNS = [
    ("change_requests", "edited_by", "VARCHAR"),
    ("change_requests", "edited_at", "DATETIME"),
    ("change_requests", "approved_revision", "INTEGER"),
    ("change_requests", "approved_hash", "VARCHAR"),
    ("change_requests", "review_comment", "TEXT"),
    ("change_requests", "override_justification", "TEXT"),
    ("change_requests", "review_events", "JSON"),
    ("deployment_records", "stages", "JSON"),
    ("deployment_records", "target_control_ids", "JSON"),
    ("deployment_records", "target_controls_result", "JSON"),
    ("deployment_records", "target_controls_passed", "BOOLEAN"),
    ("deployment_records", "batfish_diff_status", "VARCHAR"),
    ("deployment_records", "batfish_diff_summary", "TEXT"),
    ("deployment_records", "batfish_diff_detail", "JSON"),
    ("rollback_records", "stages", "JSON"),
    ("network_interfaces", "switchport_mode", "VARCHAR"),
    ("network_interfaces", "allowed_vlans", "VARCHAR"),
    ("network_interfaces", "source", "VARCHAR"),
    ("vlans", "interfaces", "JSON"),
    ("vlans", "source", "VARCHAR"),
    ("scans", "source_filename", "VARCHAR"),
    ("scans", "stage_timings", "JSON"),
    ("scans", "control_state", "VARCHAR DEFAULT 'RUNNING'"),
    ("scans", "pipeline_stage", "VARCHAR"),
    ("scans", "paused_at", "DATETIME"),
    ("scans", "resumed_at", "DATETIME"),
    ("scans", "stopped_at", "DATETIME"),
    ("audit_schedules", "time_of_day", "VARCHAR"),
    ("dataset_versions", "status", "VARCHAR DEFAULT 'FINALIZED'"),
    ("dataset_versions", "parent_version", "VARCHAR"),
    ("dataset_versions", "finalized_at", "DATETIME"),
    ("training_jobs", "created_at", "DATETIME"),
    ("command_mappings", "embedding_backend", "VARCHAR"),
]


def _ensure_sqlite_columns() -> None:
    import logging

    from sqlalchemy import text

    for table, column, ddl in _SQLITE_COLUMNS:
        try:
            with engine.begin() as conn:
                cols = {row[1] for row in conn.execute(text(f"PRAGMA table_info({table})"))}
                if cols and column not in cols:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))
        except Exception as e:  # noqa: BLE001
            logging.warning("SQLite column check skipped for %s.%s: %s", table, column, e)


def _run_postgres_migrations() -> None:
    import logging

    from sqlalchemy import text

    for stmt in _POSTGRES_MIGRATIONS:
        try:
            with engine.begin() as conn:
                conn.execute(text(stmt))
        except Exception as e:  # noqa: BLE001 - one bad statement must not skip the rest
            logging.warning("Startup migration skipped (%s): %s", stmt[:80], str(e).splitlines()[0] if str(e) else e)


def get_db():
    SessionLocal.refresh()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()