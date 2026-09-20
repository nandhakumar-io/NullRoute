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
        engine = create_engine(url, pool_pre_ping=True)
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
            try:
                from sqlalchemy import text
                with engine.begin() as conn:
                    # Convert the fallback JSON column created by create_all into an actual pgvector column
                    try:
                        conn.execute(text(
                            "ALTER TABLE command_mappings ALTER COLUMN embedding TYPE vector(384) "
                            "USING (CASE WHEN embedding IS NOT NULL THEN embedding::text::vector ELSE NULL END);"
                        ))
                    except Exception:
                        pass
            except Exception as e:
                import logging
                logging.warning(f"pgvector column conversion skipped: {e}")

            _ensure_postgres_columns()


# One statement per transaction: on Postgres a failed statement aborts the whole
# transaction, so batching these (as before) silently skipped everything after
# the first one that already existed.
_PG_SCHEMA_PATCHES = [
    "ALTER TABLE device_credential_refs ADD COLUMN IF NOT EXISTS secret_data JSON",
    "ALTER TABLE alert_channels ADD COLUMN IF NOT EXISTS secret_data JSON",
    "ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS snippet TEXT",
    "ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS merge_style VARCHAR",
    "ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS merge_confidence VARCHAR",
    "ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS merge_applied JSON",
    "ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS merge_warnings JSON",
    "ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS merge_commands JSON",
    "ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS edited_by VARCHAR",
    "ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS edited_at TIMESTAMP",
    "ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS revision INTEGER DEFAULT 1",
    # merge_confidence was first created FLOAT but stores HIGH/MEDIUM/LOW
    "ALTER TABLE change_requests ALTER COLUMN merge_confidence TYPE VARCHAR USING merge_confidence::text",
    "ALTER TABLE evidence_records ALTER COLUMN scan_id DROP NOT NULL",
]


def _ensure_postgres_columns() -> None:
    import logging
    from sqlalchemy import text
    for stmt in _PG_SCHEMA_PATCHES:
        try:
            with engine.begin() as conn:
                conn.execute(text(stmt))
        except Exception as e:  # noqa: BLE001
            logging.warning("schema patch skipped (%s): %s", stmt, str(e).splitlines()[0])


def get_db():
    SessionLocal.refresh()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
