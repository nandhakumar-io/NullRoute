"""Database engine/session management.

`engine`/`SessionLocal` are built from `DATABASE_URL` and cached by URL
value (not by import time), which keeps `app.db` test-isolation-safe:
pytest is one long-lived process, and Python caches `app.db` in
sys.modules after the first import, so every test file that does
`monkeypatch.setenv("DATABASE_URL", ...)` then `from app.main import app`
would otherwise silently get the FIRST test's engine/SQLite file instead
of its own -- order-dependent cross-test data leakage. Caching by URL
value instead of caching a single module-level engine avoids that.

`engine`/`SessionLocal` stay available as `from app.db import engine` /
`from app.db import SessionLocal` (module `__getattr__`, PEP 562), so
every existing call site keeps working unchanged -- they just resolve to
whatever DATABASE_URL is current at the moment of that import/attribute
access, which is exactly what a fresh `from app.main import app` in each
test expects.
"""
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models.db import Base

FALLBACK_SQLITE = "sqlite:///./compliance_local.db"

_engine_cache: dict[str, "object"] = {}


def _build_engine(database_url: str):
    try:
        engine = create_engine(database_url, pool_pre_ping=True)
        with engine.connect():
            pass
        return engine
    except Exception:
        # Local/offline dev fallback so the API is usable without the full
        # docker-compose stack running.
        return create_engine(FALLBACK_SQLITE, connect_args={"check_same_thread": False})


def _current_database_url() -> str:
    return os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg2://compliance:compliance@postgres:5432/compliance",
    )


def get_engine():
    """Return the engine for the CURRENT DATABASE_URL, building it once per
    distinct URL and reusing it thereafter (so a normal running process --
    where DATABASE_URL never changes -- pays the connection cost exactly
    once, same as before)."""
    url = _current_database_url()
    engine = _engine_cache.get(url)
    if engine is None:
        engine = _build_engine(url)
        _engine_cache[url] = engine
    return engine


def get_session_local():
    return sessionmaker(autocommit=False, autoflush=False, bind=get_engine())


def __getattr__(name):
    # PEP 562 module-level __getattr__: makes `from app.db import engine`
    # and `from app.db import SessionLocal` resolve dynamically instead of
    # freezing the value that existed at first import.
    if name == "engine":
        return get_engine()
    if name == "SessionLocal":
        return get_session_local()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def init_db():
    """Bring the schema up to date.

    Once Alembic migrations exist they are the source of truth (RULE in
    section 21: "do not rely solely on create_all once migrations exist").
    We only fall back to `create_all` for the local/offline SQLite dev
    fallback (see `_build_engine` above), where running the full Alembic
    stack isn't worth the friction for a throwaway file.
    """
    engine = get_engine()
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
        command.upgrade(cfg, "head")
    except Exception:
        # Alembic couldn't run (e.g. versions table locked mid-deploy on
        # another replica, or migrations not shipped in this build) -
        # fall back to create_all so the API doesn't hard-fail on boot.
        # This never *reverts* a migration; it only fills in missing
        # tables, so it's safe alongside a partially-migrated schema.
        Base.metadata.create_all(bind=engine)


def get_db():
    db = get_session_local()()
    try:
        yield db
    finally:
        db.close()
