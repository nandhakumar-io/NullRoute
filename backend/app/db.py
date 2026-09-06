"""Database engine + session management.

Builds a SQLAlchemy engine from `DATABASE_URL` (PostgreSQL + pgvector in
production, see docker-compose.yml) once at import time, matching how
every router/worker in this codebase already imports `get_db`/
`SessionLocal`/`init_db` from here (`from app.db import get_db`, etc.).

Local/offline development and the test suite point `DATABASE_URL` at
SQLite (see tests/conftest.py and the many `monkeypatch.setenv
("DATABASE_URL", f"sqlite:///{tmp_path}/test.db")` fixtures) -- the same
`app.models.db` ORM models work unmodified against either backend, per
the docstring on `app/models/db.py`.

KNOWN ISSUE (documented in tests/conftest.py): because the engine is built
once at import time from `os.environ["DATABASE_URL"]`, only the first
test in a pytest *session* that imports this module actually gets an
engine bound to its own monkeypatched URL; later tests in other files can
silently share it unless they build their own engine directly (several
already do, via `create_engine(...)` + `Base.metadata.create_all`, see
test_alert_service.py's `db_session` fixture). Fixing that properly means
making engine construction lazy/keyed by URL rather than a module-level
singleton -- out of scope for this pass, noted here so it isn't
rediscovered as a mystery later.
"""
from __future__ import annotations

import logging
import os
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.models.db import Base

logger = logging.getLogger("db")

DEFAULT_SQLITE_URL = "sqlite:///./dev.db"
DATABASE_URL = os.environ.get("DATABASE_URL", DEFAULT_SQLITE_URL)


def _build_engine(url: str) -> Engine:
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, connect_args=connect_args, pool_pre_ping=True)


engine: Engine = _build_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_engine() -> Engine:
    """Accessor for the current module-level engine (tests occasionally
    build their own independent engine instead -- see the docstring
    above -- but production code should always go through this)."""
    return engine


def get_session_local() -> sessionmaker:
    return SessionLocal


def init_db() -> None:
    """Create any tables that don't already exist yet.

    Also re-reads `DATABASE_URL` from the environment and rebinds the
    module-level engine/SessionLocal if it has changed since the last
    build. Several tests rely on this: they monkeypatch DATABASE_URL to a
    fresh per-test SQLite file, then explicitly call `init_db()` to get
    an isolated database rather than sharing the singleton engine built
    at import time (see e.g. tests/test_device_gateway.py's `db_session`
    fixture, and the KNOWN ISSUE note above this module).

    Migrations (alembic/) remain the source of truth for schema evolution
    in a real deployment; this call exists so `docker compose up` and
    `uvicorn app.main:app` produce a working schema immediately without
    requiring `alembic upgrade head` first. If the configured PostgreSQL
    is unreachable (e.g. running the backend standalone without the full
    docker-compose stack), fall back to local SQLite rather than failing
    to start.
    """
    global engine, SessionLocal

    current_url = os.environ.get("DATABASE_URL", DEFAULT_SQLITE_URL)
    if str(engine.url) != current_url:
        engine = _build_engine(current_url)
        SessionLocal.configure(bind=engine)

    try:
        Base.metadata.create_all(bind=engine)
        return
    except Exception as e:  # noqa: BLE001 - genuinely any connection/driver error here
        if engine.url.get_backend_name() == "sqlite":
            raise  # SQLite itself failing means a real filesystem problem, not a fallback case
        logger.warning(
            "PostgreSQL unreachable (%s) -- falling back to local SQLite (%s) for this process.",
            e, DEFAULT_SQLITE_URL,
        )
        engine = _build_engine(DEFAULT_SQLITE_URL)
        SessionLocal.configure(bind=engine)
        Base.metadata.create_all(bind=engine)


def get_db() -> Iterator[Session]:
    """FastAPI dependency: yields a request-scoped Session, always closed
    afterwards even if the request handler raises."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
