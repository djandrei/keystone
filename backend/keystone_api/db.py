"""Database engine, session, and declarative base.

Shared by the API and (later) the Celery worker, so the engine lives here rather
than bound to Flask. `init_db()` builds the engine from settings; tests call it
with a SQLite URL. `session_scope()` gives a transactional block.
"""
from __future__ import annotations

from contextlib import contextmanager
from collections.abc import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

from .config import get_settings


class Base(DeclarativeBase):
    """Declarative base for all Keystone models."""


_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def init_db(url: str | None = None) -> Engine:
    """(Re)initialise the engine + session factory. Idempotent per URL."""
    global _engine, _SessionLocal
    url = url or get_settings().database_url

    kwargs: dict = {"future": True, "pool_pre_ping": True}
    if url.startswith("sqlite"):
        # In-memory SQLite for tests: one shared connection, FK enforcement on.
        kwargs.update(connect_args={"check_same_thread": False}, poolclass=StaticPool)

    _engine = create_engine(url, **kwargs)

    if url.startswith("sqlite"):

        @event.listens_for(_engine, "connect")
        def _fk_on(dbapi_conn, _rec):  # type: ignore[no-untyped-def]
            dbapi_conn.execute("PRAGMA foreign_keys=ON")

    _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False, class_=Session)
    return _engine


def get_engine() -> Engine:
    if _engine is None:
        init_db()
    assert _engine is not None
    return _engine


def get_session() -> Session:
    if _SessionLocal is None:
        init_db()
    assert _SessionLocal is not None
    return _SessionLocal()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope: commit on success, roll back on error."""
    session = get_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
