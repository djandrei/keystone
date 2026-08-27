"""Request-scoped SQLAlchemy session bound to the Flask app context."""
from __future__ import annotations

from flask import Flask, g

from .db import Session, get_session


def get_db() -> Session:
    if "db" not in g:
        g.db = get_session()
    return g.db


def register_db(app: Flask) -> None:
    @app.teardown_appcontext
    def _close(_exc: BaseException | None) -> None:  # type: ignore[no-untyped-def]
        db = g.pop("db", None)
        if db is not None:
            db.close()
