"""Keystone API — Flask application factory."""
from __future__ import annotations

from flask import Flask

from .config import Settings, get_settings
from .db import init_db
from .health import health_bp
from .auth import auth_bp
from .context import register_db

__all__ = ["create_app", "Settings", "get_settings"]


def create_app(settings: Settings | None = None) -> Flask:
    """Build and configure the Keystone Flask app."""
    settings = settings or get_settings()
    init_db(settings.database_url)

    app = Flask(__name__)
    app.config["KEYSTONE"] = settings
    app.config["TESTING"] = settings.env == "test"

    register_db(app)
    app.register_blueprint(health_bp)
    app.register_blueprint(auth_bp)

    return app
