"""Keystone API — Flask application factory."""
from __future__ import annotations

from flask import Flask

from .config import Settings, get_settings
from .db import init_db
from .health import health_bp
from .auth import auth_bp
from .tokens_api import tokens_bp
from .users_api import users_bp
from .teams_api import teams_bp
from .settings_api import settings_bp
from .binaries_api import binaries_bp
from .analyses_api import analyses_bp
from .context import register_db
from .ws import register_ws

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
    app.register_blueprint(tokens_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(teams_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(binaries_bp)
    app.register_blueprint(analyses_bp)
    register_ws(app)

    return app
