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
from .audit_api import audit_bp
from .context import register_db
from .ws import register_ws
from .observability import register_observability

__all__ = ["create_app", "Settings", "get_settings"]


def create_app(settings: Settings | None = None) -> Flask:
    """Build and configure the Keystone Flask app."""
    settings = settings or get_settings()
    init_db(settings.database_url)

    app = Flask(__name__)
    app.config["KEYSTONE"] = settings
    app.config["TESTING"] = settings.env == "test"
    app.config["RATE_LIMIT_DISABLED"] = settings.env == "test"

    @app.after_request
    def _security_headers(resp):  # type: ignore[no-untyped-def]
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("X-XSS-Protection", "0")
        return resp

    register_db(app)
    register_observability(app)
    app.register_blueprint(health_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(tokens_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(teams_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(binaries_bp)
    app.register_blueprint(analyses_bp)
    app.register_blueprint(audit_bp)
    register_ws(app)

    return app
