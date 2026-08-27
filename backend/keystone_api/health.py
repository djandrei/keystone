"""Liveness endpoint. Readiness (dependency checks) arrives in M5.1."""
from __future__ import annotations

from flask import Blueprint, current_app, jsonify

health_bp = Blueprint("health", __name__)


@health_bp.get("/healthz")
def healthz():  # type: ignore[no-untyped-def]
    settings = current_app.config["KEYSTONE"]
    return jsonify(status="ok", service=settings.service_name, env=settings.env)
