"""Liveness, readiness (dependency checks) and lightweight metrics."""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify

from .context import get_db
from .models import Analysis, AnalysisStatus, Role
from .rbac import require_role

health_bp = Blueprint("health", __name__)


@health_bp.get("/healthz")
def healthz():  # type: ignore[no-untyped-def]
    settings = current_app.config["KEYSTONE"]
    return jsonify(status="ok", service=settings.service_name, env=settings.env)


def _default_readyz_checks() -> dict:
    settings = current_app.config["KEYSTONE"]

    def db_check() -> None:
        from sqlalchemy import text

        from .db import get_engine

        with get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))

    def redis_check() -> None:
        import redis

        redis.Redis.from_url(settings.redis_url).ping()

    def s3_check() -> None:
        from .storage import get_object_store

        get_object_store().exists("__readyz_probe__")

    return {"db": db_check, "redis": redis_check, "s3": s3_check}


@health_bp.get("/readyz")
def readyz():  # type: ignore[no-untyped-def]
    checks = current_app.config.get("READYZ_CHECKS") or _default_readyz_checks()
    results: dict[str, str] = {}
    ok = True
    for name, fn in checks.items():
        try:
            fn()
            results[name] = "ok"
        except Exception as e:  # noqa: BLE001 — a failed probe is the signal
            results[name] = f"error: {e}"[:120]
            ok = False
    return jsonify(status="ready" if ok else "not_ready", checks=results), (200 if ok else 503)


@health_bp.get("/metrics")
@require_role(Role.admin)
def metrics():  # type: ignore[no-untyped-def]
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import func

    from .metrics import read_http_counters

    db = get_db()
    counts = dict(
        db.query(Analysis.status, func.count(Analysis.id)).group_by(Analysis.status).all()
    )
    by_status = {s.value: int(counts.get(s, 0)) for s in AnalysisStatus}

    rows = (
        db.query(Analysis.started_at, Analysis.finished_at)
        .filter(Analysis.started_at.isnot(None), Analysis.finished_at.isnot(None))
        .all()
    )
    durations = [(f - s).total_seconds() for s, f in rows if f and s]
    avg = round(sum(durations) / len(durations), 3) if durations else None

    since = datetime.now(UTC) - timedelta(hours=24)
    recent_failures = (
        db.query(func.count(Analysis.id))
        .filter(Analysis.status == AnalysisStatus.failed, Analysis.finished_at >= since)
        .scalar()
    )

    settings = current_app.config["KEYSTONE"]
    redis = None
    try:
        import redis as _redis

        redis = _redis.Redis.from_url(settings.redis_url)
    except Exception:
        redis = None

    return jsonify(
        analyses_by_status=by_status,
        active=by_status["queued"] + by_status["running"],
        completed=len(durations),
        avg_duration_seconds=avg,
        analyses_failed=by_status["failed"],
        recent_failures_24h=int(recent_failures or 0),
        http_responses=read_http_counters(redis),
    )
