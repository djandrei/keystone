"""Observability: structured JSON request logs, a Sentry-compatible error hook,
readiness checks and lightweight metrics."""

from __future__ import annotations

import logging
import time

from flask import g, request


def build_request_log(
    method: str, path: str, status: int, duration_ms: float, request_id: str | None = None
) -> dict:
    """The structured fields for one request — pure, so it's easy to assert on."""
    fields = {
        "event": "request",
        "method": method,
        "path": path,
        "status": status,
        "duration_ms": round(duration_ms, 2),
    }
    if request_id:
        fields["request_id"] = request_id
    return fields


def configure_logging() -> None:
    """JSON logs to stderr (python-json-logger), once."""
    try:
        from pythonjsonlogger import jsonlogger
    except Exception:
        return
    root = logging.getLogger()
    if any(getattr(h, "_keystone_json", False) for h in root.handlers):
        return
    handler = logging.StreamHandler()
    handler.setFormatter(jsonlogger.JsonFormatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    handler._keystone_json = True  # type: ignore[attr-defined]
    root.addHandler(handler)
    root.setLevel(logging.INFO)


def init_error_tracking(dsn: str) -> bool:
    """Initialize a Sentry-compatible error tracker if a DSN + SDK are present.
    No-op (returns False) otherwise — keeps sentry_sdk an optional dependency."""
    if not dsn:
        return False
    try:
        import sentry_sdk

        sentry_sdk.init(dsn=dsn)
        return True
    except Exception:
        return False


def register_observability(app) -> None:  # type: ignore[no-untyped-def]
    configure_logging()
    init_error_tracking(getattr(app.config.get("KEYSTONE"), "sentry_dsn", "") or "")
    log = logging.getLogger("keystone.request")

    @app.before_request
    def _start_timer() -> None:  # type: ignore[no-untyped-def]
        g._start = time.perf_counter()

    @app.after_request
    def _log_request(resp):  # type: ignore[no-untyped-def]
        start = getattr(g, "_start", None)
        if start is not None:
            duration_ms = (time.perf_counter() - start) * 1000
            log.info(
                "request",
                extra=build_request_log(
                    request.method, request.path, resp.status_code, duration_ms
                ),
            )
        return resp
