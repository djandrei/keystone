"""Global error handlers: uniform JSON errors + guaranteed logging/Sentry capture.

Routes still return their own typed JSON for *expected* errors (`jsonify(error=...)`
with a 4xx). These handlers are the catch-all for whatever escapes:

- Framework `HTTPException`s (404 on an unknown route, 405, 413 on an oversized
  upload, `abort()`) — rendered as JSON `{"error": "<slug>"}` with their status,
  instead of Flask's default HTML page.
- Any other exception — a bug or an unhandled failure — logged with a full
  traceback (which the per-job `str(exc)` on the Analysis row never keeps),
  captured to Sentry if one is configured, and returned as a generic
  `{"error": "internal_error"}` 500 that leaks nothing.

Handling a 500 here (rather than letting it fall through Flask's default) also
means the `after_request` request logger runs on it, so an unhandled 500 finally
shows up in the structured access log instead of bypassing it.
"""

from __future__ import annotations

import logging

from flask import jsonify, request
from werkzeug.exceptions import HTTPException

log = logging.getLogger("keystone.error")


def http_error_slug(exc: HTTPException) -> str:
    """A stable snake_case slug for an HTTP status (404 'Not Found' -> 'not_found')."""
    return (exc.name or "http_error").strip().lower().replace(" ", "_")


def capture_exception(exc: BaseException) -> None:
    """Best-effort Sentry capture; a no-op if the SDK is absent or unconfigured.
    Shared by the HTTP 500 handler and the analysis-job failure recorder, so both
    paths report to Sentry identically once a DSN is set."""
    try:
        import sentry_sdk

        sentry_sdk.capture_exception(exc)
    except Exception:
        pass


def register_error_handlers(app) -> None:  # type: ignore[no-untyped-def]
    @app.errorhandler(HTTPException)
    def _handle_http(exc: HTTPException):  # type: ignore[no-untyped-def]
        code = exc.code or 500
        if code >= 500:
            log.error("http_error", extra={"status": code, "path": request.path})
        return jsonify(error=http_error_slug(exc)), code

    @app.errorhandler(Exception)
    def _handle_unexpected(exc: Exception):  # type: ignore[no-untyped-def]
        # In tests/debug, re-raise so pytest surfaces the real traceback rather
        # than a swallowed 500. (HTTPExceptions are handled above, not here.)
        if app.testing or app.debug:
            raise exc
        log.exception("unhandled_exception", extra={"path": request.path})
        capture_exception(exc)
        return jsonify(error="internal_error"), 500
