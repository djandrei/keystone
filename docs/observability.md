# Keystone — Errors & Observability

How failures are captured, surfaced, logged, and counted. Every layer fails safe:
a dead Redis or an absent Sentry never breaks a request or an analysis.

## When an HTTP request errors

- **Expected errors** (validation, not-found, forbidden) — each route returns a
  typed JSON body, e.g. `{"error": "not_found"}` with the right status.
- **Anything uncaught** — a global handler (`keystone_api/errors.py`) turns it
  into JSON instead of Flask's HTML page:
  - `HTTPException` (unknown route → 404, wrong method → 405, oversized upload →
    413) → `{"error": "<slug>"}` with its status.
  - Any other exception → the full traceback is logged (`keystone.error`),
    reported to Sentry if configured, and the client gets a generic
    `{"error": "internal_error"}` 500 that leaks nothing. In tests/debug it
    re-raises so pytest surfaces the bug.
- Because the 500 is a *handled* response, the `after_request` logger and the
  response counter both run on it — an unhandled 500 no longer bypasses the log.

## When an analysis fails

`run_analysis_core` (the pipeline) **and** the worker's engine setup (missing MCP
key, Ghidra/LLM/triage init, Ghidra import) both route failures through one
function, `jobs.record_failure`, which:

1. logs the full traceback server-side (`keystone.jobs`) — not just `str(exc)`;
2. reports to Sentry if a DSN is set (`capture_exception`);
3. marks the row `status=failed`, `error=<reason>`, `finished_at=now`;
4. best-effort publishes `{"type":"error","message":...}` to Redis — guarded so a
   dead Redis can't discard the DB record.

The reason surfaces to the user three ways: the live WS stream (`error` event →
the running step turns red), a "failed" toast, and a red **Failed** card on the
analysis page showing `analysis.error`. The status is also readable via
`GET /api/analyses/:id`.

> The worker wraps its whole body, so a setup failure *before* the pipeline marks
> the row failed with an actionable reason instead of dying as a silent Celery
> task and leaving the analysis stuck. (Transient errors are not auto-retried —
> the MCP client already retries its own HTTP; re-run to try again.)

## Logging

Structured JSON to stderr (`observability.configure_logging`, `python-json-logger`,
INFO). Every request logs `{event, method, path, status, duration_ms}` in
`after_request`. Loggers: `keystone.request`, `keystone.error`, `keystone.jobs`,
`keystone.worker`, `keystone.metrics`.

## Metrics — `GET /api/metrics` (admin only)

```json
{
  "analyses_by_status": {"queued": 0, "running": 1, "succeeded": 12, "failed": 2, "canceled": 0},
  "active": 1,
  "completed": 12,
  "avg_duration_seconds": 41.2,
  "analyses_failed": 2,
  "recent_failures_24h": 1,
  "http_responses": {"ok": 3120, "client_error": 44, "server_error": 2}
}
```

`http_responses` are Redis-backed counters (`keystone_api/metrics.py`), one INCR
per request bucketed by status class, shared across all gunicorn workers. Reads
and writes are fail-open — with Redis down the buckets report zeros.

## Frontend

An app-level `ErrorBoundary` (wrapping the whole tree in `main.tsx`) catches any
render error and shows a recoverable fallback with a **Reload** button instead of
a white screen; `componentDidCatch` logs it (and a Sentry-wired build forwards it).
The analysis page also shows a subtle "live updates disconnected" notice if the
WS stream drops while a run is active — the poll still updates the final state.

## Enabling Sentry (optional)

Off by default (no dependency). To turn it on:

1. `pip install sentry-sdk` (add it to the backend/worker images).
2. Set `KEYSTONE_SENTRY_DSN=<your dsn>`.

`init_error_tracking` then initializes it, and both HTTP 500s and analysis-job
failures report through the shared `capture_exception` hook. No code change
needed — the hooks are already in place.
