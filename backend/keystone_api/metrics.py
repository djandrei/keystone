"""Lightweight, Redis-backed HTTP response counters.

One INCR per request, bucketed by status class, so /metrics can report how many
requests succeeded vs. errored across ALL gunicorn workers (an in-process counter
wouldn't be shared). Every Redis touch is best-effort: a dead Redis must never
break a response or the metrics endpoint — it just reports zeros."""

from __future__ import annotations

from typing import Any

_PREFIX = "keystone:metrics:http:"
BUCKETS = ("ok", "client_error", "server_error")


def http_bucket(status: int) -> str:
    """Map an HTTP status to a counter bucket (2xx/3xx ok, 4xx client, 5xx server)."""
    if status >= 500:
        return "server_error"
    if status >= 400:
        return "client_error"
    return "ok"


def incr_http(redis: Any, status: int) -> None:
    """Increment the bucket for one response. Fail-open."""
    if redis is None:
        return
    try:
        redis.incr(_PREFIX + http_bucket(status))
    except Exception:
        pass


def read_http_counters(redis: Any) -> dict[str, int]:
    """Read all buckets as ints (missing/unavailable -> 0). Fail-open."""
    out = {b: 0 for b in BUCKETS}
    if redis is None:
        return out
    try:
        vals = redis.mget([_PREFIX + b for b in BUCKETS])
        for b, v in zip(BUCKETS, vals, strict=False):
            out[b] = int(v) if v is not None else 0
    except Exception:
        pass
    return out
