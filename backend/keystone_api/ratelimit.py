"""Lightweight per-IP sliding-window rate limiting.

In-memory by default (fine for a single worker / dev); the limiter is injectable
via app.config['RATE_LIMITER'] and disabled under TESTING unless a test opts in."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from collections.abc import Callable
from functools import wraps

from flask import current_app, jsonify, request


class RateLimiter:
    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._hits: dict[str, deque] = defaultdict(deque)
        self._clock = clock

    def allow(self, key: str, limit: int, window: float) -> bool:
        now = self._clock()
        dq = self._hits[key]
        while dq and dq[0] <= now - window:
            dq.popleft()
        if len(dq) >= limit:
            return False
        dq.append(now)
        return True

    def reset(self) -> None:
        self._hits.clear()


def _limiter() -> RateLimiter:
    lim = current_app.config.get("RATE_LIMITER")
    if lim is None:
        lim = RateLimiter()
        current_app.config["RATE_LIMITER"] = lim
    return lim


def _client_ip() -> str:
    fwd = request.headers.get("X-Forwarded-For")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr or "unknown"


def rate_limit(bucket: str, limit: int, window: float):  # type: ignore[no-untyped-def]
    def decorator(fn):  # type: ignore[no-untyped-def]
        @wraps(fn)
        def wrapper(*args, **kwargs):  # type: ignore[no-untyped-def]
            if current_app.config.get("RATE_LIMIT_DISABLED"):
                return fn(*args, **kwargs)
            eff_limit = current_app.config.get(f"RATELIMIT_{bucket}", limit)
            if not _limiter().allow(f"{bucket}:{_client_ip()}", eff_limit, window):
                return jsonify(error="rate_limited"), 429
            return fn(*args, **kwargs)

        return wrapper

    return decorator
