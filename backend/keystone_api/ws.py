"""WebSocket progress streaming: WS /analyses/:id/stream.

Auth is via an access token on the query string (browsers can't set headers on a
WebSocket). On connect we replay the last persisted progress snapshot, then relay
live events from the Redis `analysis:{id}` channel until a terminal event.

The auth check and relay loop are separated from the Sock wiring so they unit-test
without a real socket or Redis."""
from __future__ import annotations

import json

from .auth.tokens import decode_access_token
from .models import Analysis

_TERMINAL_EVENTS = {"done", "error", "canceled"}


def authorize_stream(token: str, analysis_id: int, db) -> tuple[Analysis | None, str | None]:  # type: ignore[no-untyped-def]
    """Return (analysis, None) if the token's principal may watch this analysis,
    else (None, error_code)."""
    try:
        claims = decode_access_token(token)
    except Exception:
        return None, "unauthorized"
    if claims.get("type") != "access":
        return None, "unauthorized"
    analysis = db.get(Analysis, analysis_id)
    if analysis is None:
        return None, "not_found"
    if claims.get("role") != "admin" and analysis.team_id not in (claims.get("teams") or []):
        return None, "forbidden"
    return analysis, None


def relay(ws, channel: str, snapshot: dict | None, pubsub) -> None:  # type: ignore[no-untyped-def]
    """Replay the snapshot's events, then stream Redis messages until terminal."""
    for event in (snapshot or {}).get("events", []):
        ws.send(json.dumps(event))
    pubsub.subscribe(channel)
    for message in pubsub.listen():
        if message.get("type") != "message":
            continue
        payload = message["data"]
        if isinstance(payload, bytes):
            payload = payload.decode("utf-8")
        ws.send(payload)
        try:
            if json.loads(payload).get("type") in _TERMINAL_EVENTS:
                break
        except ValueError:
            pass


def register_ws(app) -> None:  # type: ignore[no-untyped-def]
    from flask import request
    from flask_sock import Sock

    from .config import get_settings
    from .db import get_session

    sock = Sock(app)

    @sock.route("/analyses/<int:analysis_id>/stream")
    def stream(ws, analysis_id):  # type: ignore[no-untyped-def]
        token = request.args.get("token", "")
        db = get_session()
        try:
            analysis, err = authorize_stream(token, analysis_id, db)
            if err:
                ws.send(json.dumps({"type": "error", "message": err}))
                return
            snapshot = analysis.progress
        finally:
            db.close()

        import redis

        pubsub = redis.Redis.from_url(get_settings().redis_url).pubsub()
        try:
            relay(ws, f"analysis:{analysis_id}", snapshot, pubsub)
        finally:
            pubsub.close()
