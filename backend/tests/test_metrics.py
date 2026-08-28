"""Redis-backed HTTP response counters + the expanded /metrics fields."""

from __future__ import annotations

from keystone_api import services
from keystone_api.metrics import BUCKETS, http_bucket, incr_http, read_http_counters


class FakeRedis:
    def __init__(self):
        self.store: dict[str, int] = {}

    def incr(self, key):
        self.store[key] = self.store.get(key, 0) + 1
        return self.store[key]

    def mget(self, keys):
        return [self.store.get(k) for k in keys]


class DeadRedis:
    def incr(self, key):
        raise ConnectionError("down")

    def mget(self, keys):
        raise ConnectionError("down")


def test_http_bucket_mapping():
    assert http_bucket(200) == "ok"
    assert http_bucket(302) == "ok"
    assert http_bucket(404) == "client_error"
    assert http_bucket(400) == "client_error"
    assert http_bucket(500) == "server_error"
    assert http_bucket(503) == "server_error"


def test_incr_and_read_roundtrip():
    r = FakeRedis()
    incr_http(r, 200)
    incr_http(r, 200)
    incr_http(r, 404)
    incr_http(r, 500)
    counts = read_http_counters(r)
    assert counts == {"ok": 2, "client_error": 1, "server_error": 1}


def test_counters_fail_open():
    # None and a dead Redis both degrade to no-op / zeros, never raise
    incr_http(None, 500)
    incr_http(DeadRedis(), 500)
    assert read_http_counters(None) == {b: 0 for b in BUCKETS}
    assert read_http_counters(DeadRedis()) == {b: 0 for b in BUCKETS}


def test_after_request_increments_bucket(app, client):
    fake = FakeRedis()
    app.extensions["metrics_redis"] = fake  # used by the after_request hook
    client.get("/healthz")  # 200 -> ok
    client.get("/definitely-not-a-route")  # 404 -> client_error
    assert fake.store.get("keystone:metrics:http:ok") == 1
    assert fake.store.get("keystone:metrics:http:client_error") == 1


def test_metrics_endpoint_exposes_error_fields(app, client, session):
    services.bootstrap(session)
    session.commit()
    tok = client.post(
        "/auth/login", json={"username": "admin", "password": "change-me"}
    ).get_json()["access_token"]
    body = client.get("/metrics", headers={"Authorization": f"Bearer {tok}"}).get_json()
    assert set(body["http_responses"]) == set(BUCKETS)
    assert "analyses_failed" in body and "recent_failures_24h" in body
