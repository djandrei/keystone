"""Stage 5.0: security — headers, rate limiting, authz fuzz, no plaintext secrets."""

from __future__ import annotations

import pytest

from keystone_api import services
from keystone_api.config import Settings


def _bootstrap(session):
    services.bootstrap(session)
    session.commit()


def test_security_headers_present(app, client):
    r = client.get("/healthz")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Referrer-Policy"] == "no-referrer"


def test_login_is_rate_limited(app, client, session):
    _bootstrap(session)
    app.config["RATE_LIMIT_DISABLED"] = False
    app.config["RATELIMIT_login"] = 3  # override for a fast assertion
    from keystone_api.ratelimit import RateLimiter

    app.config["RATE_LIMITER"] = RateLimiter()
    # 3 attempts allowed (bad creds -> 401), the 4th is throttled
    codes = [
        client.post("/auth/login", json={"username": "x", "password": "y"}).status_code
        for _ in range(4)
    ]
    assert codes[:3] == [401] * 3 and codes[3] == 429


# every protected route rejects an unauthenticated caller
PROTECTED = [
    ("get", "/users"),
    ("post", "/users"),
    ("get", "/teams"),
    ("post", "/teams"),
    ("get", "/settings"),
    ("put", "/settings"),
    ("get", "/audit"),
    ("get", "/analyses"),
    ("get", "/binaries"),
    ("get", "/tokens"),
    ("get", "/auth/me"),
]


@pytest.mark.parametrize("method,path", PROTECTED)
def test_protected_routes_require_auth(app, client, session, method, path):
    _bootstrap(session)
    assert getattr(client, method)(path).status_code == 401


def test_admin_routes_forbid_non_admin(app, client, session):
    _bootstrap(session)
    from keystone_api.models import Role, User
    from keystone_api.security import hash_password

    session.add(
        User(
            username="ana", email="a@x", password_hash=hash_password("pw123456"), role=Role.analyst
        )
    )
    session.commit()
    tok = client.post("/auth/login", json={"username": "ana", "password": "pw123456"}).get_json()[
        "access_token"
    ]
    h = {"Authorization": f"Bearer {tok}"}
    for path in ("/users", "/settings", "/audit"):
        assert client.get(path, headers=h).status_code == 403


def test_llm_key_never_leaks(app, client, session, monkeypatch):
    _bootstrap(session)
    from keystone_api import settings_api

    monkeypatch.setattr(
        settings_api, "get_settings", lambda: Settings(env="test", llm_api_key="SUPER-SECRET-KEY")
    )
    admin = client.post(
        "/auth/login", json={"username": "admin", "password": "change-me"}
    ).get_json()["access_token"]
    r = client.get("/settings", headers={"Authorization": f"Bearer {admin}"})
    assert r.status_code == 200
    assert b"SUPER-SECRET-KEY" not in r.data  # never serialized
    assert r.get_json()["llm_key_configured"] is True  # only the boolean is exposed
