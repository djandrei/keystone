from __future__ import annotations

from keystone_api import services


def _bootstrap(session):
    services.bootstrap(session)
    session.commit()


def _login(client, username="admin", password="change-me"):
    return client.post("/auth/login", json={"username": username, "password": password})


def test_login_success(client, session):
    _bootstrap(session)
    r = _login(client)
    assert r.status_code == 200
    b = r.get_json()
    assert b["access_token"] and b["refresh_token"]
    assert b["user"]["role"] == "admin"


def test_login_wrong_password(client, session):
    _bootstrap(session)
    assert client.post("/auth/login", json={"username": "admin", "password": "no"}).status_code == 401


def test_me_requires_and_returns_identity(client, session):
    _bootstrap(session)
    assert client.get("/auth/me").status_code == 401
    tok = _login(client).get_json()["access_token"]
    r = client.get("/auth/me", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    assert r.get_json()["username"] == "admin"
    assert r.get_json()["role"] == "admin"


def test_refresh_rotation_single_use(client, session):
    _bootstrap(session)
    rt = _login(client).get_json()["refresh_token"]
    r = client.post("/auth/refresh", json={"refresh_token": rt})
    assert r.status_code == 200
    new = r.get_json()["refresh_token"]
    assert new != rt
    # old token is single-use — rejected after rotation
    assert client.post("/auth/refresh", json={"refresh_token": rt}).status_code == 401
    # the rotated token works
    assert client.post("/auth/refresh", json={"refresh_token": new}).status_code == 200


def test_logout_revokes_refresh(client, session):
    _bootstrap(session)
    rt = _login(client).get_json()["refresh_token"]
    assert client.post("/auth/logout", json={"refresh_token": rt}).status_code == 200
    assert client.post("/auth/refresh", json={"refresh_token": rt}).status_code == 401


def test_password_change(client, session):
    _bootstrap(session)
    tok = _login(client).get_json()["access_token"]
    r = client.post(
        "/auth/password",
        json={"old_password": "change-me", "new_password": "newpass123"},
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert r.status_code == 200
    assert _login(client).status_code == 401  # old password rejected
    assert _login(client, password="newpass123").status_code == 200
