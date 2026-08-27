from __future__ import annotations

from datetime import UTC, datetime, timedelta

from keystone_api import services
from keystone_api.auth.apitokens import create_api_token
from keystone_api.models import User


def _bootstrap(session):
    services.bootstrap(session)
    session.commit()


def _login(client):
    return client.post(
        "/auth/login", json={"username": "admin", "password": "change-me"}
    ).get_json()


def test_create_and_authenticate_with_api_token(client, session):
    _bootstrap(session)
    jwt = _login(client)["access_token"]
    r = client.post("/tokens", json={"name": "ci"}, headers={"Authorization": f"Bearer {jwt}"})
    assert r.status_code == 201
    tok = r.get_json()["token"]
    assert tok.startswith("kst_")
    me = client.get("/auth/me", headers={"Authorization": f"Bearer {tok}"})
    assert me.status_code == 200
    assert me.get_json()["username"] == "admin"


def test_list_hides_secret_and_revoke(client, session):
    _bootstrap(session)
    hdr = {"Authorization": f"Bearer {_login(client)['access_token']}"}
    created = client.post("/tokens", json={"name": "ci"}, headers=hdr).get_json()
    listing = client.get("/tokens", headers=hdr).get_json()
    assert len(listing) == 1
    assert "token" not in listing[0]
    assert listing[0]["name"] == "ci"
    assert client.delete(f"/tokens/{created['id']}", headers=hdr).status_code == 200
    # revoked token no longer authenticates
    assert (
        client.get("/auth/me", headers={"Authorization": f"Bearer {created['token']}"}).status_code
        == 401
    )


def test_expired_api_token_rejected(client, session):
    _bootstrap(session)
    user = session.query(User).filter_by(username="admin").one()
    _, raw = create_api_token(
        session, user, "old", expires_at=datetime.now(UTC) - timedelta(days=1)
    )
    session.commit()
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {raw}"}).status_code == 401
