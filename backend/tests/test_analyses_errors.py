"""Analyses API error branches (not_found / invalid) for coverage + robustness."""

from __future__ import annotations

from keystone_api import services
from keystone_api.models import Team


def _tok(client):
    return client.post(
        "/auth/login", json={"username": "admin", "password": "change-me"}
    ).get_json()["access_token"]


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _boot(session):
    services.bootstrap(session)
    session.query(Team).filter_by(name="Default").one()
    session.commit()


def test_analysis_routes_not_found(app, client, session):
    _boot(session)
    tok = _tok(client)
    assert client.get("/analyses/99999", headers=_h(tok)).status_code == 404
    assert client.get("/analyses/99999/report", headers=_h(tok)).status_code == 404
    assert client.post("/analyses/99999/cancel", headers=_h(tok)).status_code == 404
    assert client.post("/analyses/99999/select-rule", headers=_h(tok), json={"rule": "x"}).status_code == 404
    assert client.get("/analyses/99999/findings", headers=_h(tok)).status_code == 404
    assert client.get("/analyses/99999/export?format=md", headers=_h(tok)).status_code == 404


def test_start_analysis_binary_not_found_and_invalid_mode(app, client, session):
    _boot(session)
    tok = _tok(client)
    # binary doesn't exist
    assert client.post("/binaries/99999/analyses", headers=_h(tok), json={"mode": "re"}).status_code == 404
    # invalid mode on an existing binary
    from keystone_api.models import Binary, User

    u = session.query(User).filter_by(username="admin").one()
    team = session.query(Team).filter_by(name="Default").one()
    b = Binary(team_id=team.id, sha256="a" * 64, filename="x", size=10, storage_key="k", uploaded_by=u.id)
    session.add(b)
    session.commit()
    r = client.post(f"/binaries/{b.id}/analyses", headers=_h(tok), json={"mode": "bogus"})
    assert r.status_code == 400 and r.get_json()["error"] == "invalid_mode"


def test_list_invalid_mode_and_status(app, client, session):
    _boot(session)
    tok = _tok(client)
    assert client.get("/analyses?mode=bogus", headers=_h(tok)).status_code == 400
    assert client.get("/analyses?status=bogus", headers=_h(tok)).status_code == 400
