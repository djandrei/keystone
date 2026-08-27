"""Stage 2.7: analysis start/list/read/report/cancel over the API (team-scoped),
with enqueue/cancel/store injected."""

from __future__ import annotations

from keystone_api import services
from keystone_api.models import (
    Analysis,
    AnalysisMode,
    AnalysisStatus,
    Binary,
    Report,
    Role,
    Team,
    TeamMember,
    TeamRole,
    User,
)
from keystone_api.security import hash_password


class FakeStore:
    def __init__(self):
        self.objects = {}

    def put(self, key, data):
        self.objects[key] = data

    def exists(self, key):
        return key in self.objects

    def get(self, key):
        return self.objects[key]


def _setup(app):
    app.config["ENQUEUE"] = lambda aid: app.config.setdefault("_enq", []).append(aid)
    app.config["CANCEL_SIGNAL"] = lambda aid: app.config.setdefault("_cancel", []).append(aid)
    app.config["OBJECT_STORE"] = FakeStore()


def _tok(client, u, p):
    return client.post("/auth/login", json={"username": u, "password": p}).get_json()[
        "access_token"
    ]


def _h(tok):
    return {"Authorization": f"Bearer {tok}"}


def _mk(session, uname="ana", team="Blue", role=Role.analyst):
    t = Team(name=team)
    u = User(username=uname, email=f"{uname}@x", password_hash=hash_password("pw123456"), role=role)
    session.add_all([t, u])
    session.flush()
    session.add(TeamMember(team_id=t.id, user_id=u.id, team_role=TeamRole.member))
    b = Binary(
        team_id=t.id,
        sha256="a" * 64,
        filename="ls",
        size=5,
        storage_key="binaries/a",
        uploaded_by=u.id,
    )
    session.add(b)
    session.commit()
    return u, t, b


def test_start_analysis_enqueues(app, client, session):
    _setup(app)
    services.bootstrap(session)
    from keystone_api.services import update_settings

    update_settings(session, default_model="qwen/qwen3-8b")
    ana, team, binary = _mk(session)
    session.commit()
    tok = _tok(client, "ana", "pw123456")
    r = client.post(f"/binaries/{binary.id}/analyses", headers=_h(tok), json={"mode": "re"})
    assert r.status_code == 201
    body = r.get_json()
    assert body["status"] == "queued" and body["mode"] == "re" and body["model"] == "qwen/qwen3-8b"
    assert app.config["_enq"] == [body["id"]]  # enqueued exactly once


def test_start_rejects_bad_mode_and_viewer(app, client, session):
    _setup(app)
    services.bootstrap(session)
    ana, team, binary = _mk(session)
    v = User(username="vic", email="v@x", password_hash=hash_password("pw123456"), role=Role.viewer)
    session.add(v)
    session.flush()
    session.add(TeamMember(team_id=team.id, user_id=v.id, team_role=TeamRole.member))
    session.commit()
    ana_tok = _tok(client, "ana", "pw123456")
    assert (
        client.post(
            f"/binaries/{binary.id}/analyses", headers=_h(ana_tok), json={"mode": "xx"}
        ).status_code
        == 400
    )
    vic_tok = _tok(client, "vic", "pw123456")
    assert (
        client.post(
            f"/binaries/{binary.id}/analyses", headers=_h(vic_tok), json={"mode": "re"}
        ).status_code
        == 403
    )


def test_list_and_read_scoped(app, client, session):
    _setup(app)
    services.bootstrap(session)
    ana, team, binary = _mk(session, "ana", "Blue")
    other, other_team, _ = _mk(session, "bob", "Red")
    a = Analysis(team_id=team.id, binary_id=binary.id, mode=AnalysisMode.re, created_by=ana.id)
    session.add(a)
    session.commit()
    ana_tok = _tok(client, "ana", "pw123456")
    bob_tok = _tok(client, "bob", "pw123456")
    # ana sees it; bob (other team) doesn't
    assert client.get("/analyses", headers=_h(ana_tok)).get_json()["total"] == 1
    assert client.get("/analyses", headers=_h(bob_tok)).get_json()["items"] == []
    assert client.get(f"/analyses/{a.id}", headers=_h(bob_tok)).status_code == 403
    # filter by status
    assert client.get("/analyses?status=queued", headers=_h(ana_tok)).get_json()["total"] == 1
    assert client.get("/analyses?status=succeeded", headers=_h(ana_tok)).get_json()["items"] == []


def test_report_endpoint(app, client, session):
    _setup(app)
    services.bootstrap(session)
    ana, team, binary = _mk(session)
    a = Analysis(
        team_id=team.id,
        binary_id=binary.id,
        mode=AnalysisMode.re,
        status=AnalysisStatus.succeeded,
        created_by=ana.id,
    )
    session.add(a)
    session.flush()
    app.config["OBJECT_STORE"].put(f"reports/{a.id}.md", b"# RE Analysis\nlanguage_runtime: C")
    session.add(Report(analysis_id=a.id, format="md", storage_key=f"reports/{a.id}.md"))
    session.commit()
    tok = _tok(client, "ana", "pw123456")
    r = client.get(f"/analyses/{a.id}/report", headers=_h(tok))
    assert r.status_code == 200 and b"language_runtime" in r.data
    assert "text/markdown" in r.content_type


def test_cancel(app, client, session):
    _setup(app)
    services.bootstrap(session)
    ana, team, binary = _mk(session)
    a = Analysis(
        team_id=team.id,
        binary_id=binary.id,
        mode=AnalysisMode.re,
        status=AnalysisStatus.running,
        created_by=ana.id,
    )
    session.add(a)
    session.commit()
    tok = _tok(client, "ana", "pw123456")
    r = client.post(f"/analyses/{a.id}/cancel", headers=_h(tok))
    assert r.status_code == 200 and app.config["_cancel"] == [a.id]
    # a terminal analysis can't be canceled
    a.status = AnalysisStatus.succeeded
    session.commit()
    assert client.post(f"/analyses/{a.id}/cancel", headers=_h(tok)).status_code == 409
