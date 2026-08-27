"""Stage 4.0: analysis history — filters, filename search, pagination, sort."""
from __future__ import annotations

from keystone_api import services
from keystone_api.models import Analysis, AnalysisMode, AnalysisStatus, Binary, Role, Team, TeamMember, TeamRole, User
from keystone_api.security import hash_password


def _tok(client, u, p):
    return client.post("/auth/login", json={"username": u, "password": p}).get_json()["access_token"]


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _seed(session):
    services.bootstrap(session)
    t = Team(name="Blue")
    ana = User(username="ana", email="a@x", password_hash=hash_password("pw123456"), role=Role.analyst)
    bob = User(username="bob", email="b@x", password_hash=hash_password("pw123456"), role=Role.analyst)
    session.add_all([t, ana, bob])
    session.flush()
    session.add_all([
        TeamMember(team_id=t.id, user_id=ana.id, team_role=TeamRole.member),
        TeamMember(team_id=t.id, user_id=bob.id, team_role=TeamRole.member),
    ])
    b1 = Binary(team_id=t.id, sha256="1" * 64, filename="notepad.exe", size=1, storage_key="k1", uploaded_by=ana.id)
    b2 = Binary(team_id=t.id, sha256="2" * 64, filename="ksthunk.sys", size=1, storage_key="k2", uploaded_by=bob.id)
    session.add_all([b1, b2])
    session.flush()
    for i in range(5):
        session.add(Analysis(team_id=t.id, binary_id=b1.id, mode=AnalysisMode.re,
                             status=AnalysisStatus.succeeded, created_by=ana.id))
    session.add(Analysis(team_id=t.id, binary_id=b2.id, mode=AnalysisMode.vr,
                         status=AnalysisStatus.failed, created_by=bob.id))
    session.commit()
    return t, ana, bob, b1, b2


def test_envelope_and_pagination(app, client, session):
    _seed(session)
    tok = _tok(client, "ana", "pw123456")
    body = client.get("/analyses?limit=2", headers=_h(tok)).get_json()
    assert body["total"] == 6 and body["limit"] == 2 and len(body["items"]) == 2
    page2 = client.get("/analyses?limit=2&offset=2", headers=_h(tok)).get_json()
    assert {a["id"] for a in body["items"]}.isdisjoint({a["id"] for a in page2["items"]})


def test_filters_by_creator_status_mode(app, client, session):
    t, ana, bob, b1, b2 = _seed(session)
    tok = _tok(client, "ana", "pw123456")
    assert client.get(f"/analyses?created_by={bob.id}", headers=_h(tok)).get_json()["total"] == 1
    assert client.get("/analyses?status=failed", headers=_h(tok)).get_json()["total"] == 1
    assert client.get("/analyses?mode=re", headers=_h(tok)).get_json()["total"] == 5


def test_search_by_filename(app, client, session):
    _seed(session)
    tok = _tok(client, "ana", "pw123456")
    assert client.get("/analyses?q=ksthunk", headers=_h(tok)).get_json()["total"] == 1
    assert client.get("/analyses?q=notepad", headers=_h(tok)).get_json()["total"] == 5
    assert client.get("/analyses?q=nomatch", headers=_h(tok)).get_json()["total"] == 0


def test_sort_order(app, client, session):
    _seed(session)
    tok = _tok(client, "ana", "pw123456")
    asc = client.get("/analyses?sort=id&order=asc", headers=_h(tok)).get_json()["items"]
    desc = client.get("/analyses?sort=id&order=desc", headers=_h(tok)).get_json()["items"]
    assert [a["id"] for a in asc] == sorted(a["id"] for a in asc)
    assert desc[0]["id"] > desc[-1]["id"]


def test_items_carry_creator_username(app, client, session):
    _seed(session)
    tok = _tok(client, "ana", "pw123456")
    items = client.get("/analyses", headers=_h(tok)).get_json()["items"]
    names = {a["created_by_username"] for a in items}
    assert names == {"ana", "bob"}  # who ran what is visible to teammates
