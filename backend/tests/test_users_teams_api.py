from __future__ import annotations

from keystone_api import services
from keystone_api.models import AuditLog, Team, TeamMember, TeamRole, User
from keystone_api.security import hash_password


def _bootstrap(session):
    services.bootstrap(session)
    session.commit()


def _tok(client, u, p):
    return client.post("/auth/login", json={"username": u, "password": p}).get_json()["access_token"]


def _h(tok):
    return {"Authorization": f"Bearer {tok}"}


def _mk_user(session, name, role_str="analyst"):
    from keystone_api.models import Role

    u = User(username=name, email=f"{name}@x.io", password_hash=hash_password("pw123456"), role=Role[role_str])
    session.add(u)
    session.commit()
    return u


# ---- users ----------------------------------------------------------------
def test_admin_creates_user_with_temp_password(app, client, session):
    _bootstrap(session)
    admin = _tok(client, "admin", "change-me")
    r = client.post("/users", headers=_h(admin), json={"username": "neo", "email": "neo@x.io", "role": "analyst"})
    assert r.status_code == 201
    body = r.get_json()
    assert body["username"] == "neo" and "temp_password" in body and body["is_active"] is True
    # audit row written
    assert session.query(AuditLog).filter_by(action="user.create").count() == 1


def test_create_user_conflict_and_validation(app, client, session):
    _bootstrap(session)
    admin = _tok(client, "admin", "change-me")
    assert client.post("/users", headers=_h(admin), json={"username": "admin", "email": "a@x.io"}).status_code == 409
    assert client.post("/users", headers=_h(admin), json={"username": "x", "email": "not-an-email"}).status_code == 400


def test_analyst_cannot_manage_users(app, client, session):
    _bootstrap(session)
    _mk_user(session, "ana")
    ana = _tok(client, "ana", "pw123456")
    assert client.get("/users", headers=_h(ana)).status_code == 403
    assert client.post("/users", headers=_h(ana), json={"username": "z", "email": "z@x.io"}).status_code == 403
    assert client.get("/users").status_code == 401  # no auth


def test_update_and_deactivate_user(app, client, session):
    _bootstrap(session)
    u = _mk_user(session, "bob")
    admin = _tok(client, "admin", "change-me")
    r = client.patch(f"/users/{u.id}", headers=_h(admin), json={"role": "viewer", "is_active": False})
    assert r.status_code == 200 and r.get_json()["role"] == "viewer" and r.get_json()["is_active"] is False
    # cannot deactivate self
    admin_id = session.query(User).filter_by(username="admin").one().id
    assert client.delete(f"/users/{admin_id}", headers=_h(admin)).status_code == 400
    assert client.delete(f"/users/{u.id}", headers=_h(admin)).status_code == 200
    session.expire_all()
    assert session.get(User, u.id).is_active is False


# ---- teams ----------------------------------------------------------------
def test_admin_creates_team_and_manages_members(app, client, session):
    _bootstrap(session)
    admin = _tok(client, "admin", "change-me")
    u = _mk_user(session, "carol")
    r = client.post("/teams", headers=_h(admin), json={"name": "Red Cell"})
    assert r.status_code == 201
    tid = r.get_json()["id"]
    # add member
    r = client.post(f"/teams/{tid}/members", headers=_h(admin), json={"user_id": u.id, "team_role": "lead"})
    assert r.status_code == 201
    assert session.get(TeamMember, (tid, u.id)).team_role is TeamRole.lead
    # duplicate add -> 409
    assert client.post(f"/teams/{tid}/members", headers=_h(admin), json={"user_id": u.id}).status_code == 409
    # get team shows members
    body = client.get(f"/teams/{tid}", headers=_h(admin)).get_json()
    assert any(m["username"] == "carol" for m in body["members"])
    # remove
    assert client.delete(f"/teams/{tid}/members/{u.id}", headers=_h(admin)).status_code == 200
    session.expire_all()
    assert session.get(TeamMember, (tid, u.id)) is None


def test_team_lead_manages_only_own_team(app, client, session):
    _bootstrap(session)
    # lead of Alpha, plain analyst outside it
    lead = _mk_user(session, "lead1")
    outsider = _mk_user(session, "out1")
    alpha = Team(name="Alpha")
    beta = Team(name="Beta")
    session.add_all([alpha, beta])
    session.flush()
    session.add(TeamMember(team_id=alpha.id, user_id=lead.id, team_role=TeamRole.lead))
    session.commit()

    lead_tok = _tok(client, "lead1", "pw123456")
    # can add to own team
    assert client.post(f"/teams/{alpha.id}/members", headers=_h(lead_tok),
                       json={"user_id": outsider.id}).status_code == 201
    # cannot add to a team they don't lead
    assert client.post(f"/teams/{beta.id}/members", headers=_h(lead_tok),
                       json={"user_id": outsider.id}).status_code == 403
    # non-admin cannot create teams
    assert client.post("/teams", headers=_h(lead_tok), json={"name": "Gamma"}).status_code == 403


def test_team_list_is_scoped_for_non_admin(app, client, session):
    _bootstrap(session)
    ana = _mk_user(session, "d1")
    alpha = Team(name="AlphaX")
    session.add(alpha)
    session.flush()
    session.add(TeamMember(team_id=alpha.id, user_id=ana.id, team_role=TeamRole.member))
    session.commit()
    ana_tok = _tok(client, "d1", "pw123456")
    teams = client.get("/teams", headers=_h(ana_tok)).get_json()
    assert {t["name"] for t in teams} == {"AlphaX"}  # not the Default team
    # admin sees all
    admin = _tok(client, "admin", "change-me")
    names = {t["name"] for t in client.get("/teams", headers=_h(admin)).get_json()}
    assert {"Default", "AlphaX"} <= names
