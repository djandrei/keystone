"""Projects API: list (with counts), create/rename/delete, default + non-empty
guards, team scoping."""

from __future__ import annotations

from keystone_api import services
from keystone_api.models import Binary, Project, Role, Team, TeamMember, TeamRole, User
from keystone_api.security import hash_password


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _tok(client, u="admin", p="change-me"):
    return client.post("/auth/login", json={"username": u, "password": p}).get_json()[
        "access_token"
    ]


def _team(session):
    services.bootstrap(session)
    team = session.query(Team).filter_by(name="Default").one()
    session.commit()
    return team


def test_list_includes_default_with_counts(app, client, session):
    team = _team(session)
    tok = _tok(client)
    projs = client.get(f"/projects?team_id={team.id}", headers=_h(tok)).get_json()
    default = [p for p in projs if p["is_default"]]
    assert len(default) == 1 and default[0]["name"] == "Unassigned"
    assert default[0]["binary_count"] == 0


def test_create_rename_delete_flow(app, client, session):
    team = _team(session)
    tok = _tok(client)
    r = client.post("/projects", headers=_h(tok), json={"team_id": team.id, "name": "firmware-x"})
    assert r.status_code == 201
    pid = r.get_json()["id"]
    # duplicate name -> 409
    dup = client.post("/projects", headers=_h(tok), json={"team_id": team.id, "name": "firmware-x"})
    assert dup.status_code == 409 and dup.get_json()["error"] == "name_taken"
    # rename
    rn = client.patch(f"/projects/{pid}", headers=_h(tok), json={"name": "firmware-y"})
    assert rn.status_code == 200 and rn.get_json()["name"] == "firmware-y"
    # delete empty -> 204
    assert client.delete(f"/projects/{pid}", headers=_h(tok)).status_code == 204


def test_default_project_is_protected(app, client, session):
    team = _team(session)
    tok = _tok(client)
    default = session.query(Project).filter_by(team_id=team.id, is_default=True).one()
    assert client.patch(f"/projects/{default.id}", headers=_h(tok), json={"name": "x"}).status_code == 400
    assert client.delete(f"/projects/{default.id}", headers=_h(tok)).status_code == 400


def test_cannot_delete_project_with_binaries(app, client, session):
    team = _team(session)
    u = session.query(User).filter_by(username="admin").one()
    proj = Project(team_id=team.id, name="withbins")
    session.add(proj)
    session.flush()
    session.add(
        Binary(
            team_id=team.id,
            project_id=proj.id,
            sha256="a" * 64,
            filename="x",
            size=10,
            storage_key="k",
            uploaded_by=u.id,
        )
    )
    session.commit()
    tok = _tok(client)
    r = client.delete(f"/projects/{proj.id}", headers=_h(tok))
    assert r.status_code == 409
    assert r.get_json() == {"error": "has_binaries", "binaries": 1}


def test_non_member_forbidden(app, client, session):
    services.bootstrap(session)
    default_team = session.query(Team).filter_by(name="Default").one()
    other = Team(name="Other")
    ana = User(
        username="ana", email="a@x", password_hash=hash_password("pw123456"), role=Role.analyst
    )
    session.add_all([other, ana])
    session.flush()
    session.add(TeamMember(team_id=other.id, user_id=ana.id, team_role=TeamRole.member))
    session.commit()
    tok = _tok(client, "ana", "pw123456")
    # analyst in Other can't create a project in Default
    r = client.post("/projects", headers=_h(tok), json={"team_id": default_team.id, "name": "x"})
    assert r.status_code == 403
