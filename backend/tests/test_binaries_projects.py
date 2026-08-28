"""Uploads land in a project (default Unassigned), and binaries can be moved
between projects in the same team."""

from __future__ import annotations

import io
import struct

from keystone_api import services
from keystone_api.models import Project, Team

ELF = (
    b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 11 + struct.pack("<H", 0x3E) + b"\x00" * 40
) + b"\x00" * 1024


class FakeStore:
    def __init__(self):
        self.objects: dict[str, bytes] = {}

    def put(self, key, data):
        self.objects[key] = data

    def exists(self, key):
        return key in self.objects

    def get(self, key):
        return self.objects[key]


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _tok(client, u="admin", p="change-me"):
    return client.post("/auth/login", json={"username": u, "password": p}).get_json()[
        "access_token"
    ]


def _team(app, session):
    app.config["OBJECT_STORE"] = FakeStore()
    services.bootstrap(session)
    team = session.query(Team).filter_by(name="Default").one()
    session.commit()
    return team


def _upload(client, tok, team_id, name, data, project_id=None):
    form = {"team_id": str(team_id), "file": (io.BytesIO(data), name)}
    if project_id is not None:
        form["project_id"] = str(project_id)
    return client.post("/binaries", headers=_h(tok), data=form, content_type="multipart/form-data")


def test_upload_defaults_to_unassigned(app, client, session):
    team = _team(app, session)
    b = _upload(client, _tok(client), team.id, "a.elf", ELF).get_json()
    assert b["project_name"] == "Unassigned"


def test_upload_into_a_project(app, client, session):
    team = _team(app, session)
    proj = Project(team_id=team.id, name="firmware-x")
    session.add(proj)
    session.commit()
    b = _upload(client, _tok(client), team.id, "b.elf", ELF, project_id=proj.id).get_json()
    assert b["project_id"] == proj.id and b["project_name"] == "firmware-x"


def test_upload_foreign_project_rejected(app, client, session):
    team = _team(app, session)
    other = Team(name="Other")
    session.add(other)
    session.flush()
    foreign = Project(team_id=other.id, name="x")
    session.add(foreign)
    session.commit()
    r = _upload(client, _tok(client), team.id, "c.elf", ELF, project_id=foreign.id)
    assert r.status_code == 400 and r.get_json()["error"] == "invalid_project"


def test_move_binary_between_projects(app, client, session):
    team = _team(app, session)
    proj = Project(team_id=team.id, name="dest")
    session.add(proj)
    session.commit()
    tok = _tok(client)
    bid = _upload(client, tok, team.id, "d.elf", ELF).get_json()["id"]  # Unassigned
    r = client.patch(f"/binaries/{bid}", headers=_h(tok), json={"project_id": proj.id})
    assert r.status_code == 200
    assert r.get_json()["project_id"] == proj.id and r.get_json()["project_name"] == "dest"


def test_move_to_foreign_project_rejected(app, client, session):
    team = _team(app, session)
    other = Team(name="Other")
    session.add(other)
    session.flush()
    foreign = Project(team_id=other.id, name="x")
    session.add(foreign)
    session.commit()
    tok = _tok(client)
    bid = _upload(client, tok, team.id, "e.elf", ELF).get_json()["id"]
    r = client.patch(f"/binaries/{bid}", headers=_h(tok), json={"project_id": foreign.id})
    assert r.status_code == 400 and r.get_json()["error"] == "invalid_project"
