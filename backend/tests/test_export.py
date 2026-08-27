"""Stage 4.1: report export — MD, JSON bundle, valid PDF."""

from __future__ import annotations

import json

from keystone_api import services
from keystone_api.models import (
    Analysis,
    AnalysisMode,
    AnalysisStatus,
    Binary,
    Report,
    REResult,
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


def _tok(client, u, p):
    return client.post("/auth/login", json={"username": u, "password": p}).get_json()[
        "access_token"
    ]


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _seed(app, session):
    app.config["OBJECT_STORE"] = FakeStore()
    services.bootstrap(session)
    t = Team(name="Blue")
    u = User(
        username="ana", email="a@x", password_hash=hash_password("pw123456"), role=Role.analyst
    )
    session.add_all([t, u])
    session.flush()
    session.add(TeamMember(team_id=t.id, user_id=u.id, team_role=TeamRole.member))
    b = Binary(
        team_id=t.id, sha256="a" * 64, filename="ls", size=1, storage_key="k", uploaded_by=u.id
    )
    session.add(b)
    session.flush()
    a = Analysis(
        team_id=t.id,
        binary_id=b.id,
        mode=AnalysisMode.re,
        status=AnalysisStatus.succeeded,
        created_by=u.id,
    )
    session.add(a)
    session.flush()
    session.add(
        REResult(
            analysis_id=a.id, binary_type="cli_tool", language_runtime="C", purpose="lists files"
        )
    )
    app.config["OBJECT_STORE"].put(f"reports/{a.id}.md", b"# RE Analysis\nlanguage_runtime: C")
    session.add(Report(analysis_id=a.id, format="md", storage_key=f"reports/{a.id}.md"))
    session.commit()
    return a


def test_export_markdown(app, client, session):
    a = _seed(app, session)
    r = client.get(
        f"/analyses/{a.id}/export?format=md", headers=_h(_tok(client, "ana", "pw123456"))
    )
    assert r.status_code == 200 and "text/markdown" in r.content_type
    assert b"language_runtime" in r.data
    assert "attachment" in r.headers["Content-Disposition"]


def test_export_json_bundle(app, client, session):
    a = _seed(app, session)
    r = client.get(
        f"/analyses/{a.id}/export?format=json", headers=_h(_tok(client, "ana", "pw123456"))
    )
    assert r.status_code == 200 and "application/json" in r.content_type
    bundle = json.loads(r.data)
    assert bundle["analysis"]["id"] == a.id
    assert bundle["re_result"]["language_runtime"] == "C"
    assert "language_runtime" in bundle["report_markdown"]


def test_export_pdf_is_valid(app, client, session):
    a = _seed(app, session)
    r = client.get(
        f"/analyses/{a.id}/export?format=pdf", headers=_h(_tok(client, "ana", "pw123456"))
    )
    assert r.status_code == 200 and r.content_type == "application/pdf"
    assert r.data.startswith(b"%PDF-1.4") and r.data.rstrip().endswith(b"%%EOF")


def test_export_bad_format(app, client, session):
    a = _seed(app, session)
    assert (
        client.get(
            f"/analyses/{a.id}/export?format=xls", headers=_h(_tok(client, "ana", "pw123456"))
        ).status_code
        == 400
    )
