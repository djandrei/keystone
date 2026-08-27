"""Stage 2.8: WS auth + relay logic (no real socket/Redis)."""
from __future__ import annotations

import json

from keystone_api import services
from keystone_api.auth.tokens import create_access_token, user_team_ids
from keystone_api.models import Analysis, AnalysisMode, Binary, Role, Team, TeamMember, TeamRole, User
from keystone_api.security import hash_password
from keystone_api.ws import authorize_stream, relay


class FakeWS:
    def __init__(self):
        self.sent: list[str] = []

    def send(self, msg):
        self.sent.append(msg)


class FakePubSub:
    def __init__(self, messages):
        self._messages = messages
        self.subscribed = None

    def subscribe(self, channel):
        self.subscribed = channel

    def listen(self):
        yield from self._messages


def _analysis_with_member(session):
    services.bootstrap(session)
    team = Team(name="Blue")
    ana = User(username="ana", email="a@x", password_hash=hash_password("pw"), role=Role.analyst)
    session.add_all([team, ana])
    session.flush()
    session.add(TeamMember(team_id=team.id, user_id=ana.id, team_role=TeamRole.member))
    b = Binary(team_id=team.id, sha256="a" * 64, filename="ls", size=1, storage_key="k", uploaded_by=ana.id)
    session.add(b)
    session.flush()
    a = Analysis(team_id=team.id, binary_id=b.id, mode=AnalysisMode.re, created_by=ana.id)
    session.add(a)
    session.commit()
    return ana, team, a


def test_authorize_accepts_team_member(app, session):
    ana, team, analysis = _analysis_with_member(session)
    token = create_access_token(ana, user_team_ids(session, ana.id))
    got, err = authorize_stream(token, analysis.id, session)
    assert err is None and got.id == analysis.id


def test_authorize_rejects_other_team_and_bad_token(app, session):
    ana, team, analysis = _analysis_with_member(session)
    outsider = User(username="bob", email="b@x", password_hash=hash_password("pw"), role=Role.analyst)
    session.add(outsider)
    session.commit()
    outsider_token = create_access_token(outsider, [])  # no teams
    _, err = authorize_stream(outsider_token, analysis.id, session)
    assert err == "forbidden"
    _, err2 = authorize_stream("garbage.token.here", analysis.id, session)
    assert err2 == "unauthorized"


def test_authorize_admin_bypasses_team(app, session):
    ana, team, analysis = _analysis_with_member(session)
    admin = session.query(User).filter_by(username="admin").one()
    token = create_access_token(admin, [])  # admin, no team membership
    got, err = authorize_stream(token, analysis.id, session)
    assert err is None and got.id == analysis.id


def test_relay_replays_snapshot_then_streams_until_terminal():
    ws = FakeWS()
    snapshot = {"events": [{"type": "step_start", "step": "overview"}]}
    messages = [
        {"type": "subscribe"},  # ignored
        {"type": "message", "data": json.dumps({"type": "step_finish", "step": "overview"})},
        {"type": "message", "data": json.dumps({"type": "done"})},
        {"type": "message", "data": json.dumps({"type": "step_start", "step": "never"})},  # after break
    ]
    ps = FakePubSub(messages)
    relay(ws, "analysis:1", snapshot, ps)
    assert ps.subscribed == "analysis:1"
    kinds = [json.loads(m)["type"] for m in ws.sent]
    assert kinds == ["step_start", "step_finish", "done"]  # stops at terminal, drops the trailing message
