from __future__ import annotations

from keystone_api import services
from keystone_api.audit import audit
from keystone_api.auth.principal import Principal
from keystone_api.models import (
    AuditLog,
    Binary,
    Role,
    Team,
    TeamMember,
    TeamRole,
    User,
)
from keystone_api.rbac import can_access_team, is_team_lead, require_role, scope_to_teams


def _bootstrap(session):
    services.bootstrap(session)
    session.commit()


def _login(client, u, p):
    return client.post("/auth/login", json={"username": u, "password": p}).get_json()["access_token"]


def _mk_analyst(session, team_name="Blue"):
    from keystone_api.security import hash_password

    t = Team(name=team_name)
    u = User(username="ana", email="ana@x", password_hash=hash_password("pw123456"), role=Role.analyst)
    session.add_all([t, u])
    session.flush()
    session.add(TeamMember(team_id=t.id, user_id=u.id, team_role=TeamRole.member))
    session.commit()
    return u, t


def test_require_role_gates_by_role(app, client, session):
    _bootstrap(session)
    _mk_analyst(session)

    @app.route("/_t/admin-only")
    @require_role(Role.admin)
    def _admin_only():  # type: ignore[no-untyped-def]
        from flask import g

        return {"ok": g.principal.user.username}

    admin_tok = _login(client, "admin", "change-me")
    ana_tok = _login(client, "ana", "pw123456")

    assert client.get("/_t/admin-only").status_code == 401  # no auth
    assert client.get("/_t/admin-only", headers={"Authorization": f"Bearer {ana_tok}"}).status_code == 403
    r = client.get("/_t/admin-only", headers={"Authorization": f"Bearer {admin_tok}"})
    assert r.status_code == 200 and r.get_json()["ok"] == "admin"


def test_scope_to_teams(session):
    _bootstrap(session)
    ana, blue = _mk_analyst(session)
    # a binary in Blue, one in another team the analyst is not in
    other = Team(name="Red")
    session.add(other)
    session.flush()
    session.add_all([
        Binary(team_id=blue.id, sha256="a" * 64, filename="x", size=1, storage_key="k1", uploaded_by=ana.id),
        Binary(team_id=other.id, sha256="b" * 64, filename="y", size=1, storage_key="k2", uploaded_by=ana.id),
    ])
    session.commit()

    ana_p = Principal(user=ana, role=Role.analyst, team_ids=[blue.id])
    admin = session.query(User).filter_by(username="admin").one()
    admin_p = Principal(user=admin, role=Role.admin, team_ids=[1])

    ana_bins = scope_to_teams(session.query(Binary), Binary, ana_p).all()
    assert {b.team_id for b in ana_bins} == {blue.id}
    assert scope_to_teams(session.query(Binary), Binary, admin_p).count() == 2  # admin sees all


def test_team_lead_and_access(session):
    _bootstrap(session)
    ana, blue = _mk_analyst(session)
    ana_p = Principal(user=ana, role=Role.analyst, team_ids=[blue.id])
    assert can_access_team(ana_p, blue.id)
    assert not can_access_team(ana_p, 999)
    assert not is_team_lead(session, ana_p, blue.id)  # member, not lead


def test_audit_writes_row(session):
    _bootstrap(session)
    admin = session.query(User).filter_by(username="admin").one()
    p = Principal(user=admin, role=Role.admin, team_ids=[1])
    audit(session, p, "user.create", "user", 42, {"username": "x"})
    session.commit()
    row = session.query(AuditLog).one()
    assert row.action == "user.create" and row.target_id == "42" and row.user_id == admin.id
