"""Stage 4.3: admin audit-trail listing — filters, pagination, admin-only."""

from __future__ import annotations

from keystone_api import services
from keystone_api.models import Role, User
from keystone_api.security import hash_password


def _tok(client, u, p):
    return client.post("/auth/login", json={"username": u, "password": p}).get_json()[
        "access_token"
    ]


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _seed(app, client, session):
    services.bootstrap(session)
    session.commit()
    admin = _tok(client, "admin", "change-me")
    # generate audit rows: create two users + a team
    client.post("/users", headers=_h(admin), json={"username": "neo", "email": "neo@x.io"})
    client.post("/users", headers=_h(admin), json={"username": "trin", "email": "trin@x.io"})
    client.post("/teams", headers=_h(admin), json={"name": "Red Cell"})
    return admin


def test_lists_audit_rows_with_username(app, client, session):
    admin = _seed(app, client, session)
    body = client.get("/audit", headers=_h(admin)).get_json()
    assert body["total"] >= 3
    assert all(r["username"] == "admin" for r in body["items"])
    actions = {r["action"] for r in body["items"]}
    assert "user.create" in actions and "team.create" in actions


def test_filter_by_action_and_pagination(app, client, session):
    admin = _seed(app, client, session)
    only_users = client.get("/audit?action=user.create", headers=_h(admin)).get_json()
    assert only_users["total"] == 2 and all(
        r["action"] == "user.create" for r in only_users["items"]
    )
    page = client.get("/audit?limit=1", headers=_h(admin)).get_json()
    assert page["limit"] == 1 and len(page["items"]) == 1


def test_audit_is_admin_only(app, client, session):
    _seed(app, client, session)
    ana = User(
        username="ana", email="a@x", password_hash=hash_password("pw123456"), role=Role.analyst
    )
    session.add(ana)
    session.commit()
    assert client.get("/audit", headers=_h(_tok(client, "ana", "pw123456"))).status_code == 403
    assert client.get("/audit").status_code == 401
