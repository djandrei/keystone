"""Stage 3.4: VR start + rule-pick round-trip + findings endpoint."""

from __future__ import annotations

from keystone_api import services
from keystone_api.models import (
    Analysis,
    AnalysisMode,
    AnalysisStatus,
    Binary,
    Classification,
    RiskLevel,
    Role,
    Team,
    TeamMember,
    TeamRole,
    User,
    VRFinding,
)
from keystone_api.security import hash_password


def _setup(app):
    app.config["ENQUEUE"] = lambda aid: app.config.setdefault("_enq", []).append(aid)
    app.config["RULE_SIGNAL"] = lambda aid, rule: app.config.setdefault("_rule", []).append(
        (aid, rule)
    )


def _tok(client, u, p):
    return client.post("/auth/login", json={"username": u, "password": p}).get_json()[
        "access_token"
    ]


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _mk(session):
    t = Team(name="Blue")
    u = User(
        username="ana", email="a@x", password_hash=hash_password("pw123456"), role=Role.analyst
    )
    session.add_all([t, u])
    session.flush()
    session.add(TeamMember(team_id=t.id, user_id=u.id, team_role=TeamRole.member))
    b = Binary(
        team_id=t.id, sha256="a" * 64, filename="d.sys", size=1, storage_key="k", uploaded_by=u.id
    )
    session.add(b)
    session.flush()
    a = Analysis(
        team_id=t.id,
        binary_id=b.id,
        mode=AnalysisMode.vr,
        status=AnalysisStatus.running,
        created_by=u.id,
    )
    session.add(a)
    session.commit()
    return u, t, b, a


def test_start_vr_with_rule_param(app, client, session):
    _setup(app)
    services.bootstrap(session)
    u, t, b, _a = _mk(session)
    tok = _tok(client, "ana", "pw123456")
    r = client.post(
        f"/binaries/{b.id}/analyses",
        headers=_h(tok),
        json={"mode": "vr", "params": {"rule": "integer-overflow"}},
    )
    assert r.status_code == 201 and r.get_json()["mode"] == "vr"
    assert r.get_json()["params"]["rule"] == "integer-overflow"


def test_select_rule_round_trip(app, client, session):
    _setup(app)
    services.bootstrap(session)
    u, t, b, a = _mk(session)
    tok = _tok(client, "ana", "pw123456")
    assert client.post(f"/analyses/{a.id}/select-rule", headers=_h(tok), json={}).status_code == 400
    r = client.post(
        f"/analyses/{a.id}/select-rule", headers=_h(tok), json={"rule": "kernel-int-wraparound"}
    )
    assert r.status_code == 200
    assert app.config["_rule"] == [(a.id, "kernel-int-wraparound")]
    session.refresh(a)
    assert a.params["rule"] == "kernel-int-wraparound"


def test_findings_endpoint_scoped(app, client, session):
    _setup(app)
    services.bootstrap(session)
    u, t, b, a = _mk(session)
    session.add(
        VRFinding(
            analysis_id=a.id,
            rule="integer-overflow",
            file="x.c",
            line=3,
            classification=Classification.true_positive,
            risk_level=RiskLevel.high,
            cwe_id="CWE-190",
            reachable="yes",
        )
    )
    session.commit()
    tok = _tok(client, "ana", "pw123456")
    body = client.get(f"/analyses/{a.id}/findings", headers=_h(tok)).get_json()
    assert len(body) == 1 and body[0]["cwe_id"] == "CWE-190"
    assert body[0]["classification"] == "true_positive" and body[0]["risk_level"] == "high"
    # other-team user can't read
    other = User(
        username="bob", email="b@x", password_hash=hash_password("pw123456"), role=Role.analyst
    )
    session.add(other)
    session.commit()
    assert (
        client.get(
            f"/analyses/{a.id}/findings", headers=_h(_tok(client, "bob", "pw123456"))
        ).status_code
        == 404
    )
