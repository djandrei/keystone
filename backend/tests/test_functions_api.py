"""The functions API: read names, choose what the report shows, correct a name."""

from __future__ import annotations

from keystone_api import services
from keystone_api.models import (
    Analysis,
    AnalysisFunction,
    AnalysisMode,
    AuditLog,
    Binary,
    FunctionName,
    Role,
    Team,
    TeamMember,
    TeamRole,
    User,
)
from keystone_api.security import hash_password


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _tok(client, u="admin", p="change-me"):
    return client.post("/auth/login", json={"username": u, "password": p}).get_json()[
        "access_token"
    ]


def _seed(session, team_name="Default", sha="a" * 64):
    services.bootstrap(session)
    team = session.query(Team).filter_by(name=team_name).one()
    admin = session.query(User).filter_by(username="admin").one()
    proj = services.get_or_create_default_project(session, team.id)
    b = Binary(
        team_id=team.id,
        project_id=proj.id,
        sha256=sha,
        filename="x.elf",
        size=10,
        storage_key="k",
        uploaded_by=admin.id,
        ghidra_program_name="x.elf",
    )
    session.add(b)
    session.flush()
    a = Analysis(team_id=team.id, binary_id=b.id, mode=AnalysisMode.re, created_by=admin.id)
    session.add(a)
    session.flush()
    fns = []
    for i, (addr, orig, sug) in enumerate(
        [("401146", "FUN_401146", "parse_header"), ("401200", "FUN_401200", None)]
    ):
        f = FunctionName(
            binary_id=b.id,
            address=addr,
            original_name=orig,
            suggested_name=sug,
            purpose="does a thing" if sug else None,
        )
        session.add(f)
        session.flush()
        session.add(AnalysisFunction(analysis_id=a.id, function_name_id=f.id, position=i))
        fns.append(f)
    session.commit()
    return a, fns


def test_list_returns_names_with_the_original_always_present(app, client, session):
    """The friendly name is a reading aid, never the identity."""
    a, _ = _seed(session)
    rows = client.get(f"/analyses/{a.id}/functions", headers=_h(_tok(client))).get_json()
    assert [r["original_name"] for r in rows] == ["FUN_401146", "FUN_401200"]
    assert rows[0]["display_name"] == "parse_header"
    # no usable suggestion -> the original shows
    assert rows[1]["suggested_name"] is None and rows[1]["display_name"] == "FUN_401200"
    assert all(r["included"] for r in rows)


def test_list_orders_by_position(app, client, session):
    a, fns = _seed(session)
    links = {x.function_name_id: x for x in session.query(AnalysisFunction).all()}
    links[fns[0].id].position, links[fns[1].id].position = 5, 1
    session.commit()
    rows = client.get(f"/analyses/{a.id}/functions", headers=_h(_tok(client))).get_json()
    assert [r["address"] for r in rows] == ["401200", "401146"]


def test_excluding_a_function_round_trips(app, client, session):
    a, fns = _seed(session)
    tok = _tok(client)
    rows = client.patch(
        f"/analyses/{a.id}/functions", headers=_h(tok), json={"exclude": [fns[1].id]}
    ).get_json()
    assert {r["id"]: r["included"] for r in rows} == {fns[0].id: True, fns[1].id: False}
    again = client.get(f"/analyses/{a.id}/functions", headers=_h(tok)).get_json()
    assert {r["id"]: r["included"] for r in again} == {fns[0].id: True, fns[1].id: False}


def test_include_and_exclude_in_one_call(app, client, session):
    a, fns = _seed(session)
    tok = _tok(client)
    client.patch(
        f"/analyses/{a.id}/functions", headers=_h(tok), json={"exclude": [f.id for f in fns]}
    )
    rows = client.patch(
        f"/analyses/{a.id}/functions",
        headers=_h(tok),
        json={"include": [fns[0].id], "exclude": [fns[1].id]},
    ).get_json()
    assert {r["id"]: r["included"] for r in rows} == {fns[0].id: True, fns[1].id: False}


def test_toggling_is_audited(app, client, session):
    a, fns = _seed(session)
    client.patch(
        f"/analyses/{a.id}/functions", headers=_h(_tok(client)), json={"exclude": [fns[0].id]}
    )
    assert session.query(AuditLog).filter_by(action="function.include").count() == 1


def test_an_empty_toggle_is_rejected(app, client, session):
    a, _ = _seed(session)
    r = client.patch(f"/analyses/{a.id}/functions", headers=_h(_tok(client)), json={})
    assert r.status_code == 400


def test_a_function_from_another_analysis_is_rejected(app, client, session):
    a, _ = _seed(session)
    other = FunctionName(binary_id=a.binary_id, address="999", original_name="FUN_999")
    session.add(other)
    session.commit()
    r = client.patch(
        f"/analyses/{a.id}/functions", headers=_h(_tok(client)), json={"exclude": [other.id]}
    )
    assert r.status_code == 400 and r.get_json()["error"] == "unknown_function"


# --------------------------------------------------------------------------- #
# Hand corrections
# --------------------------------------------------------------------------- #
def test_renaming_marks_the_row_as_a_human_edit(app, client, session):
    """`source='user'` is what stops a naming re-run undoing it."""
    _a, fns = _seed(session)
    body = client.patch(
        f"/function-names/{fns[1].id}",
        headers=_h(_tok(client)),
        json={"suggested_name": "validate_key", "purpose": "checks the key"},
    ).get_json()
    assert body["suggested_name"] == "validate_key" and body["source"] == "user"
    session.expire_all()
    assert session.get(FunctionName, fns[1].id).source == "user"


def test_a_rename_is_audited(app, client, session):
    _a, fns = _seed(session)
    client.patch(
        f"/function-names/{fns[0].id}", headers=_h(_tok(client)), json={"suggested_name": "x"}
    )
    assert session.query(AuditLog).filter_by(action="function.rename").count() == 1


def test_an_invalid_identifier_is_refused(app, client, session):
    _a, fns = _seed(session)
    r = client.patch(
        f"/function-names/{fns[0].id}",
        headers=_h(_tok(client)),
        json={"suggested_name": "not a name"},
    )
    assert r.status_code == 400 and r.get_json()["error"] == "invalid_name"


def test_clearing_a_name_restores_the_original(app, client, session):
    _a, fns = _seed(session)
    body = client.patch(
        f"/function-names/{fns[0].id}", headers=_h(_tok(client)), json={"suggested_name": ""}
    ).get_json()
    assert body["suggested_name"] is None and body["display_name"] == "FUN_401146"


def test_a_rename_with_nothing_to_change_is_rejected(app, client, session):
    _a, fns = _seed(session)
    assert (
        client.patch(f"/function-names/{fns[0].id}", headers=_h(_tok(client)), json={}).status_code
        == 400
    )


# --------------------------------------------------------------------------- #
# Authorization — no new surface: it rides the analysis and its binary
# --------------------------------------------------------------------------- #
def _analyst_elsewhere(session):
    other = Team(name="Other")
    u = User(
        username="ana", email="a@x", password_hash=hash_password("pw123456"), role=Role.analyst
    )
    session.add_all([other, u])
    session.flush()
    session.add(TeamMember(team_id=other.id, user_id=u.id, team_role=TeamRole.member))
    session.commit()
    return u


def test_another_teams_analysis_is_not_found(app, client, session):
    a, fns = _seed(session)
    _analyst_elsewhere(session)
    tok = _tok(client, "ana", "pw123456")
    assert client.get(f"/analyses/{a.id}/functions", headers=_h(tok)).status_code == 404
    assert (
        client.patch(
            f"/analyses/{a.id}/functions", headers=_h(tok), json={"exclude": [fns[0].id]}
        ).status_code
        == 404
    )
    assert (
        client.patch(
            f"/function-names/{fns[0].id}", headers=_h(tok), json={"suggested_name": "x"}
        ).status_code
        == 404
    )


def test_a_viewer_may_read_but_not_change(app, client, session):
    a, fns = _seed(session)
    team = session.query(Team).filter_by(name="Default").one()
    v = User(username="vic", email="v@x", password_hash=hash_password("pw123456"), role=Role.viewer)
    session.add(v)
    session.flush()
    session.add(TeamMember(team_id=team.id, user_id=v.id, team_role=TeamRole.member))
    session.commit()
    tok = _tok(client, "vic", "pw123456")
    assert client.get(f"/analyses/{a.id}/functions", headers=_h(tok)).status_code == 200
    assert (
        client.patch(
            f"/analyses/{a.id}/functions", headers=_h(tok), json={"exclude": [fns[0].id]}
        ).status_code
        == 403
    )
    assert (
        client.patch(
            f"/function-names/{fns[0].id}", headers=_h(tok), json={"suggested_name": "x"}
        ).status_code
        == 403
    )


def test_unknown_ids_are_404(app, client, session):
    _seed(session)
    tok = _tok(client)
    assert client.get("/analyses/9999/functions", headers=_h(tok)).status_code == 404
    assert (
        client.patch(
            "/function-names/9999", headers=_h(tok), json={"suggested_name": "x"}
        ).status_code
        == 404
    )


def test_the_analysis_detail_reports_how_many_functions_it_has(app, client, session):
    a, _ = _seed(session)
    body = client.get(f"/analyses/{a.id}", headers=_h(_tok(client))).get_json()
    assert body["function_count"] == 2
