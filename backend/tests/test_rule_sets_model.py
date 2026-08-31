"""Rule-set schema invariants and the resolution order that turns a request into a
pinned set of versions (docs/rule-sets-plan.md §4, §5)."""

from __future__ import annotations

import pytest
from sqlalchemy.exc import IntegrityError

from keystone_api import services
from keystone_api.models import (
    BUILTIN_RULESET_NAME,
    Analysis,
    AnalysisMode,
    Binary,
    RuleSet,
    RuleSetVersion,
    Team,
    User,
)
from keystone_api.services import (
    RuleSetResolutionError,
    add_rule_set_version,
    ensure_builtin_rulesets,
    get_or_create_settings,
    latest_version,
    pin_rule_sets,
    pinned_rule_set_versions,
    resolve_rule_set_versions,
)

RULES = "rules:\n  - {id: a, languages: [c], severity: ERROR, message: m, pattern: 'x(...)'}\n"
RULES2 = "rules:\n  - {id: b, languages: [c], severity: ERROR, message: m, pattern: 'y(...)'}\n"


def _team(session, name="Default"):
    services.bootstrap(session)
    session.commit()
    return session.query(Team).filter_by(name=name).one()


def _rs(session, team_id, name="rs", content=RULES):
    rs = RuleSet(team_id=team_id, name=name)
    session.add(rs)
    session.flush()
    add_rule_set_version(session, rs, content)
    session.commit()
    return rs


# --------------------------------------------------------------------------- #
# Seeding
# --------------------------------------------------------------------------- #
def test_bootstrap_seeds_the_builtin_and_points_the_default_at_it(app, session):
    services.bootstrap(session)
    session.commit()
    rs = session.query(RuleSet).filter_by(team_id=None, name=BUILTIN_RULESET_NAME).one()
    assert rs.name == BUILTIN_RULESET_NAME and rs.is_builtin
    assert latest_version(session, rs.id).version_no == 1
    assert get_or_create_settings(session).default_rule_set_id == rs.id


def test_seeding_is_idempotent(app, session):
    services.bootstrap(session)
    services.bootstrap(session)
    ensure_builtin_rulesets(session)
    session.commit()
    rs = session.query(RuleSet).filter_by(team_id=None, name=BUILTIN_RULESET_NAME).one()
    assert len(rs.versions) == 1


def test_a_shipped_content_change_appends_v2(app, session, monkeypatch, tmp_path):
    services.bootstrap(session)
    session.commit()
    rs = session.query(RuleSet).filter_by(team_id=None, name=BUILTIN_RULESET_NAME).one()
    newer = tmp_path / "decompiled-c.yaml"
    newer.write_text(RULES)
    monkeypatch.setattr(services, "BUILTIN_RULESET_PATH", newer)
    ensure_builtin_rulesets(session)
    session.commit()
    assert [v.version_no for v in rs.versions] == [1, 2]
    assert latest_version(session, rs.id).content == RULES


def test_missing_rules_file_warns_instead_of_wedging_bootstrap(app, session, monkeypatch, tmp_path):
    """Seeding lives in the app, not the migration, precisely so this is survivable."""
    monkeypatch.setattr(services, "BUILTIN_RULESET_PATH", tmp_path / "nope.yaml")
    assert services.bootstrap(session)["admin"] == "admin"
    assert session.query(RuleSet).filter_by(team_id=None, name=BUILTIN_RULESET_NAME).count() == 0


def test_a_malformed_shipped_file_does_not_abort_bootstrap(app, session, monkeypatch, tmp_path):
    bad = tmp_path / "decompiled-c.yaml"
    bad.write_text("rules: []")
    monkeypatch.setattr(services, "BUILTIN_RULESET_PATH", bad)
    services.bootstrap(session)
    session.commit()
    rs = session.query(RuleSet).filter_by(team_id=None, name=BUILTIN_RULESET_NAME).one()
    assert rs.versions == []  # created, but with nothing in it


# --------------------------------------------------------------------------- #
# Schema invariants
# --------------------------------------------------------------------------- #
def test_version_numbers_are_monotonic_per_rule_set(app, session):
    team = _team(session)
    rs = _rs(session, team.id)
    add_rule_set_version(session, rs, RULES2)
    session.commit()
    assert [v.version_no for v in rs.versions] == [1, 2]


def test_identical_content_makes_no_version(app, session):
    team = _team(session)
    rs = _rs(session, team.id)
    assert add_rule_set_version(session, rs, RULES) is None


def test_duplicate_version_number_rejected(app, session):
    team = _team(session)
    rs = _rs(session, team.id)
    session.add(RuleSetVersion(rule_set_id=rs.id, version_no=1, content="x", content_sha256="y"))
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()


def test_two_builtins_cannot_share_a_name(app, session):
    """The NULL trap: a plain (team_id, name) constraint would let this through."""
    _team(session)
    session.add(RuleSet(team_id=None, name=BUILTIN_RULESET_NAME))
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()


def test_two_rule_sets_in_one_team_cannot_share_a_name(app, session):
    team = _team(session)
    _rs(session, team.id, name="dup")
    session.add(RuleSet(team_id=team.id, name="dup"))
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()


def test_different_teams_may_reuse_a_name(app, session):
    team = _team(session)
    other = Team(name="Other")
    session.add(other)
    session.flush()
    _rs(session, team.id, name="shared")
    _rs(session, other.id, name="shared")
    assert session.query(RuleSet).filter_by(name="shared").count() == 2


def test_deleting_a_rule_set_cascades_to_its_versions(app, session):
    team = _team(session)
    rs = _rs(session, team.id)
    rs_id = rs.id
    session.delete(rs)
    session.commit()
    assert session.query(RuleSetVersion).filter_by(rule_set_id=rs_id).count() == 0


# --------------------------------------------------------------------------- #
# Resolution order
# --------------------------------------------------------------------------- #
def _sysset(session):
    return get_or_create_settings(session)


def test_explicit_version_ids_win(app, session):
    team = _team(session)
    rs = _rs(session, team.id)
    v1 = latest_version(session, rs.id)
    add_rule_set_version(session, rs, RULES2)
    session.commit()
    got = resolve_rule_set_versions(
        session, team.id, {"rule_set_version_ids": [v1.id]}, _sysset(session)
    )
    assert [v.version_no for v in got] == [1]  # the pin, not the latest


def test_rule_set_ids_resolve_to_the_latest_version(app, session):
    team = _team(session)
    rs = _rs(session, team.id)
    add_rule_set_version(session, rs, RULES2)
    session.commit()
    got = resolve_rule_set_versions(session, team.id, {"rule_set_ids": [rs.id]}, _sysset(session))
    assert [v.version_no for v in got] == [2]


def test_falls_back_to_the_system_default(app, session):
    team = _team(session)
    got = resolve_rule_set_versions(session, team.id, None, _sysset(session))
    assert len(got) == 1 and got[0].rule_set.is_builtin


def test_no_default_resolves_to_nothing(app, session):
    """…and the worker then uses the legacy env config, so nothing regresses."""
    team = _team(session)
    sysset = _sysset(session)
    sysset.default_rule_set_id = None
    session.flush()
    assert resolve_rule_set_versions(session, team.id, {}, sysset) == []


def test_order_is_preserved(app, session):
    team = _team(session)
    a = _rs(session, team.id, name="a")
    b = _rs(session, team.id, name="b", content=RULES2)
    got = resolve_rule_set_versions(
        session, team.id, {"rule_set_ids": [b.id, a.id]}, _sysset(session)
    )
    assert [v.rule_set_id for v in got] == [b.id, a.id]


def test_a_builtin_is_resolvable_by_any_team(app, session):
    _team(session)
    other = Team(name="Other")
    session.add(other)
    session.flush()
    builtin = session.query(RuleSet).filter_by(team_id=None, name=BUILTIN_RULESET_NAME).one()
    got = resolve_rule_set_versions(
        session, other.id, {"rule_set_ids": [builtin.id]}, _sysset(session)
    )
    assert len(got) == 1


def test_another_teams_rule_set_is_rejected(app, session):
    """A pinned id arrives from the client — hiding it in the picker is not enough."""
    team = _team(session)
    other = Team(name="Other")
    session.add(other)
    session.flush()
    theirs = _rs(session, other.id, name="theirs")
    with pytest.raises(RuleSetResolutionError, match="does not belong"):
        resolve_rule_set_versions(session, team.id, {"rule_set_ids": [theirs.id]}, _sysset(session))
    v = latest_version(session, theirs.id)
    with pytest.raises(RuleSetResolutionError, match="does not belong"):
        resolve_rule_set_versions(
            session, team.id, {"rule_set_version_ids": [v.id]}, _sysset(session)
        )


def test_unknown_ids_are_rejected(app, session):
    team = _team(session)
    with pytest.raises(RuleSetResolutionError, match="not found"):
        resolve_rule_set_versions(session, team.id, {"rule_set_ids": [9999]}, _sysset(session))
    with pytest.raises(RuleSetResolutionError, match="not found"):
        resolve_rule_set_versions(
            session, team.id, {"rule_set_version_ids": [9999]}, _sysset(session)
        )


def test_a_rule_set_with_no_versions_is_rejected(app, session):
    team = _team(session)
    empty = RuleSet(team_id=team.id, name="empty")
    session.add(empty)
    session.flush()
    with pytest.raises(RuleSetResolutionError, match="no versions"):
        resolve_rule_set_versions(session, team.id, {"rule_set_ids": [empty.id]}, _sysset(session))


# --------------------------------------------------------------------------- #
# Pinning
# --------------------------------------------------------------------------- #
def _analysis(session, team):
    admin = session.query(User).filter_by(username="admin").one()
    proj = services.get_or_create_default_project(session, team.id)
    b = Binary(
        team_id=team.id,
        project_id=proj.id,
        sha256="c" * 64,
        filename="x",
        size=10,
        storage_key="k",
        uploaded_by=admin.id,
    )
    session.add(b)
    session.flush()
    a = Analysis(team_id=team.id, binary_id=b.id, mode=AnalysisMode.vr, created_by=admin.id)
    session.add(a)
    session.flush()
    return a


def test_pins_round_trip_in_config_order(app, session):
    team = _team(session)
    a = _rs(session, team.id, name="a")
    b = _rs(session, team.id, name="b", content=RULES2)
    analysis = _analysis(session, team)
    pin_rule_sets(
        session, analysis.id, [latest_version(session, b.id), latest_version(session, a.id)]
    )
    session.commit()
    assert [v.rule_set_id for v in pinned_rule_set_versions(session, analysis.id)] == [b.id, a.id]


def test_a_pinned_version_cannot_be_deleted(app, session):
    """RESTRICT is the whole point: an old report stays explainable."""
    team = _team(session)
    rs = _rs(session, team.id)
    version = latest_version(session, rs.id)
    analysis = _analysis(session, team)
    pin_rule_sets(session, analysis.id, [version])
    session.commit()
    session.delete(version)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()
