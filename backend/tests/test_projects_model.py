"""Project buckets: default project per team + auto-assignment of binaries."""

from __future__ import annotations

from keystone_api import services
from keystone_api.models import Binary, Project, Team, User


def _seed(session):
    services.bootstrap(session)
    team = session.query(Team).filter_by(name="Default").one()
    u = session.query(User).filter_by(username="admin").one()
    return team, u


def _binary(session, team, u, sha, *, project_id=None):
    b = Binary(
        team_id=team.id,
        sha256=sha,
        filename="x",
        size=10,
        storage_key="k" + sha[:6],
        uploaded_by=u.id,
        project_id=project_id,
    )
    session.add(b)
    session.flush()
    return b


def test_bootstrap_creates_default_project(session):
    team, _ = _seed(session)
    proj = session.query(Project).filter_by(team_id=team.id, is_default=True).one()
    assert proj.name == "Unassigned" and proj.is_default is True


def test_default_project_is_idempotent(session):
    team, u = _seed(session)
    p1 = services.get_or_create_default_project(session, team.id)
    p2 = services.get_or_create_default_project(session, team.id)
    assert p1.id == p2.id
    assert session.query(Project).filter_by(team_id=team.id, is_default=True).count() == 1


def test_binary_without_project_lands_in_default(session):
    team, u = _seed(session)
    default = session.query(Project).filter_by(team_id=team.id, is_default=True).one()
    b = _binary(session, team, u, "a" * 64)  # no project_id
    assert b.project_id == default.id


def test_binary_keeps_explicit_project(session):
    team, u = _seed(session)
    proj = Project(team_id=team.id, name="firmware-x")
    session.add(proj)
    session.flush()
    b = _binary(session, team, u, "b" * 64, project_id=proj.id)
    assert b.project_id == proj.id


def test_project_name_unique_per_team(session):
    import pytest
    from sqlalchemy.exc import IntegrityError

    team, _ = _seed(session)
    session.add(Project(team_id=team.id, name="dup"))
    session.flush()
    session.add(Project(team_id=team.id, name="dup"))
    with pytest.raises(IntegrityError):
        session.flush()


def test_before_flush_assigns_per_team_in_one_flush(session):
    services.bootstrap(session)
    default_team = session.query(Team).filter_by(name="Default").one()
    u = session.query(User).filter_by(username="admin").one()
    t2 = Team(name="T2")  # created directly -> no default project yet
    session.add(t2)
    session.flush()
    b1 = Binary(team_id=default_team.id, sha256="1" * 64, filename="a", size=10, storage_key="k1", uploaded_by=u.id)
    b2 = Binary(team_id=t2.id, sha256="2" * 64, filename="b", size=10, storage_key="k2", uploaded_by=u.id)
    session.add_all([b1, b2])
    session.commit()  # one flush: each binary lands in ITS team's default bucket
    p1 = session.query(Project).filter_by(team_id=default_team.id, is_default=True).one()
    p2 = session.query(Project).filter_by(team_id=t2.id, is_default=True).one()
    assert b1.project_id == p1.id and b2.project_id == p2.id and p1.id != p2.id
