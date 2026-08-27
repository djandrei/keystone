from __future__ import annotations

import pytest
from sqlalchemy.exc import IntegrityError

from keystone_api.models import (
    Analysis,
    AnalysisMode,
    AnalysisStatus,
    Binary,
    Role,
    Team,
    TeamMember,
    TeamRole,
    User,
)


def _user(session, username="ana", role=Role.analyst):
    u = User(username=username, email=f"{username}@x", password_hash="x", role=role)
    session.add(u)
    session.flush()
    return u


def _team(session, name="Blue"):
    t = Team(name=name)
    session.add(t)
    session.flush()
    return t


def test_user_team_membership(session):
    u = _user(session)
    t = _team(session)
    session.add(TeamMember(team_id=t.id, user_id=u.id, team_role=TeamRole.lead))
    session.commit()
    assert session.get(User, u.id).memberships[0].team.name == "Blue"
    assert session.get(Team, t.id).members[0].user.username == "ana"


def test_role_enum_roundtrip(session):
    u = _user(session, "boss", role=Role.admin)
    session.commit()
    assert session.get(User, u.id).role is Role.admin


def test_unique_username(session):
    _user(session, "dup")
    session.commit()
    with pytest.raises(IntegrityError):
        _user(session, "dup")
        session.commit()


def test_binary_unique_per_team(session):
    u = _user(session)
    t = _team(session)
    session.add(
        Binary(
            team_id=t.id, sha256="a" * 64, filename="ls", size=1, storage_key="k1", uploaded_by=u.id
        )
    )
    session.commit()
    with pytest.raises(IntegrityError):  # same (team, sha) rejected
        session.add(
            Binary(
                team_id=t.id,
                sha256="a" * 64,
                filename="ls2",
                size=1,
                storage_key="k2",
                uploaded_by=u.id,
            )
        )
        session.commit()
    session.rollback()
    # a different team may hold the same bytes
    t2 = _team(session, "Red")
    session.add(
        Binary(
            team_id=t2.id,
            sha256="a" * 64,
            filename="ls",
            size=1,
            storage_key="k3",
            uploaded_by=u.id,
        )
    )
    session.commit()


def test_analysis_cascade_delete(session):
    u = _user(session)
    t = _team(session)
    b = Binary(
        team_id=t.id, sha256="b" * 64, filename="x", size=1, storage_key="k", uploaded_by=u.id
    )
    session.add(b)
    session.flush()
    a = Analysis(
        team_id=t.id,
        binary_id=b.id,
        mode=AnalysisMode.re,
        status=AnalysisStatus.queued,
        created_by=u.id,
    )
    session.add(a)
    session.commit()
    assert session.query(Analysis).count() == 1
    session.delete(a)
    session.commit()
    assert session.query(Analysis).count() == 0
