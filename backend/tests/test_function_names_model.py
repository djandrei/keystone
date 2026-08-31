"""Schema invariants for friendly function names (docs/function-naming-plan.md §6)."""

from __future__ import annotations

import pytest
from sqlalchemy.exc import IntegrityError

from keystone_api import services
from keystone_api.models import (
    Analysis,
    AnalysisFunction,
    AnalysisMode,
    Binary,
    FunctionName,
    Team,
    User,
)


def _binary(session, name="crackme2.x86_64", sha=None):
    services.bootstrap(session)
    team = session.query(Team).filter_by(name="Default").one()
    admin = session.query(User).filter_by(username="admin").one()
    proj = services.get_or_create_default_project(session, team.id)
    b = Binary(
        team_id=team.id,
        project_id=proj.id,
        sha256=(sha or "a" * 64),
        filename=name,
        size=1024,
        storage_key="k",
        uploaded_by=admin.id,
        ghidra_program_name=name,
    )
    session.add(b)
    session.flush()
    return b


def _analysis(session, binary):
    admin = session.query(User).filter_by(username="admin").one()
    a = Analysis(
        team_id=binary.team_id, binary_id=binary.id, mode=AnalysisMode.re, created_by=admin.id
    )
    session.add(a)
    session.flush()
    return a


def _fn(session, binary, address="1c0026f90", original="FUN_1c0026f90", **kw):
    f = FunctionName(binary_id=binary.id, address=address, original_name=original, **kw)
    session.add(f)
    session.flush()
    return f


def test_a_name_defaults_to_llm_source(app, session):
    b = _binary(session)
    f = _fn(session, b, suggested_name="parse_ioctl_header", purpose="Reads the IOCTL code.")
    session.commit()
    assert f.source == "llm"
    assert f.display_name == "parse_ioctl_header"


def test_display_name_falls_back_to_the_original(app, session):
    """A model suggestion that failed validation leaves the original showing."""
    b = _binary(session)
    f = _fn(session, b)
    session.commit()
    assert f.suggested_name is None
    assert f.display_name == "FUN_1c0026f90"


def test_one_name_per_address_per_binary(app, session):
    b = _binary(session)
    _fn(session, b)
    session.add(FunctionName(binary_id=b.id, address="1c0026f90", original_name="dup"))
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()


def test_two_binaries_may_name_the_same_address(app, session):
    """Addresses are only unique within a program."""
    b1 = _binary(session, sha="a" * 64)
    b2 = _binary(session, name="other.elf", sha="b" * 64)
    _fn(session, b1)
    _fn(session, b2)
    session.commit()
    assert session.query(FunctionName).filter_by(address="1c0026f90").count() == 2


def test_names_are_scoped_by_the_binarys_team(app, session):
    """No new authorization surface: if you can see the binary you can see its
    names."""
    b = _binary(session)
    f = _fn(session, b)
    session.commit()
    assert session.get(Binary, f.binary_id).team_id == b.team_id


def test_deleting_a_binary_takes_its_names(app, session):
    b = _binary(session)
    _fn(session, b)
    session.commit()
    bid = b.id
    session.delete(b)
    session.commit()
    assert session.query(FunctionName).filter_by(binary_id=bid).count() == 0


def test_inclusion_defaults_to_true(app, session):
    """A report that shows nothing until you tick boxes is worse than one you
    trim."""
    b = _binary(session)
    f = _fn(session, b)
    a = _analysis(session, b)
    session.add(AnalysisFunction(analysis_id=a.id, function_name_id=f.id))
    session.commit()
    link = session.get(AnalysisFunction, (a.id, f.id))
    assert link.included is True and link.position == 0


def test_deleting_an_analysis_drops_its_selection_but_keeps_the_names(app, session):
    """Names belong to the binary and outlive any one analysis."""
    b = _binary(session)
    f = _fn(session, b)
    a = _analysis(session, b)
    session.add(AnalysisFunction(analysis_id=a.id, function_name_id=f.id))
    session.commit()
    aid, fid = a.id, f.id
    session.delete(a)
    session.commit()
    assert session.query(AnalysisFunction).filter_by(analysis_id=aid).count() == 0
    assert session.get(FunctionName, fid) is not None


def test_two_analyses_of_one_binary_can_select_differently(app, session):
    b = _binary(session)
    f1 = _fn(session, b, address="1000", original="FUN_1000")
    f2 = _fn(session, b, address="2000", original="FUN_2000")
    a1, a2 = _analysis(session, b), _analysis(session, b)
    session.add_all(
        [
            AnalysisFunction(analysis_id=a1.id, function_name_id=f1.id, included=True),
            AnalysisFunction(analysis_id=a1.id, function_name_id=f2.id, included=False),
            AnalysisFunction(analysis_id=a2.id, function_name_id=f1.id, included=True),
            AnalysisFunction(analysis_id=a2.id, function_name_id=f2.id, included=True),
        ]
    )
    session.commit()
    inc = lambda aid: {  # noqa: E731
        r.function_name_id
        for r in session.query(AnalysisFunction).filter_by(analysis_id=aid, included=True)
    }
    assert inc(a1.id) == {f1.id} and inc(a2.id) == {f1.id, f2.id}


def test_a_user_corrected_name_is_marked_as_such(app, session):
    b = _binary(session)
    f = _fn(session, b, suggested_name="thing", source="user")
    session.commit()
    assert f.source == "user"
