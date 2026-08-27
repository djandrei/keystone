"""Stage 2.6: the analysis job lifecycle (framework-free core, injected fakes)."""
from __future__ import annotations

import pytest

from keystone_api import services
from keystone_api.jobs import run_analysis_core
from keystone_api.models import Analysis, AnalysisMode, AnalysisStatus, Binary, Team, User
from keystone_api.security import hash_password
from keystone_engine.events import ProgressEvent


def _make_analysis(session) -> Analysis:
    services.bootstrap(session)
    team = session.query(Team).filter_by(name="Default").one()
    u = session.query(User).filter_by(username="admin").one()
    b = Binary(team_id=team.id, sha256="s" * 64, filename="ls", size=10, storage_key="binaries/x", uploaded_by=u.id)
    session.add(b)
    session.flush()
    a = Analysis(team_id=team.id, binary_id=b.id, mode=AnalysisMode.re, created_by=u.id)
    session.add(a)
    session.commit()
    return a


def test_lifecycle_succeeds_and_persists(session):
    a = _make_analysis(session)
    published: list[dict] = []
    persisted: dict = {}

    def pipeline(_a):
        yield ProgressEvent.step_start("overview", 1)
        yield ProgressEvent.step_finish("overview", 2)
        return "RESULT-TUPLE"

    def persist(_s, _a, result):
        persisted["r"] = result

    status = run_analysis_core(
        a.id, session, pipeline=pipeline, persist=persist, publish=lambda i, e: published.append(e)
    )
    assert status is AnalysisStatus.succeeded
    session.refresh(a)
    assert a.status is AnalysisStatus.succeeded and a.started_at and a.finished_at
    assert len(a.progress["events"]) == 2  # snapshot persisted
    assert persisted["r"] == "RESULT-TUPLE"
    assert [e["type"] for e in published][-1] == "done"


def test_cancel_aborts_between_steps(session):
    a = _make_analysis(session)
    checks = {"n": 0}

    def is_canceled(_id):
        checks["n"] += 1
        return checks["n"] > 1  # allow one event, then cancel

    def pipeline(_a):
        yield ProgressEvent.step_start("overview", 1)
        yield ProgressEvent.step_start("decompile", 2)  # never reached
        return "X"

    published: list[dict] = []
    status = run_analysis_core(
        a.id, session, pipeline=pipeline, persist=lambda *x: None,
        publish=lambda i, e: published.append(e), is_canceled=is_canceled,
    )
    assert status is AnalysisStatus.canceled
    session.refresh(a)
    assert a.status is AnalysisStatus.canceled
    assert published[-1]["type"] == "canceled"


def test_failure_records_error(session):
    a = _make_analysis(session)

    def pipeline(_a):
        yield ProgressEvent.step_start("overview", 1)
        raise RuntimeError("ghidra exploded")

    status = run_analysis_core(a.id, session, pipeline=pipeline, persist=lambda *x: None)
    assert status is AnalysisStatus.failed
    session.refresh(a)
    assert a.status is AnalysisStatus.failed and "ghidra exploded" in a.error


def test_missing_analysis_returns_failed(session):
    services.bootstrap(session)
    session.commit()
    assert run_analysis_core(9999, session, pipeline=lambda a: iter(()), persist=lambda *x: None) is AnalysisStatus.failed
