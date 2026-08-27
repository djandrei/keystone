"""Stage 2.10: the fake engine pipeline persists a real RE result + report (drives
the M2 e2e without Ghidra/LLM)."""

from __future__ import annotations

from keystone_api import services
from keystone_api.jobs import run_analysis_core
from keystone_api.models import (
    Analysis,
    AnalysisMode,
    AnalysisStatus,
    Binary,
    Report,
    Team,
    User,
)
from keystone_api.persist import persist_re_result


class FakeStore:
    def __init__(self):
        self.objects = {}

    def put(self, key, data):
        self.objects[key] = data

    def exists(self, key):
        return key in self.objects

    def get(self, key):
        return self.objects[key]


def test_fake_pipeline_persists_re_result(session):
    from worker import _fake_pipeline

    services.bootstrap(session)
    team = session.query(Team).filter_by(name="Default").one()
    u = session.query(User).filter_by(username="admin").one()
    b = Binary(
        team_id=team.id, sha256="c" * 64, filename="ls", size=1, storage_key="k", uploaded_by=u.id
    )
    session.add(b)
    session.flush()
    a = Analysis(team_id=team.id, binary_id=b.id, mode=AnalysisMode.re, created_by=u.id)
    session.add(a)
    session.commit()

    store = FakeStore()
    status = run_analysis_core(
        a.id,
        session,
        pipeline=_fake_pipeline,
        persist=lambda s, an, r: persist_re_result(s, an, r, store=store),
    )
    assert status is AnalysisStatus.succeeded
    session.refresh(a)
    assert a.status is AnalysisStatus.succeeded
    assert a.re_result.language_runtime == "C" and a.re_result.binary_type == "cli_tool"
    report = session.get(Report, a.id)
    assert report is not None and store.get(report.storage_key)
    # progress captured the full step sequence
    steps = [e["step"] for e in a.progress["events"] if e["type"] == "step_finish"]
    assert "overview" in steps and "analyze" in steps
