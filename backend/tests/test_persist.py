"""persist_re_result / persist_vr_result + enum coercion."""

from __future__ import annotations

from keystone_api import services
from keystone_api.models import (
    Analysis,
    AnalysisMode,
    Binary,
    Classification,
    Report,
    REResult,
    RiskLevel,
    Team,
    User,
    VRFinding,
)
from keystone_api.persist import _enum_or_none, persist_re_result, persist_vr_result
from keystone_engine.results import Report as EngineReport
from keystone_engine.results import REResult as EngineRE
from keystone_engine.results import VRFinding as EngineVR


class FakeStore:
    def __init__(self):
        self.objects: dict[str, bytes] = {}

    def put(self, k, d):
        self.objects[k] = d

    def exists(self, k):
        return k in self.objects

    def get(self, k):
        return self.objects[k]


def _analysis(session, mode):
    services.bootstrap(session)
    team = session.query(Team).filter_by(name="Default").one()
    u = session.query(User).filter_by(username="admin").one()
    pid = team.id  # default project auto-assigned by the hook
    b = Binary(
        team_id=team.id, sha256="a" * 64, filename="x", size=10, storage_key="k", uploaded_by=u.id
    )
    session.add(b)
    session.flush()
    _ = pid
    a = Analysis(team_id=team.id, binary_id=b.id, mode=mode, created_by=u.id)
    session.add(a)
    session.flush()
    return a


def test_enum_or_none():
    assert _enum_or_none(Classification, "true_positive") is Classification.true_positive
    assert _enum_or_none(Classification, "") is None
    assert _enum_or_none(Classification, "garbage") is None  # ValueError branch
    assert _enum_or_none(RiskLevel, "high") is RiskLevel.high


def test_persist_re_result(session):
    a = _analysis(session, AnalysisMode.re)
    store = FakeStore()
    re = EngineRE(binary_type="cli_tool", purpose="p", language_runtime="C", tool_calls=3)
    persist_re_result(session, a, (re, EngineReport(format="md", content="# RE")), store=store)
    session.commit()
    row = session.get(REResult, a.id)
    assert row.binary_type == "cli_tool" and row.tool_calls == 3
    assert session.get(Report, a.id).storage_key in store.objects


def test_persist_vr_result(session):
    a = _analysis(session, AnalysisMode.vr)
    store = FakeStore()
    findings = [
        EngineVR(
            rule="r1",
            file="f.c",
            line=3,
            semgrep_message="m",
            classification="true_positive",
            risk_level="high",
            cwe_id="CWE-798",
            reasoning="x",
            reachable="yes",
            entry_path="main->f",
            confidence="high",
        ),
        EngineVR(rule="r2", classification="bogus", risk_level=None),  # coercion edge
    ]
    persist_vr_result(session, a, (findings, EngineReport(content="# VR")), store=store)
    session.commit()
    rows = session.query(VRFinding).filter_by(analysis_id=a.id).all()
    assert len(rows) == 2
    tp = next(r for r in rows if r.rule == "r1")
    assert tp.classification is Classification.true_positive and tp.risk_level is RiskLevel.high
    bogus = next(r for r in rows if r.rule == "r2")
    assert bogus.classification is None  # coerced from an invalid value
    assert session.get(Report, a.id).storage_key in store.objects
