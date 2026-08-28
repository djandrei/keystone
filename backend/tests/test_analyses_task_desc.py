"""Dashboard 'Task' data on the analyses list: binary filename + outcome summary
(RE purpose / VR findings), succeeded-only."""

from __future__ import annotations

from keystone_api import services
from keystone_api.analyses_api import _vr_summary
from keystone_api.models import (
    Analysis,
    AnalysisMode,
    AnalysisStatus,
    Binary,
    REResult,
    RiskLevel,
    Team,
    User,
    VRFinding,
)


def _tok(client):
    return client.post(
        "/auth/login", json={"username": "admin", "password": "change-me"}
    ).get_json()["access_token"]


def _seed(session):
    services.bootstrap(session)
    team = session.query(Team).filter_by(name="Default").one()
    u = session.query(User).filter_by(username="admin").one()
    b = Binary(
        team_id=team.id,
        sha256="a" * 64,
        filename="crackme2.x86_64",
        size=16120,
        storage_key="k",
        uploaded_by=u.id,
    )
    session.add(b)
    session.flush()
    return team, u, b


def _analysis(session, team, u, b, mode, status):
    a = Analysis(team_id=team.id, binary_id=b.id, mode=mode, status=status, created_by=u.id)
    session.add(a)
    session.flush()
    return a


def _first_row(client):
    tok = _tok(client)
    return client.get("/analyses", headers={"Authorization": f"Bearer {tok}"}).get_json()["items"][
        0
    ]


def test_re_succeeded_row_has_filename_and_purpose(app, client, session):
    team, u, b = _seed(session)
    a = _analysis(session, team, u, b, AnalysisMode.re, AnalysisStatus.succeeded)
    session.add(
        REResult(analysis_id=a.id, binary_type="cli_tool", purpose="A CLI string-comparison tool")
    )
    session.commit()
    row = _first_row(client)
    assert row["binary_filename"] == "crackme2.x86_64"
    assert row["summary"] == {"kind": "re", "purpose": "A CLI string-comparison tool"}


def test_vr_succeeded_row_summarizes_top_finding(app, client, session):
    team, u, b = _seed(session)
    a = _analysis(session, team, u, b, AnalysisMode.vr, AnalysisStatus.succeeded)
    session.add_all(
        [
            VRFinding(analysis_id=a.id, rule="r1", risk_level=RiskLevel.low, cwe_id="CWE-20"),
            VRFinding(analysis_id=a.id, rule="r2", risk_level=RiskLevel.high, cwe_id="CWE-798"),
        ]
    )
    session.commit()
    row = _first_row(client)
    assert row["binary_filename"] == "crackme2.x86_64"
    assert row["summary"] == {"kind": "vr", "count": 2, "top_risk": "high", "top_cwe": "CWE-798"}


def test_unfinished_row_has_null_summary(app, client, session):
    team, u, b = _seed(session)
    _analysis(session, team, u, b, AnalysisMode.re, AnalysisStatus.running)
    session.commit()
    row = _first_row(client)
    assert row["binary_filename"] == "crackme2.x86_64"
    assert row["summary"] is None


def test_vr_summary_helper_orders_by_severity():
    assert _vr_summary([]) == {"count": 0, "top_risk": None, "top_cwe": None}
    fs = [(RiskLevel.medium, "CWE-1"), (RiskLevel.critical, "CWE-2"), (RiskLevel.low, "CWE-3")]
    assert _vr_summary(fs) == {"count": 3, "top_risk": "critical", "top_cwe": "CWE-2"}
