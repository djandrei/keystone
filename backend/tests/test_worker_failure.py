"""The worker wrapper captures engine-SETUP failures (before the pipeline) and
marks the row failed — the escape path where a real run with no MCP key used to
die as a silent Celery task and leave the analysis stuck."""

from __future__ import annotations

from keystone_api import services
from keystone_api.config import Settings
from keystone_api.db import get_session
from keystone_api.models import Analysis, AnalysisMode, AnalysisStatus, Binary, Team, User


class _FakeStore:
    def put(self, key, data):  # noqa: D401
        pass

    def exists(self, key):
        return False


def _make_analysis(session) -> int:
    services.bootstrap(session)
    team = session.query(Team).filter_by(name="Default").one()
    u = session.query(User).filter_by(username="admin").one()
    b = Binary(
        team_id=team.id, sha256="w" * 64, filename="ls", size=1, storage_key="k", uploaded_by=u.id
    )
    session.add(b)
    session.flush()
    a = Analysis(team_id=team.id, binary_id=b.id, mode=AnalysisMode.re, created_by=u.id)
    session.add(a)
    session.commit()
    return a.id


def test_real_engine_missing_mcp_key_marks_failed(session, monkeypatch, caplog):
    import worker

    aid = _make_analysis(session)
    published: list[dict] = []

    # Real engine, no MCP key -> _run_analysis raises RuntimeError during setup.
    monkeypatch.setattr(
        worker,
        "settings",
        Settings(env="test", database_url="sqlite://", engine_fake=False, mcp_api_key=""),
    )
    monkeypatch.setattr(worker, "init_db", lambda *a, **k: None)
    monkeypatch.setattr(worker, "get_session", lambda: session)
    monkeypatch.setattr(worker, "get_object_store", lambda: _FakeStore())
    monkeypatch.setattr(worker, "_publish", lambda i, e: published.append(e))

    with caplog.at_level("ERROR", logger="keystone.jobs"):
        result = worker.run_analysis(aid)

    assert result == "failed"
    # the row is failed with the actionable reason — not stuck in queued/running
    fresh = get_session()
    try:
        row = fresh.get(Analysis, aid)
        assert row.status is AnalysisStatus.failed
        assert "KEYSTONE_MCP_API_KEY" in row.error
        assert row.finished_at is not None
    finally:
        fresh.close()
    assert published[-1]["type"] == "error"
    assert any(r.name == "keystone.jobs" and r.exc_info for r in caplog.records)
