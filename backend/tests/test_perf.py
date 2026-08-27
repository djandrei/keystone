"""Stage 5.2: no N+1 on the hot list endpoint + a perf-smoke over many analyses."""

from __future__ import annotations

from sqlalchemy import event

from keystone_api import services
from keystone_api.db import get_engine
from keystone_api.jobs import run_analysis_core
from keystone_api.models import Analysis, AnalysisMode, AnalysisStatus, Binary, Team, User
from keystone_engine.events import ProgressEvent


class QueryCounter:
    def __init__(self):
        self.count = 0

    def __enter__(self):
        self._engine = get_engine()
        event.listen(self._engine, "before_cursor_execute", self._cb)
        return self

    def _cb(self, *a):
        self.count += 1

    def __exit__(self, *a):
        event.remove(self._engine, "before_cursor_execute", self._cb)


def _seed_analyses(session, n):
    services.bootstrap(session)
    team = session.query(Team).filter_by(name="Default").one()
    u = session.query(User).filter_by(username="admin").one()
    b = session.query(Binary).filter_by(team_id=team.id, sha256="a" * 64).first()
    if b is None:
        b = Binary(
            team_id=team.id,
            sha256="a" * 64,
            filename="x",
            size=1,
            storage_key="k",
            uploaded_by=u.id,
        )
        session.add(b)
        session.flush()
    for _ in range(n):
        session.add(
            Analysis(
                team_id=team.id,
                binary_id=b.id,
                mode=AnalysisMode.re,
                status=AnalysisStatus.succeeded,
                created_by=u.id,
            )
        )
    session.commit()
    return u


def _login(client):
    return client.post(
        "/auth/login", json={"username": "admin", "password": "change-me"}
    ).get_json()["access_token"]


def test_list_analyses_is_not_n_plus_one(app, client, session):
    _seed_analyses(session, 5)
    tok = _login(client)
    h = {"Authorization": f"Bearer {tok}"}
    with QueryCounter() as c5:
        client.get("/analyses?limit=100", headers=h)
    # add many more rows; the query count must stay flat (no per-row query)
    _seed_analyses(session, 25)
    with QueryCounter() as c30:
        client.get("/analyses?limit=100", headers=h)
    assert c30.count == c5.count, f"N+1 regression: {c5.count} -> {c30.count}"
    assert c30.count <= 8  # count + items + batched usernames + auth lookups


def test_perf_smoke_many_analyses_succeed(session):
    u = _seed_analyses(session, 0)
    from keystone_api.models import Binary as B

    b = session.query(B).first()

    def pipeline(_a):
        yield ProgressEvent.step_start("s", 1)
        yield ProgressEvent.step_finish("s", 2)
        return "R"

    team_id = b.team_id
    ids = []
    for _ in range(10):
        a = Analysis(team_id=team_id, binary_id=b.id, mode=AnalysisMode.re, created_by=u.id)
        session.add(a)
        session.commit()
        ids.append(a.id)

    for aid in ids:
        status = run_analysis_core(aid, session, pipeline=pipeline, persist=lambda *x: None)
        assert status is AnalysisStatus.succeeded
