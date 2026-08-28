"""Analysis lifecycle against a real Postgres + real Redis (integration).

Exercises run_analysis_core with real DB persistence (not SQLite) and a real Redis
publish. Run with the stack up: `pytest -m integration tests/test_lifecycle_integration.py`.
"""

from __future__ import annotations

import json

import pytest
from sqlalchemy import create_engine, text

from keystone_api import db as dbmod
from keystone_api.db import Base

pytestmark = pytest.mark.integration

_BASE = "postgresql+psycopg://keystone:keystone@postgres:5432"
_ADMIN_URL = f"{_BASE}/keystone"
_DB = "keystone_lifetest"
_URL = f"{_BASE}/{_DB}"
_REDIS = "redis://redis:6379/0"


@pytest.fixture
def pg():
    admin = create_engine(_ADMIN_URL, isolation_level="AUTOCOMMIT")
    with admin.connect() as c:
        c.execute(text(f"DROP DATABASE IF EXISTS {_DB} WITH (FORCE)"))
        c.execute(text(f"CREATE DATABASE {_DB}"))
    saved = (dbmod._engine, dbmod._SessionLocal)  # restore the unit-test engine after
    dbmod.init_db(_URL)
    import keystone_api.models  # noqa: F401  register tables

    Base.metadata.create_all(dbmod.get_engine())
    try:
        yield
    finally:
        dbmod._engine, dbmod._SessionLocal = saved
        with admin.connect() as c:
            c.execute(text(f"DROP DATABASE IF EXISTS {_DB} WITH (FORCE)"))
        admin.dispose()


def test_lifecycle_persists_on_real_postgres_and_publishes_to_redis(pg):
    import redis

    from keystone_api import services
    from keystone_api.jobs import run_analysis_core
    from keystone_api.models import Analysis, AnalysisMode, AnalysisStatus, Binary, Team, User
    from keystone_engine.events import ProgressEvent

    s = dbmod.get_session()
    services.bootstrap(s)
    team = s.query(Team).filter_by(name="Default").one()
    u = s.query(User).filter_by(username="admin").one()
    b = Binary(
        team_id=team.id, sha256="a" * 64, filename="x", size=10, storage_key="k", uploaded_by=u.id
    )
    s.add(b)
    s.flush()
    a = Analysis(team_id=team.id, binary_id=b.id, mode=AnalysisMode.re, created_by=u.id)
    s.add(a)
    s.commit()

    r = redis.Redis.from_url(_REDIS)
    published: list[dict] = []

    def publish(aid, ev):
        r.publish(f"analysis:{aid}", json.dumps(ev))  # real Redis
        published.append(ev)

    def pipeline(_a):
        yield ProgressEvent.step_start("overview", 1)
        yield ProgressEvent.step_finish("overview", 2)
        return "RESULT"

    status = run_analysis_core(a.id, s, pipeline=pipeline, persist=lambda *x: None, publish=publish)
    assert status is AnalysisStatus.succeeded

    s.expire_all()
    row = s.get(Analysis, a.id)
    assert row.status is AnalysisStatus.succeeded
    assert row.started_at and row.finished_at
    assert [e["step"] for e in row.progress["events"] if e["type"] == "step_finish"] == ["overview"]
    assert published[-1]["type"] == "done"
