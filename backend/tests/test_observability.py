"""Stage 5.1: health/readiness/metrics + structured request log shape."""

from __future__ import annotations

from keystone_api import services
from keystone_api.observability import build_request_log


def test_healthz(app, client):
    r = client.get("/healthz")
    assert r.status_code == 200 and r.get_json()["status"] == "ok"


def test_readyz_ok_and_failure(app, client):
    app.config["READYZ_CHECKS"] = {"db": lambda: None, "redis": lambda: None}
    r = client.get("/readyz")
    assert r.status_code == 200 and r.get_json()["status"] == "ready"
    assert r.get_json()["checks"] == {"db": "ok", "redis": "ok"}

    def boom():
        raise RuntimeError("down")

    app.config["READYZ_CHECKS"] = {"db": lambda: None, "redis": boom}
    r = client.get("/readyz")
    assert r.status_code == 503 and r.get_json()["status"] == "not_ready"
    assert r.get_json()["checks"]["db"] == "ok" and "error" in r.get_json()["checks"]["redis"]


def test_request_log_shape():
    fields = build_request_log("GET", "/analyses", 200, 12.345, request_id="abc")
    assert fields == {
        "event": "request",
        "method": "GET",
        "path": "/analyses",
        "status": 200,
        "duration_ms": 12.35,
        "request_id": "abc",
    }


def test_metrics_admin_only_and_counts(app, client, session):
    services.bootstrap(session)
    from keystone_api.models import Analysis, AnalysisMode, AnalysisStatus, Binary, Team, User

    team = session.query(Team).filter_by(name="Default").one()
    u = session.query(User).filter_by(username="admin").one()
    b = Binary(
        team_id=team.id, sha256="a" * 64, filename="x", size=1, storage_key="k", uploaded_by=u.id
    )
    session.add(b)
    session.flush()
    session.add_all(
        [
            Analysis(
                team_id=team.id,
                binary_id=b.id,
                mode=AnalysisMode.re,
                status=AnalysisStatus.succeeded,
                created_by=u.id,
            ),
            Analysis(
                team_id=team.id,
                binary_id=b.id,
                mode=AnalysisMode.re,
                status=AnalysisStatus.running,
                created_by=u.id,
            ),
        ]
    )
    session.commit()

    tok = client.post(
        "/auth/login", json={"username": "admin", "password": "change-me"}
    ).get_json()["access_token"]
    r = client.get("/metrics", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    body = r.get_json()
    assert (
        body["analyses_by_status"]["succeeded"] == 1 and body["analyses_by_status"]["running"] == 1
    )
    assert body["active"] == 1  # queued + running
    # non-admin denied
    assert client.get("/metrics").status_code == 401
