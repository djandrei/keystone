from __future__ import annotations

from keystone_api import services, settings_api
from keystone_api.models import AuditLog, Role, SystemSettings, User
from keystone_api.security import hash_password


def _bootstrap(session):
    services.bootstrap(session)
    session.commit()


def _tok(client, u, p):
    return client.post("/auth/login", json={"username": u, "password": p}).get_json()["access_token"]


def _h(tok):
    return {"Authorization": f"Bearer {tok}"}


def test_get_and_put_settings(app, client, session):
    _bootstrap(session)
    admin = _tok(client, "admin", "change-me")
    # get: singleton exists, key not leaked
    r = client.get("/settings", headers=_h(admin))
    assert r.status_code == 200
    body = r.get_json()
    assert body["llm_endpoint_url"] is None and "llm_key_configured" in body
    assert "llm_api_key" not in body and "api_key" not in body
    # put
    r = client.put("/settings", headers=_h(admin), json={
        "llm_endpoint_url": "https://llm.example/api",
        "default_model": "qwen/qwen3-8b",
        "semgrep_config": {"rules": "p/ci"},
    })
    assert r.status_code == 200 and r.get_json()["default_model"] == "qwen/qwen3-8b"
    session.expire_all()
    row = session.get(SystemSettings, 1)
    assert row.llm_endpoint_url == "https://llm.example/api" and row.updated_by is not None
    # audited
    assert session.query(AuditLog).filter_by(action="settings.update").count() == 1


def test_settings_admin_only(app, client, session):
    _bootstrap(session)
    ana = User(username="ana", email="ana@x.io", password_hash=hash_password("pw123456"), role=Role.analyst)
    session.add(ana)
    session.commit()
    tok = _tok(client, "ana", "pw123456")
    assert client.get("/settings", headers=_h(tok)).status_code == 403
    assert client.put("/settings", headers=_h(tok), json={"default_model": "x"}).status_code == 403
    assert client.get("/settings").status_code == 401


def test_test_connection(app, client, session, monkeypatch):
    _bootstrap(session)
    admin = _tok(client, "admin", "change-me")
    # no endpoint configured -> 400
    assert client.post("/settings/test-connection", headers=_h(admin), json={}).status_code == 400
    # probe monkeypatched -> ok with models
    monkeypatch.setattr(settings_api, "probe_llm", lambda url, key, timeout=5.0: {"ok": True, "models": ["m1", "m2"]})
    r = client.post("/settings/test-connection", headers=_h(admin), json={"llm_endpoint_url": "https://llm.example/api"})
    assert r.status_code == 200 and r.get_json() == {"ok": True, "models": ["m1", "m2"]}
