"""probe_llm / _probe_target: provider header selection + error paths."""

from __future__ import annotations

import json
import urllib.error

from keystone_api import settings_api


def test_probe_target_openai_vs_anthropic():
    ep, h = settings_api._probe_target("https://api.example.com/v1", "K")
    assert ep.endswith("/models") and h["Authorization"] == "Bearer K"
    ep, h = settings_api._probe_target("https://api.minimax.io/anthropic/v1", "K")
    assert h["x-api-key"] == "K" and "anthropic-version" in h


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return json.dumps(self._payload).encode()


def test_probe_llm_ok(monkeypatch):
    monkeypatch.setattr(
        settings_api.urllib.request,
        "urlopen",
        lambda *a, **k: _Resp({"data": [{"id": "m1"}, {"id": "m2"}, {"bad": 1}]}),
    )
    out = settings_api.probe_llm("https://x/v1", "K")
    assert out["ok"] and out["models"] == ["m1", "m2"]


def test_probe_llm_http_error(monkeypatch):
    def boom(*a, **k):
        raise urllib.error.HTTPError("u", 401, "no", {}, None)

    monkeypatch.setattr(settings_api.urllib.request, "urlopen", boom)
    out = settings_api.probe_llm("https://x/v1", "K")
    assert out["ok"] is False and "401" in out["error"]


def test_probe_llm_url_error(monkeypatch):
    def boom(*a, **k):
        raise urllib.error.URLError("down")

    monkeypatch.setattr(settings_api.urllib.request, "urlopen", boom)
    out = settings_api.probe_llm("https://x/v1", "K")
    assert out["ok"] is False
