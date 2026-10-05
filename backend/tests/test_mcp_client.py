"""Stage 2.1: MCP client mapping + transport retry (unit, offline)."""

from __future__ import annotations

import pytest

from keystone_engine.mcp import GhidraMcpClient, McpError


class FakeTransport:
    def __init__(self, responses: dict | None = None):
        self.calls: list[tuple[str, dict]] = []
        self.responses = responses or {}

    def call(self, tool: str, args: dict) -> dict:
        self.calls.append((tool, args))
        return self.responses.get(tool, {})

    def upload(self, filename: str, data: bytes, params: dict, timeout: float) -> dict:
        self.calls.append(("upload", {"filename": filename, "data": data, **params}))
        self.upload_timeout = timeout
        return self.responses.get("upload", {})


def test_imports_and_exports_map_to_list_symbols():
    t = FakeTransport()
    c = GhidraMcpClient(transport=t)
    c.list_imports("ls")
    c.list_exports("ls")
    assert t.calls[0][0] == "list_symbols" and t.calls[0][1]["kind"] == "import"
    assert t.calls[1][0] == "list_symbols" and t.calls[1][1]["kind"] == "export"


def test_analyze_and_list_programs():
    t = FakeTransport(
        {
            "analyze_binary": {"program": "ls", "ok": True},
            "list_programs": {"programs": ["ls", "notepad.exe"]},
        }
    )
    c = GhidraMcpClient(transport=t)
    assert c.analyze_binary("/samples/ls")["program"] == "ls"
    assert t.calls[0][1] == {"binary_path": "/samples/ls", "force": False}
    assert c.list_programs() == ["ls", "notepad.exe"]


def test_import_binary_is_one_upload_that_analyzes_and_discards():
    from keystone_engine.mcp.client import IMPORT_TIMEOUT_S

    t = FakeTransport({"upload": {"analysis": {"program": "x_ls"}}})
    c = GhidraMcpClient(transport=t)
    assert c.import_binary("x_ls", b"\x7fELF")["analysis"]["program"] == "x_ls"
    assert t.calls == [
        ("upload", {"filename": "x_ls", "data": b"\x7fELF", "analyze": "true", "keep": "false"})
    ]
    assert t.upload_timeout == IMPORT_TIMEOUT_S > 1800  # outlasts the server's analysis


def test_decompile_passes_single_or_batch():
    t = FakeTransport()
    c = GhidraMcpClient(transport=t)
    c.decompile_function("ls", "main")
    c.decompile_function("ls", ["main", "parse"])
    assert t.calls[0][1]["function"] == "main"
    assert t.calls[1][1]["function"] == ["main", "parse"]


def test_xrefs_accept_list_and_star():
    t = FakeTransport()
    c = GhidraMcpClient(transport=t)
    c.xrefs_to("*", ["malloc", "free"])
    assert t.calls[0][0] == "list_xrefs_to"
    assert t.calls[0][1]["program"] == "*" and t.calls[0][1]["target"] == ["malloc", "free"]


def test_requires_base_url_or_transport():
    with pytest.raises(ValueError):
        GhidraMcpClient()


def test_http_transport_retries_then_succeeds():
    from keystone_engine.mcp.client import HttpTransport

    class Flaky(HttpTransport):
        def __init__(self):
            super().__init__("http://x", retries=3, backoff=0.0)
            self.n = 0

    calls = {"n": 0}

    # exercise the retry loop by monkeypatching urlopen to fail twice then pass
    import urllib.error
    import urllib.request

    class FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"ok": true}'

    def fake_urlopen(req, timeout=None):
        calls["n"] += 1
        if calls["n"] < 3:
            raise urllib.error.URLError("connection refused")
        return FakeResp()

    orig = urllib.request.urlopen
    urllib.request.urlopen = fake_urlopen  # type: ignore[assignment]
    try:
        t = HttpTransport("http://x", retries=3, backoff=0.0)
        assert t.call("ping", {}) == {"ok": True}
        assert calls["n"] == 3
    finally:
        urllib.request.urlopen = orig  # type: ignore[assignment]


def test_http_transport_gives_up_and_raises():
    import urllib.error
    import urllib.request

    def always_fail(req, timeout=None):
        raise urllib.error.URLError("down")

    orig = urllib.request.urlopen
    urllib.request.urlopen = always_fail  # type: ignore[assignment]
    try:
        from keystone_engine.mcp.client import HttpTransport

        with pytest.raises(McpError):
            HttpTransport("http://x", retries=1, backoff=0.0).call("ping", {})
    finally:
        urllib.request.urlopen = orig  # type: ignore[assignment]


def test_http_transport_sends_bearer_when_key_set():
    import urllib.request

    from keystone_engine.mcp.client import HttpTransport

    captured = {}

    class FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b"{}"

    def fake_urlopen(req, timeout=None):
        captured["headers"] = dict(req.header_items())
        return FakeResp()

    orig = urllib.request.urlopen
    urllib.request.urlopen = fake_urlopen  # type: ignore[assignment]
    try:
        HttpTransport("http://x", api_key="secret-key-value").call("list_programs", {})
        assert captured["headers"].get("Authorization") == "Bearer secret-key-value"
        # no key -> no Authorization header
        captured.clear()
        HttpTransport("http://x").call("list_programs", {})
        assert "Authorization" not in captured["headers"]
    finally:
        urllib.request.urlopen = orig  # type: ignore[assignment]


def test_client_passes_api_key_to_default_transport():
    from keystone_engine.mcp.client import GhidraMcpClient, HttpTransport

    c = GhidraMcpClient(base_url="http://x", api_key="k")
    assert isinstance(c._t, HttpTransport) and c._t.api_key == "k"


class _Resp:
    def __init__(self, body: bytes = b"{}"):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self.body


def _http_error(code: int, kind: str, message: str):
    import io
    import json
    import urllib.error

    body = json.dumps({"error": {"kind": kind, "message": message}}).encode()
    return urllib.error.HTTPError("http://x", code, "err", {}, io.BytesIO(body))


def _patched_urlopen(monkeypatch, outcome):
    """urlopen that records each request and raises/returns `outcome(n)`."""
    import urllib.request

    requests: list = []

    def fake(req, timeout=None):
        requests.append((req, timeout))
        result = outcome(len(requests))
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(urllib.request, "urlopen", fake)
    return requests


@pytest.mark.parametrize("code,kind", [(400, "bad_argument"), (404, "not_found"), (504, "timeout")])
def test_client_errors_and_504_are_not_retried(monkeypatch, code, kind):
    from keystone_engine.mcp.client import HttpTransport

    reqs = _patched_urlopen(monkeypatch, lambda n: _http_error(code, kind, "nope"))
    with pytest.raises(McpError, match=f"HTTP {code}: {kind}: nope"):
        HttpTransport("http://x", retries=2, backoff=0.0).call("analyze_binary", {})
    assert len(reqs) == 1


def test_other_5xx_is_retried(monkeypatch):
    from keystone_engine.mcp.client import HttpTransport

    reqs = _patched_urlopen(
        monkeypatch, lambda n: _http_error(500, "error", "boom") if n < 2 else _Resp()
    )
    assert HttpTransport("http://x", retries=2, backoff=0.0).call("ping", {}) == {}
    assert len(reqs) == 2


def test_upload_sends_raw_bytes_and_413_is_too_large_not_retried(monkeypatch):
    from keystone_engine.mcp.client import HttpTransport

    reqs = _patched_urlopen(
        monkeypatch,
        lambda n: _http_error(413, "too_large", "file exceeds the 10-byte upload limit"),
    )
    t = HttpTransport("http://x/api", api_key="k", retries=2, backoff=0.0)
    with pytest.raises(McpError, match="HTTP 413: too_large: file exceeds"):
        t.upload("a b_ls", b"\x00\x01", {"analyze": "true", "keep": "false"}, 99.0)

    assert len(reqs) == 1
    req, timeout = reqs[0]
    assert req.full_url == "http://x/api/upload?filename=a+b_ls&analyze=true&keep=false"
    assert req.data == b"\x00\x01"  # raw, not base64/JSON
    assert req.get_header("Content-type") == "application/octet-stream"
    assert req.get_header("Authorization") == "Bearer k"
    assert timeout == 99.0


def test_non_json_error_body_falls_back_to_raw_text(monkeypatch):
    import io
    import urllib.error

    from keystone_engine.mcp.client import HttpTransport

    err = urllib.error.HTTPError("http://x", 403, "f", {}, io.BytesIO(b"Invalid API key"))
    _patched_urlopen(monkeypatch, lambda n: err)
    with pytest.raises(McpError, match="HTTP 403: Invalid API key"):
        HttpTransport("http://x", backoff=0.0).call("ping", {})
