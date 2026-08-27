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
