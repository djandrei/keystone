"""Stage 2.1 integration: the MCP client answers against a live ghidra-headless-mcp.

Skips unless the service is reachable (set KEYSTONE_MCP_ENDPOINT; from a
Keystone container it is http://host.docker.internal:1351/api, the server's
--http service). Deselected by default — run with `pytest -m integration`, from
the worker container (it maps host.docker.internal and carries the API key).

The binary is tests/fixtures/bin/keycheck.x86_64, built from fixtures/src by
fixtures/build.sh and committed. It is imported, never executed. The imported
program is left in the server's project: re-imports are idempotent, and
deleting it could delete the whole project if it were the last program there."""

from __future__ import annotations

import os
import urllib.request
from pathlib import Path

import pytest

from keystone_engine.mcp import GhidraMcpClient, McpError

pytestmark = pytest.mark.integration

ENDPOINT = os.environ.get("KEYSTONE_MCP_ENDPOINT", "http://host.docker.internal:1351/api")
API_KEY = os.environ.get("KEYSTONE_MCP_API_KEY") or os.environ.get("GHMCP_API_KEY")
# The server's default cap; override if its MAX_STREAM_UPLOAD_BYTES differs.
SERVER_UPLOAD_LIMIT = int(os.environ.get("GHMCP_MAX_STREAM_UPLOAD_BYTES", str(128 * 1024 * 1024)))

FIXTURE = Path(__file__).parent / "fixtures" / "bin" / "keycheck.x86_64"
# Keystone uploads as {sha256}_{name}; a fixed prefix keeps this test's program
# recognisable in the server's project.
UPLOAD_NAME = "keystone-it_keycheck.x86_64"


@pytest.fixture(scope="module")
def client():
    c = GhidraMcpClient(base_url=ENDPOINT, api_key=API_KEY)
    try:
        c.list_programs()  # cheap reachability probe
    except (McpError, OSError) as e:
        pytest.skip(f"ghidra-headless-mcp not reachable at {ENDPOINT}: {e}")
    return c


@pytest.fixture(scope="module")
def imported(client):
    """Import the fixture once for the module, the way the worker does."""
    return client.import_binary(UPLOAD_NAME, FIXTURE.read_bytes())


@pytest.fixture(scope="module")
def program(imported):
    return imported["analysis"]["program"]


@pytest.fixture
def request_count(monkeypatch):
    """Count HTTP requests, to prove what is and is not retried."""
    real = urllib.request.urlopen
    count = {"n": 0}

    def counting(*args, **kwargs):
        count["n"] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(urllib.request, "urlopen", counting)
    return count


def test_list_programs_returns_a_list(client):
    assert isinstance(client.list_programs(), list)


# --- import: one request that uploads, imports and discards ------------------


def test_import_returns_the_program_and_keeps_no_upload(client, imported, program):
    assert program == UPLOAD_NAME
    assert imported["kept"] is False
    assert imported.get("path") is None  # nothing left on disk to point at
    uploads = client._t.call("list_uploads", {})["uploads"]
    assert UPLOAD_NAME not in {u["filename"] for u in uploads}
    assert program in client.list_programs()


def test_reimporting_the_same_bytes_is_idempotent(client, program):
    again = client.import_binary(UPLOAD_NAME, FIXTURE.read_bytes())
    assert again["analysis"]["program"] == program
    assert client.list_programs().count(program) == 1


# --- the calls the RE/VR pipelines make --------------------------------------


def test_program_info(client, program):
    info = client.program_info(program)
    assert info["language_id"] == "x86:LE:64:default"
    assert info["function_count"] > 0


def test_list_functions_finds_check_key(client, program):
    funcs = client.list_functions(program, name_contains="check_key")["functions"]
    assert [f["name"] for f in funcs] == ["check_key"]


def test_decompile_check_key(client, program):
    c_code = client.decompile_function(program, "check_key")["c"]
    assert "check_key" in c_code and "strcmp" in c_code


def test_decompile_batch(client, program):
    res = client.decompile_function(program, ["check_key", "main"])
    names = {r.get("name") for r in res.get("results", [])}
    assert {"check_key", "main"} <= names


def test_list_strings_has_the_fixture_strings(client, program):
    values = {s["value"] for s in client.list_strings(program, limit=500)["strings"]}
    assert {"KEYSTONE-FIXTURE-KEY", "ACCESS GRANTED"} <= values


def test_xrefs_to_check_key_include_main(client, program):
    result = client.xrefs_to(program, "check_key")["results"][0]
    assert result["resolved_kind"] == "function"
    assert "main" in {x.get("from_function") for x in result["xrefs"]}


def test_list_exports(client, program):
    names = {s["name"] for s in client.list_exports(program, limit=500)["symbols"]}
    assert "main" in names


# --- errors: kind + message, and client errors are not retried --------------


def test_missing_binary_is_404_and_not_retried(client, request_count):
    with pytest.raises(McpError, match=r"HTTP 404: not_found: binary not found"):
        client.analyze_binary("/no/such/binary")
    assert request_count["n"] == 1


def test_bad_upload_name_is_400_and_not_retried(client, request_count):
    with pytest.raises(McpError, match=r"HTTP 400: bad_argument"):
        client.import_binary("../escape", b"\x7fELF")
    assert request_count["n"] == 1


def test_invalid_arguments_are_422_and_not_retried(client, program, request_count):
    with pytest.raises(McpError, match=r"HTTP 422: invalid_arguments"):
        client._t.call("list_functions", {"program": program, "limit": "not-a-number"})
    assert request_count["n"] == 1


@pytest.mark.xfail(
    strict=True,
    reason="ghidra-headless-mcp answers 413 from Content-Length and closes the "
    "connection while the body is still being sent, so the client sees a "
    "connection reset (and retries) instead of the 413. Passes once the server "
    "drains the body before replying.",
)
def test_oversize_upload_is_413_too_large_and_not_retried(client, request_count):
    with pytest.raises(McpError, match=r"HTTP 413: too_large"):
        client.import_binary("keystone-it_oversize.bin", b"\0" * (SERVER_UPLOAD_LIMIT + 1))
    assert request_count["n"] == 1
