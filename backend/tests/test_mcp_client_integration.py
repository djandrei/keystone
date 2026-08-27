"""Stage 2.1 integration: the MCP client answers against a live ghidra-headless-mcp.

Skips unless the service is reachable (set KEYSTONE_MCP_ENDPOINT; inside the
Compose network it is http://ghidra-mcp:1341). Deselected by default — run with
`pytest -m integration`."""

from __future__ import annotations

import os

import pytest

from keystone_engine.mcp import GhidraMcpClient, McpError

pytestmark = pytest.mark.integration

ENDPOINT = os.environ.get("KEYSTONE_MCP_ENDPOINT", "http://ghidra-mcp:1341")
API_KEY = os.environ.get("KEYSTONE_MCP_API_KEY") or os.environ.get("GHMCP_API_KEY")


@pytest.fixture
def client():
    c = GhidraMcpClient(base_url=ENDPOINT, api_key=API_KEY)
    try:
        c.list_programs()  # cheap reachability probe
    except (McpError, OSError) as e:
        pytest.skip(f"ghidra-headless-mcp not reachable at {ENDPOINT}: {e}")
    return c


def test_list_programs_returns_a_list(client):
    assert isinstance(client.list_programs(), list)
