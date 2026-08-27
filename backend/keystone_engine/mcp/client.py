"""Typed client for `ghidra-headless-mcp` (30 tools behind mcpo/OpenAPI).

Each MCP tool is a `POST {base}/{tool}` whose body is the argument dict and whose
response is the tool's result JSON (mcpo omits null fields — always use .get()).

The transport is injectable: unit tests pass a `FakeTransport`; the default
`HttpTransport` (stdlib urllib) talks to a running mcpo. Every call is a JVM cold
start on the server (~2.8 s), so the client batches where the server supports it
(decompile/xref list forms) to amortize it.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Protocol, runtime_checkable


class McpError(RuntimeError):
    """A tool call failed after exhausting retries, or returned an error envelope."""


@runtime_checkable
class Transport(Protocol):
    def call(self, tool: str, args: dict) -> dict: ...


class HttpTransport:
    def __init__(
        self, base_url: str, *, timeout: float = 120.0, retries: int = 2, backoff: float = 0.5
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff

    def call(self, tool: str, args: dict) -> dict:
        url = f"{self.base_url}/{tool}"
        body = json.dumps(args).encode("utf-8")
        last: Exception | None = None
        for attempt in range(self.retries + 1):
            req = urllib.request.Request(
                url, data=body, headers={"Content-Type": "application/json"}, method="POST"
            )
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 (trusted internal service)
                    payload = resp.read().decode("utf-8")
                parsed = json.loads(payload) if payload else {}
                return parsed if isinstance(parsed, dict) else {"result": parsed}
            except urllib.error.HTTPError as e:
                # 5xx (incl. JVM warmup 502/503) are retryable; 4xx are not.
                if e.code < 500 or attempt == self.retries:
                    detail = e.read().decode("utf-8", "replace")[:500]
                    raise McpError(f"{tool} -> HTTP {e.code}: {detail}") from e
                last = e
            except (urllib.error.URLError, TimeoutError, ValueError) as e:
                if attempt == self.retries:
                    raise McpError(f"{tool} -> {e}") from e
                last = e
            time.sleep(self.backoff * (2**attempt))
        raise McpError(f"{tool} -> {last}")  # unreachable, keeps type-checkers happy


class GhidraMcpClient:
    """Thin, typed wrapper over the tool surface the pipelines need."""

    def __init__(self, base_url: str | None = None, transport: Transport | None = None) -> None:
        if transport is None:
            if not base_url:
                raise ValueError("GhidraMcpClient needs a base_url or a transport")
            transport = HttpTransport(base_url)
        self._t = transport

    # --- import / analyze ---------------------------------------------------
    def analyze_binary(self, binary_path: str, force: bool = False) -> dict:
        """Import + auto-analyze once. Returns AnalysisResult (incl. the created
        program name, which is not always the file name)."""
        return self._t.call("analyze_binary", {"binary_path": binary_path, "force": force})

    def list_programs(self, refresh: bool = False) -> list[str]:
        return self._t.call("list_programs", {"refresh": refresh}).get("programs", [])

    def program_info(self, program: str) -> dict:
        return self._t.call("get_program_info", {"program": program})

    # --- structure ----------------------------------------------------------
    def list_functions(
        self, program: str, *, name_contains: str | None = None, limit: int = 200, offset: int = 0
    ) -> dict:
        args: dict = {"program": program, "limit": limit, "offset": offset}
        if name_contains:
            args["name_contains"] = name_contains
        return self._t.call("list_functions", args)

    def list_imports(self, program: str, *, limit: int = 200, offset: int = 0) -> dict:
        return self._t.call(
            "list_symbols", {"program": program, "kind": "import", "limit": limit, "offset": offset}
        )

    def list_exports(self, program: str, *, limit: int = 200, offset: int = 0) -> dict:
        return self._t.call(
            "list_symbols", {"program": program, "kind": "export", "limit": limit, "offset": offset}
        )

    def list_strings(self, program: str, *, limit: int = 200, offset: int = 0) -> dict:
        return self._t.call("list_strings", {"program": program, "limit": limit, "offset": offset})

    # --- decompile (single or batched) --------------------------------------
    def decompile_function(self, program: str, function: str | list[str]) -> dict:
        return self._t.call("decompile_function", {"program": program, "function": function})

    # --- xrefs (target may be a list; program may be a list or "*") ----------
    def xrefs_to(self, program: str | list[str], target: str | list[str], *, limit: int = 100) -> dict:
        return self._t.call("list_xrefs_to", {"program": program, "target": target, "limit": limit})

    def xrefs_from(self, program: str | list[str], target: str | list[str], *, limit: int = 100) -> dict:
        return self._t.call("list_xrefs_from", {"program": program, "target": target, "limit": limit})

    # --- search / resolve ---------------------------------------------------
    def search_code(self, program: str, pattern: str, *, limit: int = 100) -> dict:
        return self._t.call("search_code", {"program": program, "pattern": pattern, "limit": limit})

    def resolve_symbol(self, name: str | list[str], programs: str | list[str] = "*") -> dict:
        return self._t.call("resolve_symbol", {"name": name, "programs": programs})
