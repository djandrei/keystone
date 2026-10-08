"""Typed client for `ghidra-headless-mcp`, over its plain HTTP/JSON surface.

Each MCP tool is a `POST {base}/{tool}` whose body is the argument dict and whose
response is the tool's result JSON (null fields may be omitted — always use
.get()). The base is the server's `--http` `/api`, which answers failures with a
status that says whose fault it was and a `{"error": {"kind", "message"}}` body;
binaries go to `POST {base}/upload` as raw bytes.

The transport is injectable: unit tests pass a `FakeTransport`; the default
`HttpTransport` (stdlib urllib) talks to a running server. Every call is a JVM cold
start on the server (~2.8 s), so the client batches where the server supports it
(decompile/xref list forms) to amortize it.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Protocol, runtime_checkable

# Above the server's ANALYZE_TIMEOUT_S (1800 s), so a slow import ends with the
# server's 504 rather than a client timeout that would be retried as new work.
IMPORT_TIMEOUT_S = 1830.0


class McpError(RuntimeError):
    """A tool call failed after exhausting retries, or returned an error envelope."""


@runtime_checkable
class Transport(Protocol):
    def call(self, tool: str, args: dict) -> dict: ...

    def upload(self, filename: str, data: bytes, params: dict, timeout: float) -> dict: ...


def _error_detail(e: urllib.error.HTTPError) -> str:
    """`kind: message` from the server's error body, else the raw text."""
    raw = e.read().decode("utf-8", "replace")
    try:
        err = json.loads(raw).get("error")
        if isinstance(err, dict) and err.get("message"):
            return f"{err.get('kind', 'error')}: {err['message']}"
    except (ValueError, AttributeError):
        pass
    return raw[:500]


class HttpTransport:
    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        timeout: float = 120.0,
        retries: int = 2,
        backoff: float = 0.5,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or None
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff

    def _headers(self, content_type: str) -> dict:
        headers = {"Content-Type": content_type}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def call(self, tool: str, args: dict) -> dict:
        body = json.dumps(args).encode("utf-8")
        return self._post(tool, f"{self.base_url}/{tool}", body, "application/json", self.timeout)

    def upload(self, filename: str, data: bytes, params: dict, timeout: float) -> dict:
        query = urllib.parse.urlencode({"filename": filename, **params})
        url = f"{self.base_url}/upload?{query}"
        return self._post("upload", url, data, "application/octet-stream", timeout)

    def _post(self, tool: str, url: str, body: bytes, content_type: str, timeout: float) -> dict:
        last: Exception | None = None
        for attempt in range(self.retries + 1):
            req = urllib.request.Request(
                url, data=body, headers=self._headers(content_type), method="POST"
            )
            try:
                with urllib.request.urlopen(
                    req, timeout=timeout
                ) as resp:  # noqa: S310 (trusted internal service)
                    payload = resp.read().decode("utf-8")
                parsed = json.loads(payload) if payload else {}
                return parsed if isinstance(parsed, dict) else {"result": parsed}
            except urllib.error.HTTPError as e:
                # 4xx is the caller's fault and 504 an analysis that ran out of
                # time — repeating either cannot help. Other 5xx (incl. JVM
                # warmup 502/503) are retryable.
                if e.code < 500 or e.code == 504 or attempt == self.retries:
                    raise McpError(f"{tool} -> HTTP {e.code}: {_error_detail(e)}") from e
                last = e
            except (urllib.error.URLError, TimeoutError, ValueError) as e:
                if attempt == self.retries:
                    raise McpError(f"{tool} -> {e}") from e
                last = e
            time.sleep(self.backoff * (2**attempt))
        raise McpError(f"{tool} -> {last}")  # unreachable, keeps type-checkers happy


class GhidraMcpClient:
    """Thin, typed wrapper over the tool surface the pipelines need."""

    def __init__(
        self,
        base_url: str | None = None,
        transport: Transport | None = None,
        *,
        api_key: str | None = None,
    ) -> None:
        if transport is None:
            if not base_url:
                raise ValueError("GhidraMcpClient needs a base_url or a transport")
            transport = HttpTransport(base_url, api_key=api_key)
        self._t = transport

    # --- import / analyze ---------------------------------------------------
    def import_binary(self, filename: str, data: bytes) -> dict:
        """Upload the bytes, import + auto-analyze them, and let the server delete
        the upload — one request. The server stages the file in a private
        directory, so concurrent imports of the same name cannot collide. Returns
        UploadResult; the created program name is in `analysis.program`."""
        return self._t.upload(
            filename, data, {"analyze": "true", "keep": "false"}, IMPORT_TIMEOUT_S
        )

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
    def xrefs_to(
        self, program: str | list[str], target: str | list[str], *, limit: int = 100
    ) -> dict:
        return self._t.call("list_xrefs_to", {"program": program, "target": target, "limit": limit})

    def xrefs_from(
        self, program: str | list[str], target: str | list[str], *, limit: int = 100
    ) -> dict:
        return self._t.call(
            "list_xrefs_from", {"program": program, "target": target, "limit": limit}
        )

    # --- search / resolve ---------------------------------------------------
    def search_code(self, program: str, pattern: str, *, limit: int = 100) -> dict:
        return self._t.call("search_code", {"program": program, "pattern": pattern, "limit": limit})

    def resolve_symbol(self, name: str | list[str], programs: str | list[str] = "*") -> dict:
        return self._t.call("resolve_symbol", {"name": name, "programs": programs})

    # --- call paths -----------------------------------------------------------
    def find_call_paths(
        self, program: str, source: str, target: str, *, max_depth: int = 8, max_paths: int = 3
    ) -> dict:
        """Call chains from `source` to `target` (names or entry addresses), each a
        list of {name, address} from source to target. Only calls Ghidra resolved
        are edges, so no path does not mean unreachable. `truncated` means
        max_paths stopped the search. The default asks for few paths, since one
        is proof."""
        return self._t.call(
            "find_call_paths",
            {
                "program": program,
                "source": source,
                "target": target,
                "max_depth": max_depth,
                "max_paths": max_paths,
            },
        )
