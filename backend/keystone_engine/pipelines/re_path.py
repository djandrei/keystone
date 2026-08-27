"""The RE analysis path: overview → decompile key functions → ReAct analyzer →
report. Emits ProgressEvents per Step and returns (REResult, Report).

Run it as a generator; the final value is the result tuple::

    gen = re_path.run(binary, client)
    try:
        while True:
            publish(next(gen))
    except StopIteration as stop:
        result, report = stop.value
"""

from __future__ import annotations

from collections.abc import Generator
from dataclasses import dataclass
from typing import Any, Protocol

from keystone_engine.events import EventType, ProgressEvent
from keystone_engine.llm.retry import react_with_retry
from keystone_engine.mcp import GhidraMcpClient
from keystone_engine.results import Report, REResult
from keystone_engine.signatures.platform import _import_names

_ENTRY_HINTS = ("main", "entry", "_start", "start", "driverentry", "winmain", "dllmain", "wmain")


@dataclass
class BinaryRef:
    program: str  # program name inside the Ghidra project
    sha256: str  # content hash — the decompile cache key
    filename: str | None = None


# --- decompilation cache (in-memory default; worker backs it with MinIO in M3) --
class DecompileCache(Protocol):
    def get(self, sha256: str, fn: str) -> str | None: ...
    def put(self, sha256: str, fn: str, code: str) -> None: ...


class MemoryDecompileCache:
    def __init__(self) -> None:
        self._d: dict[tuple[str, str], str] = {}

    def get(self, sha256: str, fn: str) -> str | None:
        return self._d.get((sha256, fn))

    def put(self, sha256: str, fn: str, code: str) -> None:
        self._d[(sha256, fn)] = code


class _Seq:
    def __init__(self) -> None:
        self.n = 0

    def next(self) -> int:
        self.n += 1
        return self.n


# --- steps ------------------------------------------------------------------
def build_overview(client: GhidraMcpClient, program: str) -> dict:
    info = client.program_info(program)
    imports = _import_names(client, program)[:40]
    strings_raw = client.list_strings(program).get("strings", [])
    strings = [
        (s.get("value") or s.get("string") or "") if isinstance(s, dict) else str(s)
        for s in strings_raw
    ][:30]
    text = (
        f"Program: {info.get('name', program)}\n"
        f"Format: {info.get('executable_format')}  Language: {info.get('language_id')}\n"
        f"Functions: {info.get('function_count')}  Symbols: {info.get('symbol_count')}\n"
        f"Imports (sample): {', '.join(imports)}\n"
        f"Strings (sample): {' | '.join(s for s in strings if s)}"
    )
    return {"info": info, "imports": imports, "strings": strings, "text": text}


def pick_key_functions(client: GhidraMcpClient, program: str, *, max_fns: int = 8) -> list[str]:
    fns = client.list_functions(program, limit=500).get("functions", [])
    real = [f for f in fns if not f.get("is_thunk") and not f.get("is_external") and f.get("name")]

    priority = [f for f in real if any(h in f["name"].lower() for h in _ENTRY_HINTS)]
    export_names = {
        e["name"]
        for e in client.list_exports(program).get("symbols", [])
        if isinstance(e, dict) and e.get("name")
    }
    exported = [f for f in real if f["name"] in export_names]
    by_size = sorted(real, key=lambda f: f.get("size", 0), reverse=True)

    ordered: list[str] = []
    for group in (priority, exported, by_size):
        for f in group:
            if f["name"] not in ordered:
                ordered.append(f["name"])
            if len(ordered) >= max_fns:
                return ordered[:max_fns]
    return ordered[:max_fns]


def decompile_key_functions(
    client: GhidraMcpClient, program: str, sha256: str, fn_names: list[str], cache: DecompileCache
) -> dict[str, str]:
    """Decompile the misses in ONE batched call (amortizing JVM cold start),
    serving hits from the (sha256, fn) cache."""
    out: dict[str, str] = {}
    misses: list[str] = []
    for fn in fn_names:
        hit = cache.get(sha256, fn)
        if hit is not None:
            out[fn] = hit
        else:
            misses.append(fn)
    if not misses:
        return out

    resp = client.decompile_function(program, misses if len(misses) > 1 else misses[0])
    if "results" in resp:  # batch envelope
        for r in resp["results"]:
            code = r.get("c") or ""
            out[r["target"]] = code
            cache.put(sha256, r["target"], code)
    else:  # single
        code = resp.get("c") or ""
        out[misses[0]] = code
        cache.put(sha256, misses[0], code)
    return out


def assemble_report(binary: BinaryRef, result: REResult, overview: dict) -> Report:
    md = f"""# RE Analysis — {binary.filename or binary.program}

**Binary type:** {result.binary_type or "unknown"}
**Language / runtime:** {result.language_runtime or "unknown"}

## Purpose
{result.purpose or "_not determined_"}

## Key functions
{result.key_functions or "_none identified_"}

## Attack surface
{result.attack_surface or "_none identified_"}

## Overview
```
{overview.get("text", "")}
```
"""
    return Report(format="md", content=md)


# --- the ReAct analyzer -----------------------------------------------------
def _analysis_signature() -> Any:
    import dspy

    class BinaryAnalysisSignature(dspy.Signature):
        """Analyze a binary from its overview and decompiled key functions, using
        the Ghidra MCP tools to dig deeper as needed. Produce a concise, evidence-
        based summary."""

        overview: str = dspy.InputField(desc="Program metadata, imports and strings")
        functions: str = dspy.InputField(desc="Decompiled C of the key functions")
        binary_type: str = dspy.OutputField(
            desc="e.g. kernel_driver, cli_tool, library, service, gui_app"
        )
        purpose: str = dspy.OutputField(desc="One sentence: what does this binary do?")
        key_functions: str = dspy.OutputField(desc="3–5 functions worth knowing and why")
        attack_surface: str = dspy.OutputField(
            desc="Entry points and exposed/attacker-reachable surface"
        )
        language_runtime: str = dspy.OutputField(
            desc="Source language / runtime: C, C++, Go, Rust, .NET, …"
        )

    return BinaryAnalysisSignature


def _make_re_tools(client: GhidraMcpClient, program: str) -> list:
    def decompile(function: str) -> str:
        """Decompile a function of the program to C."""
        return client.decompile_function(program, function).get("c", "(no code)")

    def list_functions(name_contains: str = "") -> str:
        """List functions, optionally filtered by a name substring."""
        fns = client.list_functions(program, name_contains=name_contains or None, limit=50).get(
            "functions", []
        )
        return ", ".join(f["name"] for f in fns) or "(none)"

    def xrefs_to(target: str) -> str:
        """Who references this function/symbol/address."""
        return str(client.xrefs_to(program, target))[:800]

    def list_imports() -> str:
        """List imported symbols of the program."""
        return ", ".join(_import_names(client, program)[:60]) or "(none)"

    return [decompile, list_functions, xrefs_to, list_imports]


def make_binary_analyzer(client: GhidraMcpClient, program: str, *, max_iters: int = 8) -> Any:
    import dspy

    return dspy.ReAct(
        _analysis_signature(), tools=_make_re_tools(client, program), max_iters=max_iters
    )


# --- the pipeline -----------------------------------------------------------
def run(
    binary: BinaryRef,
    client: GhidraMcpClient,
    *,
    analyzer: Any | None = None,
    cache: DecompileCache | None = None,
) -> Generator[ProgressEvent, None, tuple[REResult, Report]]:
    cache = cache or MemoryDecompileCache()
    seq = _Seq()

    yield ProgressEvent.step_start("overview", seq.next(), program=binary.program)
    overview = build_overview(client, binary.program)
    yield ProgressEvent.step_finish(
        "overview",
        seq.next(),
        imports=len(overview["imports"]),
        functions=overview["info"].get("function_count"),
    )

    yield ProgressEvent.step_start("decompile", seq.next())
    key_fns = pick_key_functions(client, binary.program)
    decs = decompile_key_functions(client, binary.program, binary.sha256, key_fns, cache)
    yield ProgressEvent.step_finish(
        "decompile", seq.next(), count=len(decs), functions=list(decs.keys())
    )

    yield ProgressEvent.step_start("analyze", seq.next())
    if analyzer is None:
        analyzer = make_binary_analyzer(client, binary.program)
    functions_blob = "\n\n".join(f"// {fn}\n{code}" for fn, code in decs.items())
    pred = react_with_retry(lambda: analyzer(overview=overview["text"], functions=functions_blob))
    result = REResult(
        binary_type=getattr(pred, "binary_type", None),
        purpose=getattr(pred, "purpose", None),
        key_functions=getattr(pred, "key_functions", None),
        attack_surface=getattr(pred, "attack_surface", None),
        language_runtime=getattr(pred, "language_runtime", None),
        tool_calls=len(decs),
        raw={"decompiled": list(decs.keys())},
    )
    yield ProgressEvent.step_finish("analyze", seq.next(), language_runtime=result.language_runtime)

    report = assemble_report(binary, result, overview)
    yield ProgressEvent(
        type=EventType.done,
        seq=seq.next(),
        step="done",
        data={"language_runtime": result.language_runtime},
    )
    return result, report
