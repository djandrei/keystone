"""VR reachability from the call graph: before any model is asked, look for a
real call chain from an entry point to each suspicious finding's function.

ghidra-headless-mcp's find_call_paths walks the calls Ghidra resolved, so a
chain it returns is proof that the function can be called from that entry
point. The converse does not hold: a function reached only through a pointer
(a callback, a vtable, a driver dispatch table) has no call edge, so finding no
chain means "not proven", never "unreachable". Those findings stay with the
reachability agent.

Deterministic and model-free. Every query is a JVM start on the server, so the
work is bounded: one query per (entry point, function), stopping at the first
entry point that yields a chain, under a per-analysis budget. No failure here
fails the analysis; the evidence says what was skipped and why.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from keystone_engine.mcp import GhidraMcpClient, McpError
from keystone_engine.results import VRFinding
from keystone_engine.semgrep import _safe
from keystone_engine.signatures.reachability import _SUSPICIOUS

log = logging.getLogger("keystone.vr")

# A program with one of these is an executable or driver; they are its only
# entry points. Its other global functions may be "exported" (an unstripped
# ELF exports every one), but an attacker cannot call them directly.
MAIN_LIKE = ("main", "wmain", "WinMain", "wWinMain", "DriverEntry")
# Without a main: the loader's entry, then the exported functions (a library).
PROGRAM_ENTRY = ("entry", "_start")
# Compiler and C-runtime scaffolding that is exported but is no attack surface.
STUB_EXPORTS = frozenset(
    {
        "_init",
        "_fini",
        "frame_dummy",
        "register_tm_clones",
        "deregister_tm_clones",
        "__do_global_dtors_aux",
        "_dl_relocate_static_pie",
    }
)
STUB_PREFIXES = ("__DT_", "__libc_csu_")

MAX_ENTRY_POINTS = 8
# Every query is a JVM start on the server: measured at about 6 s each on a
# small ELF, so 40 bounds the step at roughly four minutes per analysis.
MAX_QUERIES = 40


@dataclass(frozen=True)
class Function:
    name: str
    address: str


@dataclass(frozen=True)
class CallPath:
    """A call chain from an entry point (first) to the finding's function (last)."""

    steps: tuple[Function, ...]

    def describe(self) -> str:
        return " → ".join(f"{s.name}@{s.address}" for s in self.steps)

    def to_list(self) -> list[dict]:
        return [{"name": s.name, "address": s.address} for s in self.steps]


@dataclass
class CallPathEvidence:
    """What the step proved, keyed by decompiled-file stem, and what it could not
    try. Every suspicious function lands in exactly one of paths, unproven,
    failed, unresolved and over_budget — or the step is disabled."""

    paths: dict[str, CallPath] = field(default_factory=dict)
    unproven: list[str] = field(default_factory=list)  # asked; no chain found
    failed: list[str] = field(default_factory=list)  # a query raised
    unresolved: list[str] = field(default_factory=list)  # stem matches no function
    over_budget: list[str] = field(default_factory=list)  # never asked
    queries: int = 0
    disabled: str | None = None  # set when the step could not run at all


def function_index(client: GhidraMcpClient, program: str) -> dict[str, Function]:
    """Map each decompiled file's stem to its function. The decompile step writes
    `{_safe(name)}.c` for every function that is neither a thunk nor external, so
    this indexes the same set the same way; on a stem collision the first wins,
    as the file on disk does."""
    index: dict[str, Function] = {}
    for f in client.list_functions(program, limit=5000).get("functions", []):
        name, address = f.get("name"), f.get("address")
        if not name or not address or f.get("is_thunk") or f.get("is_external"):
            continue
        index.setdefault(_safe(name), Function(name, address))
    return index


def _is_stub(name: str) -> bool:
    return name in STUB_EXPORTS or name.startswith(STUB_PREFIXES)


def entry_points(
    client: GhidraMcpClient,
    program: str,
    index: dict[str, Function],
    *,
    limit: int = MAX_ENTRY_POINTS,
) -> list[Function]:
    """Where an attacker's input can start: the main-like functions when there
    are any, else the program entry and the exported functions, capped."""
    by_name = {f.name: f for f in index.values()}
    main_like = [by_name[n] for n in MAIN_LIKE if n in by_name]
    if main_like:
        return main_like[:limit]

    entries = [by_name[n] for n in PROGRAM_ENTRY if n in by_name]
    functions_at = {f.address: f for f in index.values()}
    for sym in client.list_exports(program, limit=500).get("symbols", []):
        name, address = sym.get("name"), sym.get("address")
        # exports include data symbols and runtime stubs; only real functions count
        if not name or address not in functions_at or _is_stub(name):
            continue
        entries.append(functions_at[address])

    unique: list[Function] = []
    for e in entries:
        if e.address not in {u.address for u in unique}:
            unique.append(e)
    return unique[:limit]


def _suspicious_stems(findings: list[VRFinding]) -> list[str]:
    stems: list[str] = []
    for f in findings:
        if f.classification in _SUSPICIOUS and f.file:
            stem = Path(f.file).stem
            if stem not in stems:
                stems.append(stem)
    return stems


def _shortest(paths: list[list[dict]]) -> CallPath:
    best = min(paths, key=len)
    return CallPath(tuple(Function(s["name"], s["address"]) for s in best))


def prove_reachability(
    findings: list[VRFinding],
    client: GhidraMcpClient,
    program: str,
    *,
    max_queries: int = MAX_QUERIES,
    max_entry_points: int = MAX_ENTRY_POINTS,
) -> CallPathEvidence:
    """Look for a call chain from an entry point to each suspicious finding's
    function. Never raises for a server-side problem: it records it instead."""
    evidence = CallPathEvidence()
    stems = _suspicious_stems(findings)
    if not stems:
        return evidence

    try:
        index = function_index(client, program)
        entries = entry_points(client, program, index, limit=max_entry_points)
    except McpError as exc:
        evidence.disabled = f"could not list functions or exports: {exc}"
        log.warning("call-path step skipped: %s", evidence.disabled)
        return evidence
    if not entries:
        evidence.disabled = "no entry points"
        return evidence
    entry_addresses = {e.address for e in entries}

    for stem in stems:
        target = index.get(stem)
        if target is None:
            evidence.unresolved.append(stem)
            continue
        if target.address in entry_addresses:
            evidence.paths[stem] = CallPath((target,))
            continue

        # one outcome per function: proven, unproven, failed or over_budget
        outcome = "unproven"
        for entry in entries:
            if evidence.queries >= max_queries:
                outcome = "over_budget"
                break
            evidence.queries += 1
            try:
                result = client.find_call_paths(program, entry.address, target.address)
            except McpError as exc:
                if "no tool named" in str(exc):
                    # an older server: every query would fail the same way. Paths
                    # proven without a query (entry points) still stand.
                    evidence.disabled = f"the Ghidra server has no find_call_paths ({exc})"
                    log.warning("call-path step skipped: %s", evidence.disabled)
                    return evidence
                log.warning("find_call_paths for %s failed: %s", target.name, exc)
                outcome = "failed"
                break
            if result.get("paths"):
                evidence.paths[stem] = _shortest(result["paths"])
                outcome = "proven"
                break
        if outcome == "unproven":
            evidence.unproven.append(stem)
        elif outcome == "failed":
            evidence.failed.append(stem)
        elif outcome == "over_budget":
            evidence.over_budget.append(stem)
    return evidence
