"""Platform classification: WHERE does this binary run?

Three layers, cheapest first:
1. `classify_platform_simple` — filename extension (no LLM, no Ghidra).
2. `classify_platform_from_imports` — deterministic scoring over the import table
   (one MCP call). Imports are the fastest true signal of a binary's OS.
3. `make_platform_classifier` — a DSPy ReAct agent over MCP tools, for the hard
   `.gzf`/stripped/ambiguous cases. Exercised in integration.
"""
from __future__ import annotations

from typing import Any

from keystone_engine.mcp import GhidraMcpClient

PLATFORMS = ("windows", "linux", "apple", "android", "unknown")

# Substring indicators matched case-insensitively against import/library names.
_INDICATORS: dict[str, tuple[str, ...]] = {
    "windows": (
        "kernel32", "ntdll", "user32", "advapi32", "ws2_32", "gdi32", "ole32",
        "shell32", "createfile", "regopenkey", "virtualalloc", "loadlibrary",
        "getprocaddress", "winmain", "wincrt", "heapalloc", "createremotethread",
    ),
    "linux": (
        "__libc_start_main", "libc.so", "glibc", "gnu/libc", "dlopen", "pthread_",
        "__cxa_", "__gmon_start__", "libpthread", "libdl", "libstdc++",
    ),
    "apple": (
        "_objc_", "objc_msgsend", "corefoundation", "__cfstring", "_nslog",
        "dyld", "libsystem", "_dispatch_", "cfstringcreate", "libobjc",
    ),
    "android": ("libandroid", "__android_log", "jni_", "art::", "libbinder", "dalvik"),
}


def classify_platform_simple(binary_name: str) -> dict:
    """Filename-only fast path (no LLM required): a fixed extension -> platform
    mapping."""
    n = binary_name.lower()
    if n.endswith((".sys", ".dll", ".exe")):
        return {"platform": "windows", "reasoning": "File extension indicates a Windows binary"}
    if n.endswith((".kext", ".dylib")):
        return {"platform": "apple", "reasoning": "File extension (.kext/.dylib) indicates a macOS binary"}
    if n.endswith((".ko", ".so")):
        return {"platform": "linux", "reasoning": "File extension (.ko/.so) indicates a Linux binary"}
    if n.endswith((".apk", ".dex")):
        return {"platform": "android", "reasoning": "File extension (.apk/.dex) indicates an Android artifact"}
    return {"platform": "unknown", "reasoning": "Could not classify from filename; inspect imports"}


def classify_platform_from_imports(names: list[str]) -> dict:
    """Score import/library names against per-platform indicators; the top scorer
    wins. Returns platform 'unknown' with an empty score when nothing matches."""
    scores = {p: 0 for p in _INDICATORS}
    hits: dict[str, list[str]] = {p: [] for p in _INDICATORS}
    for raw in names:
        low = raw.lower()
        for platform, indicators in _INDICATORS.items():
            for ind in indicators:
                if ind in low:
                    scores[platform] += 1
                    hits[platform].append(raw)
                    break
    best = max(scores, key=lambda p: scores[p])
    if scores[best] == 0:
        return {"platform": "unknown", "reasoning": "No platform-specific imports found", "scores": scores}
    evidence = ", ".join(sorted(set(hits[best]))[:5])
    return {
        "platform": best,
        "reasoning": f"Imports characteristic of {best}: {evidence}",
        "scores": scores,
    }


def _import_names(client: GhidraMcpClient, program: str) -> list[str]:
    data = client.list_imports(program)
    rows = data.get("symbols", data.get("imports", []))
    names: list[str] = []
    for r in rows:
        if isinstance(r, dict) and r.get("name"):
            names.append(r["name"])
        elif isinstance(r, str):
            names.append(r)
    return names


def classify_platform(
    program: str,
    client: GhidraMcpClient,
    *,
    filename: str | None = None,
    classifier: Any | None = None,
) -> dict:
    """Layered classification. Filename → import heuristic → (optional) ReAct LLM.
    `classifier` is any callable `f(program=...) -> obj.platform/.reasoning`
    (a DSPy ReAct module, or a test stub)."""
    if filename:
        simple = classify_platform_simple(filename)
        if simple["platform"] != "unknown":
            return simple

    heuristic = classify_platform_from_imports(_import_names(client, program))
    if heuristic["platform"] != "unknown":
        return {"platform": heuristic["platform"], "reasoning": heuristic["reasoning"]}

    if classifier is not None:
        pred = classifier(program=program)
        return {"platform": getattr(pred, "platform", "unknown"), "reasoning": getattr(pred, "reasoning", "")}

    return {"platform": "unknown", "reasoning": "Inconclusive from filename and imports"}


# --- DSPy ReAct path (used by the pipeline / integration) -------------------
def _platform_signature() -> Any:
    import dspy

    class McpPlatformSignature(dspy.Signature):
        """Classify the target platform of an analyzed program using Ghidra MCP
        tools. Start with the import table; imports are the strongest signal of a
        binary's operating system. Use program metadata only if imports are
        ambiguous."""

        program: str = dspy.InputField(desc="Program name in the Ghidra project")
        platform: str = dspy.OutputField(
            desc="One of: windows, linux, apple, android, unknown. Use 'unknown' only if evidence is insufficient."
        )
        reasoning: str = dspy.OutputField(desc="Concise explanation citing specific imports/metadata")

    return McpPlatformSignature


def make_platform_classifier(client: GhidraMcpClient, *, max_iters: int = 5) -> Any:
    """A DSPy ReAct classifier whose tools are the MCP import/export/metadata calls."""
    import dspy

    def list_imports(program: str) -> str:
        """List the imported symbols of the program (the strongest OS signal)."""
        return ", ".join(_import_names(client, program)[:60]) or "(none)"

    def list_exports(program: str) -> str:
        """List the exported symbols of the program."""
        data = client.list_exports(program)
        rows = data.get("symbols", data.get("exports", []))
        names = [r["name"] if isinstance(r, dict) else r for r in rows if r]
        return ", ".join(names[:60]) or "(none)"

    def program_metadata(program: str) -> str:
        """Format, architecture, endianness and image base of the program."""
        info = client.program_info(program)
        keys = ("format", "arch", "architecture", "language_id", "endian", "image_base")
        return ", ".join(f"{k}={info[k]}" for k in keys if k in info) or str(info)[:300]

    return dspy.ReAct(
        _platform_signature(), tools=[list_imports, list_exports, program_metadata], max_iters=max_iters
    )
