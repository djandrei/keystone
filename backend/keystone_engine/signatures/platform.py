"""Platform classification: WHERE does this binary run?

`detect_platform` tries three answers in order of cost and stops at the first
that is sure:
1. `platform_from_filename` — some extensions are only ever one platform's.
2. `classify_platform_from_imports` — score the import table against known
   per-OS libraries and symbols (one MCP call). Imports are the most reliable
   cheap signal.
3. An agent from `build_platform_agent` — a DSPy ReAct loop over Ghidra queries,
   for stripped, packed or `.gzf` inputs where the first two come back unknown.
"""

from __future__ import annotations

from typing import Any

from keystone_engine.mcp import GhidraMcpClient

PLATFORMS = ("windows", "linux", "apple", "android", "unknown")

# Substring indicators matched case-insensitively against import/library names.
_INDICATORS: dict[str, tuple[str, ...]] = {
    "windows": (
        "kernel32",
        "ntdll",
        "user32",
        "advapi32",
        "ws2_32",
        "gdi32",
        "ole32",
        "shell32",
        "createfile",
        "regopenkey",
        "virtualalloc",
        "loadlibrary",
        "getprocaddress",
        "winmain",
        "wincrt",
        "heapalloc",
        "createremotethread",
    ),
    "linux": (
        "__libc_start_main",
        "libc.so",
        "glibc",
        "gnu/libc",
        "dlopen",
        "pthread_",
        "__cxa_",
        "__gmon_start__",
        "libpthread",
        "libdl",
        "libstdc++",
    ),
    "apple": (
        "_objc_",
        "objc_msgsend",
        "corefoundation",
        "__cfstring",
        "_nslog",
        "dyld",
        "libsystem",
        "_dispatch_",
        "cfstringcreate",
        "libobjc",
    ),
    "android": ("libandroid", "__android_log", "jni_", "art::", "libbinder", "dalvik"),
}


# Extensions that settle the platform on their own. Anything else (including no
# extension, the usual case for ELF executables) falls through to the imports.
_DECISIVE_EXTENSIONS: dict[str, str] = {
    ".exe": "windows",
    ".dll": "windows",
    ".sys": "windows",
    ".dylib": "apple",
    ".kext": "apple",
    ".so": "linux",
    ".ko": "linux",
    ".apk": "android",
    ".dex": "android",
}


def platform_from_filename(name: str) -> dict:
    """Answer from the extension alone when it is decisive: no Ghidra call, no
    model. Returns platform 'unknown' when the name does not settle it."""
    _stem, dot, ext = name.lower().rpartition(".")
    suffix = dot + ext if dot else ""
    platform = _DECISIVE_EXTENSIONS.get(suffix)
    if platform is None:
        return {"platform": "unknown", "reasoning": "The file name does not settle it."}
    return {"platform": platform, "reasoning": f"Only {platform} uses {suffix} files."}


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
        return {
            "platform": "unknown",
            "reasoning": "No platform-specific imports found",
            "scores": scores,
        }
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


def detect_platform(
    program: str,
    client: GhidraMcpClient,
    *,
    filename: str | None = None,
    classifier: Any | None = None,
) -> dict:
    """The file name, then the imports, then (if given) `classifier`: any callable
    `f(program=...)` returning an object with `.platform` and `.reasoning`, such
    as an agent from `build_platform_agent` or a test stub."""
    if filename:
        by_name = platform_from_filename(filename)
        if by_name["platform"] != "unknown":
            return by_name

    heuristic = classify_platform_from_imports(_import_names(client, program))
    if heuristic["platform"] != "unknown":
        return {"platform": heuristic["platform"], "reasoning": heuristic["reasoning"]}

    if classifier is not None:
        pred = classifier(program=program)
        return {
            "platform": getattr(pred, "platform", "unknown"),
            "reasoning": getattr(pred, "reasoning", ""),
        }

    return {"platform": "unknown", "reasoning": "Inconclusive from filename and imports"}


# --- the agent, for inputs the cheap paths cannot settle ---------------------
def _platform_signature() -> Any:
    import dspy

    class PlatformFromImports(dspy.Signature):
        """Work out which operating system a program in the Ghidra project was
        built for. The imported libraries and symbols usually decide it; turn to
        the exports and the program's format and architecture when they do not."""

        program: str = dspy.InputField(desc="The program's name in the Ghidra project")
        platform: str = dspy.OutputField(
            desc="windows, linux, apple or android; unknown when the tools give no clear answer"
        )
        reasoning: str = dspy.OutputField(
            desc="The imports or metadata that decided it, in a sentence or two"
        )

    return PlatformFromImports


def build_platform_agent(client: GhidraMcpClient, *, max_iters: int = 5) -> Any:
    """A DSPy ReAct agent that answers by querying Ghidra for the program's
    imports, exports and metadata."""
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
        _platform_signature(),
        tools=[list_imports, list_exports, program_metadata],
        max_iters=max_iters,
    )
