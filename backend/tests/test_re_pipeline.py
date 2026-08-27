"""Stage 2.4: the RE pipeline — event sequence, result shape, decompile cache."""

from __future__ import annotations

from keystone_engine.events import EventType
from keystone_engine.mcp import GhidraMcpClient
from keystone_engine.pipelines import BinaryRef, MemoryDecompileCache, re_path


class FakeMcp:
    """Answers every tool the RE pipeline calls, and counts decompile calls."""

    def __init__(self):
        self.decompile_calls = 0

    def call(self, tool, args):
        if tool == "get_program_info":
            return {
                "name": "ls",
                "executable_format": "ELF",
                "language_id": "x86:LE:64",
                "function_count": 3,
                "symbol_count": 10,
            }
        if tool == "list_symbols" and args["kind"] == "import":
            return {"symbols": [{"name": "__libc_start_main"}, {"name": "printf"}]}
        if tool == "list_symbols" and args["kind"] == "export":
            return {"symbols": [{"name": "main"}]}
        if tool == "list_strings":
            return {"strings": [{"value": "usage: ls"}]}
        if tool == "list_functions":
            return {
                "functions": [
                    {
                        "name": "main",
                        "address": "0x1000",
                        "size": 200,
                        "is_thunk": False,
                        "is_external": False,
                    },
                    {
                        "name": "helper",
                        "address": "0x1200",
                        "size": 80,
                        "is_thunk": False,
                        "is_external": False,
                    },
                    {
                        "name": "printf",
                        "address": "0x1400",
                        "size": 10,
                        "is_thunk": True,
                        "is_external": True,
                    },
                ]
            }
        if tool == "decompile_function":
            self.decompile_calls += 1
            fn = args["function"]
            targets = fn if isinstance(fn, list) else [fn]
            return {"results": [{"target": t, "c": f"int {t}() {{ return 0; }}"} for t in targets]}
        return {}


class FakeAnalyzer:
    def __call__(self, overview, functions):
        class Pred:
            binary_type = "cli_tool"
            purpose = "Lists directory contents."
            key_functions = "main, helper"
            attack_surface = "argv parsing"
            language_runtime = "C"

        assert "ls" in overview and "main" in functions  # got real inputs
        return Pred()


def _drive(gen):
    events = []
    try:
        while True:
            events.append(next(gen))
    except StopIteration as stop:
        return events, stop.value


def test_re_pipeline_events_and_result():
    client = GhidraMcpClient(transport=FakeMcp())
    binary = BinaryRef(program="ls", sha256="abc123", filename="ls")
    events, (result, report) = _drive(re_path.run(binary, client, analyzer=FakeAnalyzer()))

    steps = [(e.type, e.step) for e in events]
    assert (EventType.step_start, "overview") in steps
    assert (EventType.step_start, "decompile") in steps
    assert (EventType.step_start, "analyze") in steps
    assert events[-1].type is EventType.done
    # seq strictly increasing
    assert [e.seq for e in events] == sorted(e.seq for e in events)

    assert result.binary_type == "cli_tool"
    assert result.language_runtime == "C"  # the extra field is present
    assert result.tool_calls >= 1
    assert "RE Analysis" in report.content and "language_runtime" in events[-1].data


def test_decompile_cache_prevents_re_decompile():
    mcp = FakeMcp()
    client = GhidraMcpClient(transport=mcp)
    binary = BinaryRef(program="ls", sha256="abc123", filename="ls")
    cache = MemoryDecompileCache()

    _drive(re_path.run(binary, client, analyzer=FakeAnalyzer(), cache=cache))
    first = mcp.decompile_calls
    assert first >= 1

    # second run with the same cache: no new decompile calls
    _drive(re_path.run(binary, client, analyzer=FakeAnalyzer(), cache=cache))
    assert mcp.decompile_calls == first


def test_decompile_batches_misses_in_one_call():
    mcp = FakeMcp()
    client = GhidraMcpClient(transport=mcp)
    binary = BinaryRef(program="ls", sha256="z", filename="ls")
    _drive(re_path.run(binary, client, analyzer=FakeAnalyzer()))
    # all key functions decompiled in a single batched call
    assert mcp.decompile_calls == 1
