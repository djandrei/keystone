"""Stage 2.3: layered platform classification (filename + import heuristic)."""
from __future__ import annotations

from keystone_engine.mcp import GhidraMcpClient
from keystone_engine.signatures import (
    classify_platform,
    classify_platform_from_imports,
    classify_platform_simple,
)


class FakeTransport:
    def __init__(self, imports):
        self._imports = imports

    def call(self, tool, args):
        if tool == "list_symbols" and args.get("kind") == "import":
            return {"symbols": [{"name": n} for n in self._imports]}
        return {}


def test_simple_by_extension():
    assert classify_platform_simple("driver.sys")["platform"] == "windows"
    assert classify_platform_simple("evil.dll")["platform"] == "windows"
    assert classify_platform_simple("thing.dylib")["platform"] == "apple"
    assert classify_platform_simple("module.ko")["platform"] == "linux"
    assert classify_platform_simple("app.apk")["platform"] == "android"
    assert classify_platform_simple("ls")["platform"] == "unknown"


def test_from_imports_scores_each_platform():
    assert classify_platform_from_imports(["CreateFileA", "RegOpenKeyExW", "kernel32.dll"])["platform"] == "windows"
    assert classify_platform_from_imports(["__libc_start_main", "pthread_create"])["platform"] == "linux"
    assert classify_platform_from_imports(["_objc_msgSend", "CFStringCreateWithCString"])["platform"] == "apple"
    assert classify_platform_from_imports(["__android_log_print", "JNI_OnLoad"])["platform"] == "android"
    assert classify_platform_from_imports(["some_generic_func"])["platform"] == "unknown"


def test_classify_prefers_filename_then_imports():
    # filename wins outright
    c = GhidraMcpClient(transport=FakeTransport(["__libc_start_main"]))
    assert classify_platform("prog", c, filename="thing.dll")["platform"] == "windows"

    # unknown filename -> falls through to the import heuristic
    c2 = GhidraMcpClient(transport=FakeTransport(["CreateFileW", "VirtualAlloc"]))
    assert classify_platform("prog", c2, filename="stripped.gzf")["platform"] == "windows"


def test_classify_falls_back_to_injected_classifier():
    # imports inconclusive -> use the (LLM/ReAct) classifier stub
    c = GhidraMcpClient(transport=FakeTransport(["mystery_fn"]))

    class Stub:
        platform = "linux"
        reasoning = "ReAct decided"

    result = classify_platform("prog", c, filename="unknown", classifier=lambda program: Stub())
    assert result == {"platform": "linux", "reasoning": "ReAct decided"}
