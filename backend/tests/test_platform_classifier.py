"""Stage 2.3: layered platform classification (filename + import heuristic)."""

from __future__ import annotations

from keystone_engine.mcp import GhidraMcpClient
from keystone_engine.signatures import (
    classify_platform_from_imports,
    detect_platform,
    platform_from_filename,
)


class FakeTransport:
    def __init__(self, imports):
        self._imports = imports

    def call(self, tool, args):
        if tool == "list_symbols" and args.get("kind") == "import":
            return {"symbols": [{"name": n} for n in self._imports]}
        return {}


def test_simple_by_extension():
    assert platform_from_filename("driver.sys")["platform"] == "windows"
    assert platform_from_filename("evil.dll")["platform"] == "windows"
    assert platform_from_filename("thing.dylib")["platform"] == "apple"
    assert platform_from_filename("module.ko")["platform"] == "linux"
    assert platform_from_filename("app.apk")["platform"] == "android"
    assert platform_from_filename("ls")["platform"] == "unknown"


def test_from_imports_scores_each_platform():
    assert (
        classify_platform_from_imports(["CreateFileA", "RegOpenKeyExW", "kernel32.dll"])["platform"]
        == "windows"
    )
    assert (
        classify_platform_from_imports(["__libc_start_main", "pthread_create"])["platform"]
        == "linux"
    )
    assert (
        classify_platform_from_imports(["_objc_msgSend", "CFStringCreateWithCString"])["platform"]
        == "apple"
    )
    assert (
        classify_platform_from_imports(["__android_log_print", "JNI_OnLoad"])["platform"]
        == "android"
    )
    assert classify_platform_from_imports(["some_generic_func"])["platform"] == "unknown"


def test_classify_prefers_filename_then_imports():
    # filename wins outright
    c = GhidraMcpClient(transport=FakeTransport(["__libc_start_main"]))
    assert detect_platform("prog", c, filename="thing.dll")["platform"] == "windows"

    # unknown filename -> falls through to the import heuristic
    c2 = GhidraMcpClient(transport=FakeTransport(["CreateFileW", "VirtualAlloc"]))
    assert detect_platform("prog", c2, filename="stripped.gzf")["platform"] == "windows"


def test_classify_falls_back_to_injected_classifier():
    # imports inconclusive -> use the (LLM/ReAct) classifier stub
    c = GhidraMcpClient(transport=FakeTransport(["mystery_fn"]))

    class Stub:
        platform = "linux"
        reasoning = "ReAct decided"

    result = detect_platform("prog", c, filename="unknown", classifier=lambda program: Stub())
    assert result == {"platform": "linux", "reasoning": "ReAct decided"}


def test_every_decisive_extension_and_case():
    expected = {
        "setup.EXE": "windows",
        "libfoo.so": "linux",
        "Driver.KEXT": "apple",
        "classes.dex": "android",
        "archive.tar.gz": "unknown",
    }
    for name, platform in expected.items():
        assert platform_from_filename(name)["platform"] == platform, name
