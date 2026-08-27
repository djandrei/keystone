"""Stage 3.0: decompile-to-disk caching + Semgrep parse/group (fake runner)."""

from __future__ import annotations

from keystone_engine.mcp import GhidraMcpClient
from keystone_engine.semgrep import (
    decompile_program_to_dir,
    group_by_rule_class,
    parse_semgrep,
    rule_class,
    run_semgrep,
)


class FakeMcp:
    def __init__(self):
        self.decompile_calls = 0

    def call(self, tool, args):
        if tool == "list_functions":
            return {
                "functions": [
                    {"name": "main", "is_thunk": False, "is_external": False},
                    {"name": "parse_header", "is_thunk": False, "is_external": False},
                    {"name": "memcpy", "is_thunk": True, "is_external": True},
                ]
            }
        if tool == "decompile_function":
            self.decompile_calls += 1
            targets = args["function"] if isinstance(args["function"], list) else [args["function"]]
            return {
                "results": [
                    {
                        "target": t,
                        "c": f"void {t}(){{ int n = read(); char b[8]; memcpy(b,src,n); }}",
                    }
                    for t in targets
                ]
            }
        return {}


SEMGREP_JSON = {
    "results": [
        {
            "check_id": "rules.c.security.integer-overflow",
            "path": "/d/parse_header.c",
            "start": {"line": 3},
            "extra": {"message": "possible integer overflow into memcpy"},
        },
        {
            "check_id": "rules.c.security.integer-overflow",
            "path": "/d/main.c",
            "start": {"line": 1},
            "extra": {"message": "unchecked length"},
        },
    ]
}


def test_decompile_to_dir_writes_and_caches(tmp_path):
    mcp = FakeMcp()
    client = GhidraMcpClient(transport=mcp)
    d1 = decompile_program_to_dir(client, "drv", "abc", tmp_path)
    files = sorted(p.name for p in d1.glob("*.c"))
    assert files == ["main.c", "parse_header.c"]  # thunks/externals skipped
    assert mcp.decompile_calls == 1  # one batched call

    # second call: cache marker short-circuits, no new decompile
    decompile_program_to_dir(client, "drv", "abc", tmp_path)
    assert mcp.decompile_calls == 1


def test_parse_and_group():
    findings = parse_semgrep(SEMGREP_JSON)
    assert len(findings) == 2
    assert findings[0].rule.endswith("integer-overflow") and findings[0].line == 3
    groups = group_by_rule_class(findings)
    assert set(groups) == {"integer-overflow"}
    assert len(groups["integer-overflow"]) == 2


def test_run_semgrep_with_injected_runner(tmp_path):
    findings = run_semgrep(tmp_path, "p/ci", runner=lambda d, c: SEMGREP_JSON)
    assert [f.line for f in findings] == [3, 1]


def test_rule_class():
    assert rule_class("rules.c.security.integer-overflow") == "integer-overflow"
    assert rule_class("path/to/kernel-int-wraparound") == "kernel-int-wraparound"
    assert rule_class("bare") == "bare"
