"""Stage 3.0: decompile-to-disk caching + Semgrep parse/group (fake runner)."""

from __future__ import annotations

from keystone_engine.mcp import GhidraMcpClient
from keystone_engine.results import VRFinding
from keystone_engine.semgrep import (
    class_severity,
    decompile_program_to_dir,
    group_by_rule_class,
    parse_semgrep,
    pick_rule_class,
    rank_rule_classes,
    rule_class,
    rule_class_summary,
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


# --------------------------------------------------------------------------- #
# Ranking rule classes for triage. Only one class is ever triaged, so which one
# wins by default decides what the analyst actually gets to see.
# --------------------------------------------------------------------------- #
def _f(sev):
    return VRFinding(rule="r", file="f.c", line=1, severity=sev)


# The real class counts from the 114-function decompiled ksthunk corpus.
KSTHUNK = {
    "bad-words": [_f("INFO")] * 46,
    "typos": [_f("INFO")] * 33,
    "interesting-api-calls": [_f("WARNING")] * 8,
    "integer-truncation": [_f("WARNING")] * 4,
    "missing-return": [_f("INFO")] * 1,
}


def test_severity_beats_volume():
    """The bug this fixes: ranking by count alone made `bad-words` (INFO, 46 hits)
    outrank `integer-truncation` (WARNING, and the actual CVE class)."""
    assert pick_rule_class(KSTHUNK) != "bad-words"
    ranked = rank_rule_classes(KSTHUNK)
    assert ranked.index("integer-truncation") < ranked.index("bad-words")
    assert ranked.index("integer-truncation") < ranked.index("typos")


def test_an_error_class_outranks_a_much_larger_warning_class():
    groups = {"noisy": [_f("WARNING")] * 100, "use-after-free": [_f("ERROR")] * 1}
    assert pick_rule_class(groups) == "use-after-free"


def test_volume_breaks_ties_within_a_severity():
    groups = {"a": [_f("ERROR")] * 2, "b": [_f("ERROR")] * 9}
    assert pick_rule_class(groups) == "b"


def test_ranking_is_deterministic_for_identical_classes():
    groups = {"b": [_f("ERROR")], "a": [_f("ERROR")]}
    assert rank_rule_classes(groups) == rank_rule_classes(groups) == ["b", "a"]


def test_a_class_takes_the_highest_severity_any_of_its_rules_declared():
    assert class_severity([_f("INFO"), _f("ERROR"), _f("WARNING")]) == 3
    assert class_severity([_f(None), _f("nonsense")]) == 0


def test_unknown_severity_sorts_last_but_is_still_pickable():
    groups = {"unknown": [_f(None)] * 50, "low": [_f("INFO")] * 1}
    assert pick_rule_class(groups) == "low"
    assert pick_rule_class({"unknown": [_f(None)]}) == "unknown"


def test_no_groups_picks_nothing():
    assert pick_rule_class({}) is None
    assert rank_rule_classes({}) == []


def test_summary_is_ranked_and_carries_the_severity_label():
    rows = rule_class_summary(KSTHUNK)
    assert [r["rule"] for r in rows] == rank_rule_classes(KSTHUNK)
    assert rows[0]["severity"] == "WARNING"
    assert {r["rule"]: r["count"] for r in rows}["bad-words"] == 46
    assert rule_class_summary({"x": [_f(None)]})[0]["severity"] is None


def test_parse_semgrep_captures_the_declared_severity():
    raw = {
        "results": [
            {
                "check_id": "ks1.use-after-free",
                "path": "a.c",
                "start": {"line": 1},
                "extra": {"message": "m", "severity": "ERROR"},
            }
        ]
    }
    assert parse_semgrep(raw)[0].severity == "ERROR"
