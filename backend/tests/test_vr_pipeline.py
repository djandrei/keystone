"""Stage 3.3: the VR pipeline — event sequence, rule pick, findings shape."""

from __future__ import annotations

from keystone_engine.events import EventType
from keystone_engine.mcp import GhidraMcpClient
from keystone_engine.pipelines import BinaryRef, vr_path


class FakeMcp:
    def call(self, tool, args):
        if tool == "list_functions":
            return {
                "functions": [{"name": "parse_header", "is_thunk": False, "is_external": False}]
            }
        if tool == "decompile_function":
            targets = args["function"] if isinstance(args["function"], list) else [args["function"]]
            return {"results": [{"target": t, "c": f"void {t}(){{}}"} for t in targets]}
        return {}


SEMGREP = {
    "results": [
        {
            "check_id": "rules.c.integer-overflow",
            "path": "/x/parse_header.c",
            "start": {"line": 3},
            "extra": {"message": "overflow into memcpy"},
        },
        {
            "check_id": "rules.c.integer-overflow",
            "path": "/x/other.c",
            "start": {"line": 5},
            "extra": {"message": "unchecked len"},
        },
        {
            "check_id": "rules.c.format-string",
            "path": "/x/log.c",
            "start": {"line": 1},
            "extra": {"message": "fmt"},
        },
    ]
}


class TriageStub:
    def __call__(self, finding_message, code, rule):
        class P:
            classification = "true_positive"
            risk_level = "high"
            cwe_id = "CWE-190"
            reasoning = "unchecked length"

        return P()


class ReachStub:
    def __call__(self, finding_message, function_code, function_name):
        class P:
            reachable = "yes"
            entry_path = "ioctl -> parse_header"
            confidence = "high"

        return P()


def _drive(gen):
    events = []
    try:
        while True:
            events.append(next(gen))
    except StopIteration as stop:
        return events, stop.value


def test_vr_pipeline_auto_picks_and_annotates(tmp_path):
    client = GhidraMcpClient(transport=FakeMcp())
    binary = BinaryRef(program="drv", sha256="h1", filename="ksthunk.sys")
    gen = vr_path.run(
        binary,
        client,
        base_dir=str(tmp_path),
        semgrep_runner=lambda d, c: SEMGREP,
        triage_agent=TriageStub(),
        reachability_agent=ReachStub(),
    )
    events, (findings, report, _named) = _drive(gen)

    steps = [(e.type, e.step) for e in events]
    for step in ("decompile", "semgrep", "rule_pick", "triage", "reachability"):
        assert (EventType.step_start, step) in steps
    assert events[-1].type is EventType.done

    # auto-picked the largest class (integer-overflow: 2 vs format-string: 1)
    pick = next(e for e in events if e.step == "rule_pick" and e.type is EventType.step_finish)
    assert pick.data["rule"] == "integer-overflow" and pick.data["selected"] == 2

    assert len(findings) == 2
    assert all(f.cwe_id == "CWE-190" and f.reachable == "yes" for f in findings)
    assert "VR Analysis" in report.content and "CWE-190" in report.content


def test_vr_pipeline_honors_explicit_rule_and_budget(tmp_path):
    client = GhidraMcpClient(transport=FakeMcp())
    binary = BinaryRef(program="drv", sha256="h2", filename="d.sys")
    gen = vr_path.run(
        binary,
        client,
        base_dir=str(tmp_path),
        rule="format-string",
        budget=5,
        semgrep_runner=lambda d, c: SEMGREP,
        triage_agent=TriageStub(),
        reachability_agent=ReachStub(),
    )
    _events, (findings, _report, _n) = _drive(gen)
    assert len(findings) == 1 and findings[0].rule.endswith("format-string")


def test_vr_pipeline_interactive_rule_resolver(tmp_path):
    from keystone_engine.events import EventType as ET

    client = GhidraMcpClient(transport=FakeMcp())
    binary = BinaryRef(program="drv", sha256="h3", filename="d.sys")
    seen: dict = {}

    def resolver(counts):
        seen["counts"] = counts
        return "format-string"  # user picks the smaller class

    gen = vr_path.run(
        binary,
        client,
        base_dir=str(tmp_path),
        rule_resolver=resolver,
        semgrep_runner=lambda d, c: SEMGREP,
        triage_agent=TriageStub(),
        reachability_agent=ReachStub(),
    )
    events, (findings, _r, _n) = _drive(gen)
    assert any(e.type is ET.needs_input and e.step == "rule_pick" for e in events)
    assert seen["counts"] == {"integer-overflow": 2, "format-string": 1}
    assert len(findings) == 1 and findings[0].rule.endswith("format-string")


# --------------------------------------------------------------------------- #
# Who picks the rule class, and what happens when nobody does.
# --------------------------------------------------------------------------- #
def _severity_runner(_dir, _cfg):
    """A scan where the noisiest class is the least severe — the ksthunk shape."""

    def hit(check_id, sev, line):
        return {
            "check_id": check_id,
            "path": "/d/f.c",
            "start": {"line": line},
            "extra": {"message": "m", "severity": sev},
        }

    return {
        "results": [hit("typos", "INFO", i) for i in range(20)]
        + [hit("integer-truncation", "WARNING", i) for i in range(3)]
    }


def _run(tmp_path, **kw):
    client = GhidraMcpClient(transport=FakeMcp())
    gen = vr_path.run(
        BinaryRef(program="p", sha256="s", filename="f"),
        client,
        base_dir=str(tmp_path),
        semgrep_runner=_severity_runner,
        triage_agent=TriageStub(),
        reachability_agent=ReachStub(),
        **kw,
    )
    return _drive(gen)


def test_auto_pick_prefers_severity_over_volume(tmp_path):
    """Unattended, the run must not spend its whole budget on 20 INFO typos."""
    events, (findings, _report, _n) = _run(tmp_path)
    picked = next(e for e in events if e.step == "rule_pick" and e.type.value == "step_finish")
    assert picked.data["rule"] == "integer-truncation"
    assert picked.data["selected"] == 3
    assert len(findings) == 3


def test_a_resolver_timeout_lands_on_the_same_ranked_default(tmp_path):
    """The resolver returning None (nobody answered) must not fall back to the
    largest class — the pipeline owns the default so both paths agree."""
    events, (findings, _report, _n) = _run(tmp_path, rule_resolver=lambda counts: None)
    picked = next(e for e in events if e.step == "rule_pick" and e.type.value == "step_finish")
    assert picked.data["rule"] == "integer-truncation"


def test_the_needs_input_event_carries_the_ranked_summary(tmp_path):
    """The human picker is shown the same ordering the auto-pick would use."""
    events, _ = _run(tmp_path, rule_resolver=lambda counts: "typos")
    ask = next(e for e in events if e.type.value == "needs_input")
    summary = ask.data["class_summary"]
    assert [r["rule"] for r in summary] == ["integer-truncation", "typos"]
    assert summary[0]["severity"] == "WARNING"
    assert ask.data["auto"] == "integer-truncation"
    # counts are still there for older clients
    assert ask.data["classes"] == {"typos": 20, "integer-truncation": 3}


def test_an_explicit_choice_still_wins(tmp_path):
    """Ranking is only the default — the analyst overrides it."""
    _events, (findings, _report, _n) = _run(tmp_path, rule_resolver=lambda counts: "typos")
    assert len(findings) == 20
