"""VR names only the functions its triaged findings sit in.

VR decompiles every function in the binary — real binaries run to thousands — so
the scoping is the whole point of the design."""

from __future__ import annotations

from keystone_engine.mcp import GhidraMcpClient
from keystone_engine.pipelines import BinaryRef, vr_path
from keystone_engine.pipelines.vr_path import FUNCTION_NAMING_MAX


class FakeMcp:
    """Three real functions with addresses; only some will carry findings."""

    def call(self, tool, args):
        if tool == "list_functions":
            return {
                "functions": [
                    {
                        "name": f"fn_{i}",
                        "address": f"40{i:04x}",
                        "is_thunk": False,
                        "is_external": False,
                    }
                    for i in range(60)
                ]
            }
        if tool == "decompile_function":
            t = args["function"] if isinstance(args["function"], list) else [args["function"]]
            return {
                "results": [{"target": x, "c": f"void {x}(void) {{ memcpy(a,b,c); }}"} for x in t]
            }
        return {}


class TriageStub:
    def __call__(self, finding_message, code, rule):
        class P:
            classification = "true_positive"
            risk_level = "high"
            cwe_id = "CWE-120"
            reasoning = "r"

        return P()


class ReachStub:
    def __call__(self, finding_message, function_code, function_name):
        class P:
            reachable = "yes"
            entry_path = "e"
            confidence = "high"

        return P()


class NamingStub:
    def __init__(self):
        self.calls, self.seen = 0, []

    def __call__(self, functions):
        self.calls += 1
        n = functions.count("### ")
        self.seen.append(n)

        class P:
            names = "\n".join(f"{i} | named_{i} | purpose" for i in range(1, n + 1))

        return P()


def _semgrep_over(fn_names):
    def runner(_dir, _cfg):
        return {
            "results": [
                {
                    "check_id": "dangerous-copy",
                    "path": f"/d/{fn}.c",
                    "start": {"line": 1},
                    "extra": {"message": "m", "severity": "ERROR"},
                }
                for fn in fn_names
            ]
        }

    return runner


def _run(tmp_path, fn_names, naming_agent=None, **kw):
    gen = vr_path.run(
        BinaryRef(program="p", sha256="s", filename="f"),
        GhidraMcpClient(transport=FakeMcp()),
        base_dir=str(tmp_path),
        semgrep_runner=_semgrep_over(fn_names),
        triage_agent=TriageStub(),
        reachability_agent=ReachStub(),
        naming_agent=naming_agent or NamingStub(),
        **kw,
    )
    events = []
    try:
        while True:
            events.append(next(gen))
    except StopIteration as stop:
        return events, stop.value


def test_only_functions_with_findings_are_named(tmp_path):
    """Not all 60 in the binary — the three the analyst is triaging."""
    _events, (_f, _r, named) = _run(tmp_path, ["fn_1", "fn_2", "fn_3"])
    assert {n.original_name for n in named} == {"fn_1", "fn_2", "fn_3"}


def test_the_step_is_emitted_with_counts(tmp_path):
    events, _ = _run(tmp_path, ["fn_1", "fn_2"])
    finish = [e for e in events if e.step == "name_functions" and e.type.value == "step_finish"][0]
    assert finish.data == {"named": 2, "total": 2}


def test_a_function_with_several_findings_is_named_once(tmp_path):
    _events, (_f, _r, named) = _run(tmp_path, ["fn_1", "fn_1", "fn_1", "fn_2"])
    assert [n.original_name for n in named] == ["fn_1", "fn_2"]


def test_addresses_come_from_ghidra_not_the_file_name(tmp_path):
    _events, (_f, _r, named) = _run(tmp_path, ["fn_7"])
    assert named[0].address == "400007"


def test_no_findings_names_nothing(tmp_path):
    stub = NamingStub()
    _events, (_f, _r, named) = _run(tmp_path, [], naming_agent=stub)
    assert named == [] and stub.calls == 0


def test_the_cap_bounds_a_pathological_class(tmp_path):
    """A rule class matching hundreds of functions must not become hundreds of
    LLM calls."""
    stub = NamingStub()
    _events, (_f, _r, named) = _run(tmp_path, [f"fn_{i}" for i in range(60)], naming_agent=stub)
    assert len(named) == FUNCTION_NAMING_MAX
    assert sum(stub.seen) == FUNCTION_NAMING_MAX


def test_an_unknown_function_stem_is_skipped(tmp_path):
    """A finding whose file matches no function in the program has no address to
    key a name on."""
    _events, (_f, _r, named) = _run(tmp_path, ["fn_1", "not_a_function"])
    assert [n.original_name for n in named] == ["fn_1"]


def test_naming_failure_does_not_fail_the_vr_run(tmp_path):
    class Boom:
        def __call__(self, functions):
            raise RuntimeError("no LM")

    events, (findings, report, named) = _run(tmp_path, ["fn_1"], naming_agent=Boom())
    assert findings and report.content.startswith("# VR Analysis")
    assert named and named[0].suggested_name is None


def test_reserved_names_are_honoured(tmp_path):
    _events, (_f, _r, named) = _run(tmp_path, ["fn_1"], reserved_names={"named_1"})
    assert named[0].suggested_name == "named_1_2"
