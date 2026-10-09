"""VR reachability, call-graph half: prove a finding's function reachable from an
entry point with find_call_paths, before any model is asked. Fake client only —
no Ghidra, no LLM."""

from __future__ import annotations

from keystone_engine.mcp import McpError
from keystone_engine.results import VRFinding
from keystone_engine.signatures.call_paths import (
    STUB_EXPORTS,
    entry_points,
    function_index,
    prove_reachability,
)

PROGRAM = "prog"


def fn(name: str, address: str, **kw) -> dict:
    return {"name": name, "address": address, **kw}


class FakeClient:
    """Answers the three calls the step makes. `paths` maps (source, target)
    addresses to the server's path lists; `fail` maps a target address to the
    error message its query raises."""

    def __init__(self, functions, exports=(), paths=None, fail=None):
        self.functions = list(functions)
        self.exports = list(exports)
        self.paths = paths or {}
        self.fail = fail or {}
        self.queries: list[tuple[str, str]] = []

    def list_functions(self, program, **kw):
        return {"functions": self.functions}

    def list_exports(self, program, **kw):
        return {"symbols": self.exports}

    def find_call_paths(self, program, source, target, **kw):
        self.queries.append((source, target))
        if target in self.fail:
            raise McpError(self.fail[target])
        found = self.paths.get((source, target), [])
        return {"path_count": len(found), "truncated": False, "paths": found}


def finding(stem: str, classification: str = "true_positive") -> VRFinding:
    return VRFinding(rule="r", file=f"/tmp/dec/{stem}.c", classification=classification)


def chain(*names_and_addresses: tuple[str, str]) -> list[dict]:
    return [{"name": n, "address": a} for n, a in names_and_addresses]


EXECUTABLE = [
    fn("_start", "1000"),
    fn("main", "1100"),
    fn("handle", "1200"),
    fn("copy_field", "1300"),
    fn("helper", "1400"),
    fn("strcpy", "9000", is_external=True),
]


# --------------------------------------------------------------------- index
def test_the_index_maps_decompiled_file_stems_to_functions():
    client = FakeClient(
        [
            fn("Foo::bar", "2000"),  # C++ name: the decompiled file is Foo__bar.c
            fn("thunk_memcpy", "2100", is_thunk=True),
            fn("memcpy", "9100", is_external=True),
            fn("plain", "2200"),
        ]
    )
    index = function_index(client, PROGRAM)
    assert index["Foo__bar"].name == "Foo::bar" and index["Foo__bar"].address == "2000"
    assert "plain" in index
    # the decompile step skips thunks and externals, so no finding can sit in one
    assert "thunk_memcpy" not in index and "memcpy" not in index


# -------------------------------------------------------------- entry points
def test_an_executable_with_main_starts_at_main_only():
    # An unstripped executable "exports" every global function. Treating them
    # as entry points would prove any finding in one reachable from itself.
    client = FakeClient(
        EXECUTABLE,
        exports=[fn("_start", "1000"), fn("main", "1100"), fn("handle", "1200")],
    )
    names = [e.name for e in entry_points(client, PROGRAM, function_index(client, PROGRAM))]
    assert names == ["main"]


def test_without_main_the_program_entry_and_exported_functions_are_entries():
    functions = [fn("entry", "1000"), fn("_init", "1010"), fn("api_open", "1100")]
    functions += [fn(f"api_{i}", f"{1200 + i}") for i in range(12)]
    exports = [
        fn("__DT_INIT", "1010"),  # dynamic-section tag at _init's address
        fn("_init", "1010"),
        fn("api_open", "1100"),
        fn("_edata", "8000"),  # data, not a function
        fn("entry", "1000"),
    ] + [fn(f"api_{i}", f"{1200 + i}") for i in range(12)]
    client = FakeClient(functions, exports=exports)
    entries = entry_points(client, PROGRAM, function_index(client, PROGRAM))
    names = [e.name for e in entries]
    assert names[0] == "entry"  # the program entry first
    assert "api_open" in names
    assert not {"_init", "__DT_INIT", "_edata"} & set(names)
    assert len(entries) == 8  # capped
    assert len({e.address for e in entries}) == len(entries)  # no duplicates


def test_runtime_stubs_are_never_entry_points():
    assert {"_init", "_fini", "frame_dummy", "__do_global_dtors_aux"} <= STUB_EXPORTS


# ------------------------------------------------------------------- proving
def test_a_reachable_function_gets_the_shortest_path_found():
    client = FakeClient(
        EXECUTABLE,
        paths={
            ("1100", "1300"): [
                chain(
                    ("main", "1100"), ("helper", "1400"), ("handle", "1200"), ("copy_field", "1300")
                ),
                chain(("main", "1100"), ("handle", "1200"), ("copy_field", "1300")),
            ]
        },
    )
    evidence = prove_reachability([finding("copy_field")], client, PROGRAM)
    path = evidence.paths["copy_field"]
    assert [s.name for s in path.steps] == ["main", "handle", "copy_field"]
    assert path.describe() == "main@1100 → handle@1200 → copy_field@1300"
    assert path.to_list()[0] == {"name": "main", "address": "1100"}
    assert evidence.queries == 1 and client.queries == [("1100", "1300")]


def test_addresses_are_sent_not_names():
    client = FakeClient([fn("main", "1100"), fn("Foo::bar", "2000")])
    prove_reachability([finding("Foo__bar")], client, PROGRAM)
    assert client.queries == [("1100", "2000")]


def test_one_query_per_function_however_many_findings_it_has():
    client = FakeClient(EXECUTABLE)
    prove_reachability(
        [finding("copy_field"), finding("copy_field"), finding("helper")], client, PROGRAM
    )
    assert [t for _, t in client.queries] == ["1300", "1400"]


def test_the_search_stops_at_the_first_entry_point_with_a_path():
    functions = [fn("entry", "1000"), fn("api_a", "1100"), fn("api_b", "1200"), fn("sink", "1300")]
    exports = [fn("entry", "1000"), fn("api_a", "1100"), fn("api_b", "1200")]
    client = FakeClient(
        functions,
        exports=exports,
        paths={("1100", "1300"): [chain(("api_a", "1100"), ("sink", "1300"))]},
    )
    evidence = prove_reachability([finding("sink")], client, PROGRAM)
    assert evidence.paths["sink"].steps[0].name == "api_a"
    assert client.queries == [("1000", "1300"), ("1100", "1300")]  # api_b never asked


def test_a_finding_in_an_entry_point_is_reachable_without_a_query():
    client = FakeClient(EXECUTABLE)
    evidence = prove_reachability([finding("main")], client, PROGRAM)
    assert [s.name for s in evidence.paths["main"].steps] == ["main"]
    assert client.queries == []


def test_no_path_is_unproven_never_unreachable():
    # e.g. a handler reached only through a function pointer: no call edge
    client = FakeClient(EXECUTABLE)
    evidence = prove_reachability([finding("helper")], client, PROGRAM)
    assert "helper" not in evidence.paths
    assert evidence.unproven == ["helper"]


def test_clean_findings_are_not_queried():
    client = FakeClient(EXECUTABLE)
    evidence = prove_reachability(
        [finding("copy_field", "false_positive"), finding("helper", "needs_review")],
        client,
        PROGRAM,
    )
    assert [t for _, t in client.queries] == ["1400"]
    assert evidence.unproven == ["helper"]


def test_a_stem_matching_no_function_is_reported_not_queried():
    client = FakeClient(EXECUTABLE)
    evidence = prove_reachability([finding("gone")], client, PROGRAM)
    assert evidence.unresolved == ["gone"] and client.queries == []


def test_one_failing_query_does_not_stop_the_others():
    client = FakeClient(
        EXECUTABLE,
        paths={("1100", "1400"): [chain(("main", "1100"), ("helper", "1400"))]},
        fail={"1300": "find_call_paths -> HTTP 404: not_found: function not found: 1300"},
    )
    evidence = prove_reachability([finding("copy_field"), finding("helper")], client, PROGRAM)
    assert evidence.failed == ["copy_field"]
    assert "helper" in evidence.paths and evidence.disabled is None


def test_the_query_budget_is_honoured_and_what_it_skipped_is_named():
    client = FakeClient(EXECUTABLE)
    evidence = prove_reachability(
        [finding("handle"), finding("copy_field"), finding("helper")],
        client,
        PROGRAM,
        max_queries=2,
    )
    assert evidence.queries == 2 and len(client.queries) == 2
    assert evidence.unproven == ["handle", "copy_field"]
    assert evidence.over_budget == ["helper"]


def test_a_server_without_the_tool_switches_the_step_off():
    client = FakeClient(
        EXECUTABLE,
        fail={
            "1300": "find_call_paths -> HTTP 404: not_found: no tool named 'find_call_paths'",
        },
    )
    evidence = prove_reachability([finding("copy_field"), finding("helper")], client, PROGRAM)
    assert evidence.disabled and "find_call_paths" in evidence.disabled
    assert len(client.queries) == 1  # stopped at the first answer, helper never asked
    assert evidence.paths == {}


def test_a_program_with_no_usable_entry_point_switches_the_step_off():
    client = FakeClient([fn("sub_1000", "1000"), fn("sink", "1300")], exports=[])
    evidence = prove_reachability([finding("sink")], client, PROGRAM)
    assert evidence.disabled == "no entry points" and client.queries == []


def test_a_failing_function_list_switches_the_step_off_instead_of_failing():
    class Broken(FakeClient):
        def list_functions(self, program, **kw):
            raise McpError("list_functions -> HTTP 500: error: boom")

    evidence = prove_reachability([finding("sink")], Broken(EXECUTABLE), PROGRAM)
    assert evidence.disabled and "boom" in evidence.disabled


def test_nothing_suspicious_means_no_calls_at_all():
    client = FakeClient(EXECUTABLE)

    def explode(*a, **k):
        raise AssertionError("the step must not touch Ghidra")

    client.list_functions = explode  # type: ignore[method-assign]
    evidence = prove_reachability([finding("main", "false_positive")], client, PROGRAM)
    assert evidence.paths == {} and evidence.queries == 0


def test_every_suspicious_function_lands_in_exactly_one_outcome():
    client = FakeClient(
        EXECUTABLE,
        paths={("1100", "1200"): [chain(("main", "1100"), ("handle", "1200"))]},
        fail={"1300": "find_call_paths -> HTTP 500: error: boom"},
    )
    stems = ["main", "handle", "copy_field", "helper", "gone", "_start"]
    evidence = prove_reachability([finding(s) for s in stems], client, PROGRAM, max_queries=3)
    buckets = [
        list(evidence.paths),
        evidence.unproven,
        evidence.failed,
        evidence.unresolved,
        evidence.over_budget,
    ]
    placed = [s for bucket in buckets for s in bucket]
    assert sorted(placed) == sorted(stems)  # each once, none lost
    assert evidence.over_budget == ["_start"]  # the budget ran out after helper
    assert evidence.unresolved == ["gone"]  # still classified after the budget ran out
