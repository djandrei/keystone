"""RE names the functions it decompiled, and persists them against the binary."""

from __future__ import annotations

from keystone_api import services
from keystone_api.models import (
    Analysis,
    AnalysisFunction,
    AnalysisMode,
    Binary,
    FunctionName,
    Team,
    User,
)
from keystone_api.persist import persist_function_names, persist_re_result
from keystone_engine.mcp import GhidraMcpClient
from keystone_engine.pipelines import BinaryRef, re_path
from keystone_engine.results import Report as EngineReport
from keystone_engine.results import REResult as EngineRE
from keystone_engine.signatures.naming import NamedFunction


class FakeMcp:
    """Two real functions with addresses, plus a thunk that must not be named."""

    def call(self, tool, args):
        if tool == "list_functions":
            return {
                "functions": [
                    {
                        "name": "parse_header",
                        "address": "401146",
                        "is_thunk": False,
                        "is_external": False,
                        "size": 90,
                    },
                    {
                        "name": "check_key",
                        "address": "401200",
                        "is_thunk": False,
                        "is_external": False,
                        "size": 60,
                    },
                ]
            }
        if tool == "decompile_function":
            t = args["function"] if isinstance(args["function"], list) else [args["function"]]
            return {"results": [{"target": x, "c": f"void {x}(void) {{}}"} for x in t]}
        if tool == "get_program_info":
            return {"name": "p", "executable_format": "ELF", "function_count": 2}
        if tool in ("list_symbols", "list_strings", "list_exports", "list_imports"):
            return {"symbols": [], "strings": []}
        return {}


class NamingStub:
    def __init__(self):
        self.calls = 0

    def __call__(self, functions):
        self.calls += 1
        n = functions.count("### ")

        class P:
            names = "\n".join(f"{i} | good_name_{i} | purpose {i}" for i in range(1, n + 1))

        return P()


class AnalyzerStub:
    def __call__(self, overview, functions):
        class P:
            binary_type = "ELF"
            purpose = "p"
            key_functions = "k"
            attack_surface = "a"
            language_runtime = "C"
            behavioral_facts = None

        return P()


def _drive(gen):
    events = []
    try:
        while True:
            events.append(next(gen))
    except StopIteration as stop:
        return events, stop.value


def _run(**kw):
    return _drive(
        re_path.run(
            BinaryRef(program="p", sha256="h", filename="x.elf"),
            GhidraMcpClient(transport=FakeMcp()),
            analyzer=AnalyzerStub(),
            **kw,
        )
    )


# --------------------------------------------------------------------------- #
# The pipeline step
# --------------------------------------------------------------------------- #
def test_the_run_gains_a_naming_step():
    events, _ = _run(naming_agent=NamingStub())
    steps = [e.step for e in events]
    assert "name_functions" in steps
    # …between decompile and analyze, because the code has to be in hand
    assert steps.index("decompile") < steps.index("name_functions") < steps.index("analyze")


def test_the_step_reports_how_many_were_named():
    events, _ = _run(naming_agent=NamingStub())
    finish = [e for e in events if e.step == "name_functions" and e.type.value == "step_finish"][0]
    assert finish.data == {"named": 2, "total": 2}


def test_names_ride_out_on_the_result():
    _events, (result, _report) = _run(naming_agent=NamingStub())
    names = {n.original_name: n for n in result.function_names}
    assert set(names) == {"parse_header", "check_key"}
    assert names["parse_header"].address == "401146"
    assert names["parse_header"].suggested_name.startswith("good_name_")
    assert names["parse_header"].purpose


def test_all_eight_are_named_in_one_call():
    stub = NamingStub()
    _run(naming_agent=stub)
    assert stub.calls == 1


def test_reserved_names_reach_the_agent():
    """A second run must not propose a name another function already holds."""
    _events, (result, _r) = _run(naming_agent=NamingStub(), reserved_names={"good_name_1"})
    suggested = {n.suggested_name for n in result.function_names}
    assert "good_name_1" not in suggested
    assert "good_name_1_2" in suggested


def test_a_naming_failure_does_not_fail_the_analysis():
    class Boom:
        def __call__(self, functions):
            raise RuntimeError("no LM")

    _events, (result, report) = _run(naming_agent=Boom())
    assert report.content.startswith("# RE Analysis")
    assert all(n.suggested_name is None for n in result.function_names)


def test_a_function_without_an_address_is_skipped():
    """A name is stored against the address; without one it would not survive a
    re-import."""

    class NoAddrMcp(FakeMcp):
        def call(self, tool, args):
            if tool == "list_functions":
                return {
                    "functions": [{"name": "parse_header", "is_thunk": False, "is_external": False}]
                }
            return super().call(tool, args)

    _events, (result, _r) = _drive(
        re_path.run(
            BinaryRef(program="p", sha256="h", filename="x.elf"),
            GhidraMcpClient(transport=NoAddrMcp()),
            analyzer=AnalyzerStub(),
            naming_agent=NamingStub(),
        )
    )
    assert result.function_names == []


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #
class FakeStore:
    def __init__(self):
        self.objects = {}

    def put(self, k, d):
        self.objects[k] = d

    def exists(self, k):
        return k in self.objects

    def get(self, k):
        return self.objects[k]


def _analysis(session, sha="a" * 64):
    services.bootstrap(session)
    team = session.query(Team).filter_by(name="Default").one()
    admin = session.query(User).filter_by(username="admin").one()
    proj = services.get_or_create_default_project(session, team.id)
    b = Binary(
        team_id=team.id,
        project_id=proj.id,
        sha256=sha,
        filename="x.elf",
        size=10,
        storage_key="k",
        uploaded_by=admin.id,
        ghidra_program_name="x.elf",
    )
    session.add(b)
    session.flush()
    a = Analysis(team_id=team.id, binary_id=b.id, mode=AnalysisMode.re, created_by=admin.id)
    session.add(a)
    session.flush()
    return a


def _named(name="parse_header", addr="401146", suggested="parse_ioctl_header"):
    return NamedFunction(original_name=name, address=addr, suggested_name=suggested, purpose="p")


def test_persist_stores_names_and_links_them_included(app, session):
    a = _analysis(session)
    persist_function_names(session, a, [_named()])
    session.commit()
    row = session.query(FunctionName).one()
    assert row.binary_id == a.binary_id and row.suggested_name == "parse_ioctl_header"
    link = session.query(AnalysisFunction).one()
    assert link.analysis_id == a.id and link.included is True


def test_persist_is_idempotent_for_the_same_address(app, session):
    a = _analysis(session)
    persist_function_names(session, a, [_named()])
    session.commit()
    persist_function_names(session, a, [_named()])
    session.commit()
    assert session.query(FunctionName).count() == 1
    assert session.query(AnalysisFunction).count() == 1


def test_a_rerun_never_overwrites_a_hand_corrected_name(app, session):
    a = _analysis(session)
    persist_function_names(session, a, [_named()])
    session.commit()
    row = session.query(FunctionName).one()
    row.suggested_name = "what_a_human_called_it"
    row.source = "user"
    session.commit()

    changed = persist_function_names(session, a, [_named(suggested="machine_second_guess")])
    session.commit()
    session.refresh(row)
    assert row.suggested_name == "what_a_human_called_it"
    assert changed == 0


def test_a_rerun_may_improve_a_machine_name(app, session):
    a = _analysis(session)
    persist_function_names(session, a, [_named(suggested="fn_1")])
    session.commit()
    persist_function_names(session, a, [_named(suggested="parse_ioctl_header")])
    session.commit()
    assert session.query(FunctionName).one().suggested_name == "parse_ioctl_header"


def test_a_second_analysis_of_one_binary_reuses_the_names(app, session):
    a1 = _analysis(session)
    persist_function_names(session, a1, [_named()])
    session.commit()
    admin = session.query(User).filter_by(username="admin").one()
    a2 = Analysis(
        team_id=a1.team_id, binary_id=a1.binary_id, mode=AnalysisMode.re, created_by=admin.id
    )
    session.add(a2)
    session.flush()
    persist_function_names(session, a2, [_named()])
    session.commit()
    assert session.query(FunctionName).count() == 1  # one name…
    assert session.query(AnalysisFunction).count() == 2  # …linked to both runs


def test_persist_re_result_carries_names_through(app, session):
    a = _analysis(session)
    persist_re_result(
        session,
        a,
        (
            EngineRE(binary_type="ELF", function_names=[_named()]),
            EngineReport(format="md", content="# RE Analysis\n"),
        ),
        store=FakeStore(),
    )
    session.commit()
    assert session.query(FunctionName).one().suggested_name == "parse_ioctl_header"


def test_an_re_result_with_no_names_persists_cleanly(app, session):
    a = _analysis(session)
    persist_re_result(
        session, a, (EngineRE(binary_type="ELF"), EngineReport(content="# R\n")), store=FakeStore()
    )
    session.commit()
    assert session.query(FunctionName).count() == 0
