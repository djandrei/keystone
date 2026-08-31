"""The Functions section: rendered at read time into the report and every export."""

from __future__ import annotations

import json

from keystone_api import services
from keystone_api.export import functions_section, with_attribution, with_functions
from keystone_api.models import (
    Analysis,
    AnalysisFunction,
    AnalysisMode,
    Binary,
    FunctionName,
    Report,
    Team,
    User,
)

FN = [
    {
        "id": 1,
        "address": "401146",
        "original_name": "FUN_401146",
        "suggested_name": "parse_ioctl_header",
        "display_name": "parse_ioctl_header",
        "purpose": "Reads the IOCTL code and input length.",
        "source": "llm",
        "included": True,
    },
    {
        "id": 2,
        "address": "401200",
        "original_name": "FUN_401200",
        "suggested_name": None,
        "display_name": "FUN_401200",
        "purpose": None,
        "source": "llm",
        "included": True,
    },
    {
        "id": 3,
        "address": "401300",
        "original_name": "FUN_401300",
        "suggested_name": "debug_print_stub",
        "display_name": "debug_print_stub",
        "purpose": "Writes to the debug port.",
        "source": "llm",
        "included": False,
    },
]


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def test_the_original_symbol_is_always_printed():
    """A suggested name is model output from attacker-controlled code; the report
    must never present it as the identity."""
    out = functions_section(FN)
    assert "**parse_ioctl_header** `FUN_401146` @ 401146" in out
    assert "Reads the IOCTL code and input length." in out


def test_a_function_with_no_usable_name_shows_its_symbol_alone():
    out = functions_section(FN)
    assert "- `FUN_401200` @ 401200" in out


def test_an_excluded_function_is_absent():
    out = functions_section(FN)
    assert "debug_print_stub" not in out


def test_nothing_included_renders_nothing():
    assert functions_section([{**FN[0], "included": False}]) == ""
    assert functions_section([]) == ""


def test_with_functions_appends_below_the_body():
    """Appended, unlike attribution: provenance comes first, a reference list after."""
    out = with_functions("# RE Analysis\n\nbody text\n", FN)
    assert out.index("body text") < out.index("## Functions")


def test_with_functions_leaves_a_report_with_no_selection_alone():
    assert with_functions("# R\n\nbody\n", []) == "# R\n\nbody\n"


def test_functions_and_attribution_compose():
    pinned = [
        {
            "name": "0xdea · Memory safety",
            "version_no": 1,
            "rule_count": 20,
            "attribution": {"author": "Marco Ivaldi (raptor)", "license": "MIT"},
        }
    ]
    out = with_functions(with_attribution("# VR Analysis\n\nbody\n", pinned), FN)
    # attribution under the title, functions at the end
    assert out.index("## Rule sets") < out.index("body") < out.index("## Functions")


# --------------------------------------------------------------------------- #
# Through the API, in every format
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


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _tok(client):
    return client.post(
        "/auth/login", json={"username": "admin", "password": "change-me"}
    ).get_json()["access_token"]


def _seed(app, session):
    store = FakeStore()
    app.config["OBJECT_STORE"] = store
    services.bootstrap(session)
    team = session.query(Team).filter_by(name="Default").one()
    admin = session.query(User).filter_by(username="admin").one()
    proj = services.get_or_create_default_project(session, team.id)
    b = Binary(
        team_id=team.id,
        project_id=proj.id,
        sha256="a" * 64,
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
    key = f"reports/{a.id}.md"
    store.put(key, b"# RE Analysis - x.elf\n\nA body paragraph.\n")
    session.add(Report(analysis_id=a.id, format="md", storage_key=key))
    fns = []
    for i, (addr, orig, sug, purpose) in enumerate(
        [
            ("401146", "FUN_401146", "parse_ioctl_header", "Reads the IOCTL code."),
            ("401300", "FUN_401300", "debug_print_stub", "Writes to the debug port."),
        ]
    ):
        f = FunctionName(
            binary_id=b.id, address=addr, original_name=orig, suggested_name=sug, purpose=purpose
        )
        session.add(f)
        session.flush()
        session.add(AnalysisFunction(analysis_id=a.id, function_name_id=f.id, position=i))
        fns.append(f)
    session.commit()
    return a, fns


def test_the_report_view_shows_the_selection(app, client, session):
    a, _ = _seed(app, session)
    md = client.get(f"/analyses/{a.id}/report", headers=_h(_tok(client))).get_data(as_text=True)
    assert "A body paragraph." in md
    assert "parse_ioctl_header" in md and "debug_print_stub" in md


def test_unticking_removes_it_from_the_report_with_no_regeneration(app, client, session):
    """There is no stored artifact to rebuild — the section composes at read time."""
    a, fns = _seed(app, session)
    tok = _tok(client)
    client.patch(f"/analyses/{a.id}/functions", headers=_h(tok), json={"exclude": [fns[1].id]})
    md = client.get(f"/analyses/{a.id}/report", headers=_h(tok)).get_data(as_text=True)
    assert "parse_ioctl_header" in md
    assert "debug_print_stub" not in md


def test_every_export_format_agrees(app, client, session):
    a, fns = _seed(app, session)
    tok = _tok(client)
    client.patch(f"/analyses/{a.id}/functions", headers=_h(tok), json={"exclude": [fns[1].id]})

    md = client.get(f"/analyses/{a.id}/export?format=md", headers=_h(tok)).get_data(as_text=True)
    assert "parse_ioctl_header" in md and "debug_print_stub" not in md

    bundle = json.loads(
        client.get(f"/analyses/{a.id}/export?format=json", headers=_h(tok)).get_data()
    )
    assert [f["display_name"] for f in bundle["functions"]] == [
        "parse_ioctl_header",
        "debug_print_stub",
    ]
    assert [f["included"] for f in bundle["functions"]] == [True, False]
    assert "debug_print_stub" not in bundle["report_markdown"]

    pdf = client.get(f"/analyses/{a.id}/export?format=pdf", headers=_h(tok)).get_data()
    assert pdf.startswith(b"%PDF-1.4") and b"parse_ioctl_header" in pdf


def test_the_json_bundle_keeps_excluded_rows_as_data(app, client, session):
    """Excluded from the prose, still present as data — an export is a record of
    what was found, not only of what was shown."""
    a, fns = _seed(app, session)
    tok = _tok(client)
    client.patch(f"/analyses/{a.id}/functions", headers=_h(tok), json={"exclude": [fns[0].id]})
    bundle = json.loads(
        client.get(f"/analyses/{a.id}/export?format=json", headers=_h(tok)).get_data()
    )
    assert len(bundle["functions"]) == 2


def test_an_analysis_with_no_functions_renders_unchanged(app, client, session):
    a, fns = _seed(app, session)
    for f in fns:
        session.delete(f)
    session.commit()
    md = client.get(f"/analyses/{a.id}/report", headers=_h(_tok(client))).get_data(as_text=True)
    assert md == "# RE Analysis - x.elf\n\nA body paragraph.\n"
