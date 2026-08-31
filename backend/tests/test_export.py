"""Stage 4.1: report export — MD, JSON bundle, valid PDF."""

from __future__ import annotations

import json

from keystone_api import services
from keystone_api.models import (
    Analysis,
    AnalysisMode,
    AnalysisStatus,
    Binary,
    Report,
    REResult,
    Role,
    Team,
    TeamMember,
    TeamRole,
    User,
)
from keystone_api.security import hash_password


class FakeStore:
    def __init__(self):
        self.objects = {}

    def put(self, key, data):
        self.objects[key] = data

    def exists(self, key):
        return key in self.objects

    def get(self, key):
        return self.objects[key]


def _tok(client, u, p):
    return client.post("/auth/login", json={"username": u, "password": p}).get_json()[
        "access_token"
    ]


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _seed(app, session):
    app.config["OBJECT_STORE"] = FakeStore()
    services.bootstrap(session)
    t = Team(name="Blue")
    u = User(
        username="ana", email="a@x", password_hash=hash_password("pw123456"), role=Role.analyst
    )
    session.add_all([t, u])
    session.flush()
    session.add(TeamMember(team_id=t.id, user_id=u.id, team_role=TeamRole.member))
    b = Binary(
        team_id=t.id, sha256="a" * 64, filename="ls", size=1, storage_key="k", uploaded_by=u.id
    )
    session.add(b)
    session.flush()
    a = Analysis(
        team_id=t.id,
        binary_id=b.id,
        mode=AnalysisMode.re,
        status=AnalysisStatus.succeeded,
        created_by=u.id,
    )
    session.add(a)
    session.flush()
    session.add(
        REResult(
            analysis_id=a.id, binary_type="cli_tool", language_runtime="C", purpose="lists files"
        )
    )
    app.config["OBJECT_STORE"].put(f"reports/{a.id}.md", b"# RE Analysis\nlanguage_runtime: C")
    session.add(Report(analysis_id=a.id, format="md", storage_key=f"reports/{a.id}.md"))
    session.commit()
    return a


def test_export_markdown(app, client, session):
    a = _seed(app, session)
    r = client.get(
        f"/analyses/{a.id}/export?format=md", headers=_h(_tok(client, "ana", "pw123456"))
    )
    assert r.status_code == 200 and "text/markdown" in r.content_type
    assert b"language_runtime" in r.data
    assert "attachment" in r.headers["Content-Disposition"]


def test_export_json_bundle(app, client, session):
    a = _seed(app, session)
    r = client.get(
        f"/analyses/{a.id}/export?format=json", headers=_h(_tok(client, "ana", "pw123456"))
    )
    assert r.status_code == 200 and "application/json" in r.content_type
    bundle = json.loads(r.data)
    assert bundle["analysis"]["id"] == a.id
    assert bundle["re_result"]["language_runtime"] == "C"
    assert "language_runtime" in bundle["report_markdown"]


def test_export_pdf_is_valid(app, client, session):
    a = _seed(app, session)
    r = client.get(
        f"/analyses/{a.id}/export?format=pdf", headers=_h(_tok(client, "ana", "pw123456"))
    )
    assert r.status_code == 200 and r.content_type == "application/pdf"
    assert r.data.startswith(b"%PDF-1.4") and r.data.rstrip().endswith(b"%%EOF")


def test_export_bad_format(app, client, session):
    a = _seed(app, session)
    assert (
        client.get(
            f"/analyses/{a.id}/export?format=xls", headers=_h(_tok(client, "ana", "pw123456"))
        ).status_code
        == 400
    )


# --------------------------------------------------------------------------- #
# Attribution in exports. An export is the redistributed artifact — the credit for
# imported rules has to leave Keystone with it, in every format.
# --------------------------------------------------------------------------- #
CREDIT = {
    "author": "Marco Ivaldi (raptor)",
    "license": "MIT",
    "url": "https://github.com/0xdea/semgrep-rules",
    "commit": "33155497b25b4639193db016962af2df46290b10",
}
PINNED = [
    {
        "rule_set_id": 3,
        "rule_set_version_id": 30,
        "name": "0xdea · Memory safety (C/C++)",
        "version_no": 1,
        "is_builtin": True,
        "rule_count": 20,
        "attribution": CREDIT,
    },
    {
        "rule_set_id": 7,
        "rule_set_version_id": 71,
        "name": "our own rules",
        "version_no": 2,
        "is_builtin": False,
        "rule_count": 3,
        "attribution": None,
    },
]


def test_attribution_section_names_author_licence_and_source():
    from keystone_api.export import attribution_section

    out = attribution_section(PINNED)
    assert "0xdea · Memory safety (C/C++)** v1 — 20 rules" in out
    assert "Rules by Marco Ivaldi (raptor)" in out
    assert "MIT" in out
    assert "https://github.com/0xdea/semgrep-rules @ 3315549" in out
    # a rule set authored here is listed as provenance but claims no credit
    assert "our own rules** v2" in out
    assert out.count("Rules by") == 1


def test_attribution_section_is_empty_without_pins():
    from keystone_api.export import attribution_section

    assert attribution_section([]) == ""


def test_with_attribution_sits_under_the_title():
    """Near the top, not the bottom: it is provenance as much as a licence notice."""
    from keystone_api.export import with_attribution

    out = with_attribution("# VR Analysis — ls\n\nbody text\n", PINNED)
    lines = [ln for ln in out.splitlines() if ln.strip()]
    assert lines[0] == "# VR Analysis — ls"
    assert lines[1] == "## Rule sets"
    assert lines.index("body text") > lines.index("## Rule sets")


def test_with_attribution_handles_a_report_with_no_title():
    from keystone_api.export import with_attribution

    out = with_attribution("just body\n", PINNED)
    assert out.startswith("## Rule sets")
    assert "just body" in out


def test_with_attribution_leaves_an_unpinned_report_alone():
    from keystone_api.export import with_attribution

    assert with_attribution("# R\n\nbody\n", []) == "# R\n\nbody\n"


def test_pdf_paginates_instead_of_clipping():
    """The old writer clipped to one page, which would have silently dropped the
    credit off the end of any real report."""
    from keystone_api.export import text_to_pdf

    pdf = text_to_pdf("line\n" * 300)
    assert pdf.startswith(b"%PDF-1.4")
    assert pdf.rstrip().endswith(b"%%EOF")
    assert pdf.count(b"/Type/Page/") == 6
    assert b"/Count 6" in pdf


def test_pdf_is_capped_at_max_pages():
    from keystone_api.export import MAX_PAGES, text_to_pdf

    pdf = text_to_pdf("line\n" * (58 * (MAX_PAGES + 10)))
    assert pdf.count(b"/Type/Page/") == MAX_PAGES


def test_pdf_keeps_the_credit_that_a_one_page_export_would_have_lost():
    from keystone_api.export import text_to_pdf, with_attribution

    long_report = "# VR Analysis\n\n" + "some finding line\n" * 200
    pdf = text_to_pdf(with_attribution(long_report, PINNED))
    # parentheses are PDF string delimiters, so the byline appears escaped
    assert rb"Marco Ivaldi \(raptor\)" in pdf
    assert b"github.com/0xdea/semgrep-rules" in pdf


def test_json_bundle_carries_the_rule_sets_and_their_credit():
    from keystone_api.export import report_json_bundle

    bundle = json.loads(report_json_bundle({"id": 1}, None, [], "# R\n", PINNED))
    assert bundle["rule_sets"] == PINNED
    assert bundle["rule_sets"][0]["attribution"]["author"] == "Marco Ivaldi (raptor)"


def test_json_bundle_without_rule_sets_is_an_empty_list():
    from keystone_api.export import report_json_bundle

    assert json.loads(report_json_bundle({"id": 1}, None, [], "# R\n"))["rule_sets"] == []
