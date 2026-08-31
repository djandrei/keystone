"""Starting a VR analysis with chosen rule sets: the 400 on a bad pin, the pin
itself, what the analysis reports back, and how the worker turns a pin into
`--config` paths."""

from __future__ import annotations

import io

from keystone_api import services
from keystone_api.models import (
    AnalysisRuleSet,
    RuleSet,
    RuleSetVersion,
    Team,
)
from keystone_api.services import add_rule_set_version, latest_version

RULES_A = (
    "rules:\n"
    "  - {id: dangerous-copy, languages: [c], severity: ERROR, message: A, pattern: 'memcpy(...)'}\n"
)
RULES_B = (
    "rules:\n"
    "  - {id: command-exec, languages: [c], severity: WARNING, message: B, pattern: 'system(...)'}\n"
)

ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 1024


class _FakeStore:
    """Same shape as tests/test_persist.py's — the report artifact is not the
    subject here."""

    def __init__(self):
        self.objects: dict[str, bytes] = {}

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


def _setup(app, client, session):
    """A bootstrapped team with one uploaded binary. Returns (team, binary_id, token)."""
    services.bootstrap(session)
    session.commit()
    team = session.query(Team).filter_by(name="Default").one()
    tok = _tok(client)
    r = client.post(
        "/binaries",
        headers=_h(tok),
        data={"team_id": str(team.id), "file": (io.BytesIO(ELF), "sample.elf")},
        content_type="multipart/form-data",
    )
    assert r.status_code == 201, r.get_json()
    return team, r.get_json()["id"], tok


def _rs(session, team_id, name, content):
    rs = RuleSet(team_id=team_id, name=name)
    session.add(rs)
    session.flush()
    add_rule_set_version(session, rs, content)
    session.commit()
    return rs


def test_vr_start_pins_the_chosen_rule_sets(app, client, session):
    team, bid, tok = _setup(app, client, session)
    a = _rs(session, team.id, "a", RULES_A)
    b = _rs(session, team.id, "b", RULES_B)

    r = client.post(
        f"/binaries/{bid}/analyses",
        headers=_h(tok),
        json={"mode": "vr", "params": {"rule_set_ids": [b.id, a.id]}},
    )
    assert r.status_code == 201
    aid = r.get_json()["id"]

    pins = (
        session.query(AnalysisRuleSet)
        .filter_by(analysis_id=aid)
        .order_by(AnalysisRuleSet.position)
        .all()
    )
    assert [p.position for p in pins] == [0, 1]
    got = [session.get(RuleSetVersion, p.rule_set_version_id).rule_set_id for p in pins]
    assert got == [b.id, a.id]


def test_vr_start_defaults_to_the_system_built_in(app, client, session):
    team, bid, tok = _setup(app, client, session)
    r = client.post(f"/binaries/{bid}/analyses", headers=_h(tok), json={"mode": "vr"})
    assert r.status_code == 201
    detail = client.get(f"/analyses/{r.get_json()['id']}", headers=_h(tok)).get_json()
    assert len(detail["rule_sets"]) == 1
    assert detail["rule_sets"][0]["is_builtin"] is True


def test_analysis_detail_names_the_exact_versions_it_ran(app, client, session):
    """The visible payoff of pinning: v1 is still named after v2 lands."""
    team, bid, tok = _setup(app, client, session)
    rs = _rs(session, team.id, "a", RULES_A)
    aid = client.post(
        f"/binaries/{bid}/analyses",
        headers=_h(tok),
        json={"mode": "vr", "params": {"rule_set_ids": [rs.id]}},
    ).get_json()["id"]

    client.post(f"/rule-sets/{rs.id}/versions", headers=_h(tok), json={"content": RULES_B})

    detail = client.get(f"/analyses/{aid}", headers=_h(tok)).get_json()
    assert detail["rule_sets"] == [
        {
            "rule_set_id": rs.id,
            "rule_set_version_id": latest_version(session, rs.id).id - 1,
            "name": "a",
            "version_no": 1,
            "is_builtin": False,
            "rule_count": 1,
        }
    ]


def test_an_exact_version_pin_survives_a_later_edit(app, client, session):
    team, bid, tok = _setup(app, client, session)
    rs = _rs(session, team.id, "a", RULES_A)
    v1 = latest_version(session, rs.id)
    client.post(f"/rule-sets/{rs.id}/versions", headers=_h(tok), json={"content": RULES_B})

    aid = client.post(
        f"/binaries/{bid}/analyses",
        headers=_h(tok),
        json={"mode": "vr", "params": {"rule_set_version_ids": [v1.id]}},
    ).get_json()["id"]
    detail = client.get(f"/analyses/{aid}", headers=_h(tok)).get_json()
    assert detail["rule_sets"][0]["version_no"] == 1


def test_an_unknown_rule_set_is_a_400_not_a_failed_job(app, client, session):
    _team, bid, tok = _setup(app, client, session)
    r = client.post(
        f"/binaries/{bid}/analyses",
        headers=_h(tok),
        json={"mode": "vr", "params": {"rule_set_ids": [9999]}},
    )
    assert r.status_code == 400 and r.get_json()["error"] == "invalid_rule_set"


def test_another_teams_rule_set_is_rejected_at_start(app, client, session):
    team, bid, tok = _setup(app, client, session)
    other = Team(name="Other")
    session.add(other)
    session.flush()
    theirs = _rs(session, other.id, "theirs", RULES_A)
    r = client.post(
        f"/binaries/{bid}/analyses",
        headers=_h(tok),
        json={"mode": "vr", "params": {"rule_set_ids": [theirs.id]}},
    )
    assert r.status_code == 400
    assert "does not belong" in r.get_json()["detail"]


def test_re_mode_pins_nothing(app, client, session):
    """RE does not run Semgrep; resolving rule sets for it would be noise."""
    _team, bid, tok = _setup(app, client, session)
    aid = client.post(f"/binaries/{bid}/analyses", headers=_h(tok), json={"mode": "re"}).get_json()[
        "id"
    ]
    assert session.query(AnalysisRuleSet).filter_by(analysis_id=aid).count() == 0


# --------------------------------------------------------------------------- #
# The worker's read side
# --------------------------------------------------------------------------- #
def test_worker_materializes_the_pin_into_config_paths(app, client, session, monkeypatch):
    import worker

    team, bid, tok = _setup(app, client, session)
    a = _rs(session, team.id, "a", RULES_A)
    b = _rs(session, team.id, "b", RULES_B)
    aid = client.post(
        f"/binaries/{bid}/analyses",
        headers=_h(tok),
        json={"mode": "vr", "params": {"rule_set_ids": [a.id, b.id]}},
    ).get_json()["id"]

    configs = worker._resolve_semgrep_configs(session, aid)
    va, vb = latest_version(session, a.id), latest_version(session, b.id)
    assert [c.split("/")[-1] for c in configs] == [f"rs{va.id}.yaml", f"rs{vb.id}.yaml"]
    # …and the written rules are namespaced, so the two `id`s stay distinct
    import yaml

    ids = [yaml.safe_load(open(c))["rules"][0]["id"] for c in configs]
    assert ids == [f"ks{va.id}.dangerous-copy", f"ks{vb.id}.command-exec"]


def test_worker_falls_back_to_the_env_config_when_nothing_is_pinned(app, client, session):
    """A pre-M6 analysis, or a deployment with no library — must not regress."""
    import worker
    from keystone_api.config import get_settings

    _team, bid, tok = _setup(app, client, session)
    aid = client.post(f"/binaries/{bid}/analyses", headers=_h(tok), json={"mode": "re"}).get_json()[
        "id"
    ]
    assert worker._resolve_semgrep_configs(session, aid) == get_settings().semgrep_config


def test_findings_carry_rule_set_provenance_through_persist(app, client, session):
    from keystone_api.models import Analysis
    from keystone_api.persist import persist_vr_result
    from keystone_engine.results import Report
    from keystone_engine.results import VRFinding as EngineVR

    team, bid, tok = _setup(app, client, session)
    rs = _rs(session, team.id, "a", RULES_A)
    version = latest_version(session, rs.id)
    aid = client.post(
        f"/binaries/{bid}/analyses",
        headers=_h(tok),
        json={"mode": "vr", "params": {"rule_set_ids": [rs.id]}},
    ).get_json()["id"]

    analysis = session.get(Analysis, aid)
    persist_vr_result(
        session,
        analysis,
        (
            [
                EngineVR(
                    rule=f"ks{version.id}.dangerous-copy",
                    file="f.c",
                    line=1,
                    rule_set_version_id=version.id,
                )
            ],
            Report(format="md", content="# r"),
        ),
        store=_FakeStore(),
    )
    session.commit()
    findings = client.get(f"/analyses/{aid}/findings", headers=_h(tok)).get_json()
    assert findings[0]["rule_set_version_id"] == version.id
