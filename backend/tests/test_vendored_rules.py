"""The vendored 0xdea rule tree and its grouping into Keystone built-ins.

Two jobs: prove the vendored copy is intact and loadable by Keystone's own
validator, and pin the editorial decisions in `rule_import.GROUPS` so a re-vendor
that changes them fails loudly."""

from __future__ import annotations

import shutil
import subprocess

import pytest
import yaml

from keystone_api import services
from keystone_api.models import RuleSet, RuleSetVersion
from keystone_api.rule_import import (
    GROUPS,
    VENDOR_ROOT,
    build_groups,
    compose,
    load_vendored_rules,
    select,
)
from keystone_api.rulesets import validate_ruleset


# --------------------------------------------------------------------------- #
# The vendored tree
# --------------------------------------------------------------------------- #
def test_the_tree_is_present_with_its_licence_and_provenance():
    """MIT requires the licence travel with the copy; UPSTREAM.md pins the commit."""
    assert (VENDOR_ROOT / "LICENSE").is_file()
    assert "MIT License" in (VENDOR_ROOT / "LICENSE").read_text()
    upstream = (VENDOR_ROOT / "UPSTREAM.md").read_text()
    assert "0xdea/semgrep-rules" in upstream
    assert "33155497b25b4639193db016962af2df46290b10" in upstream


def test_every_vendored_rule_passes_keystones_validator():
    """The whole premise of the import: these load unmodified."""
    for path in sorted((VENDOR_ROOT / "rules").rglob("*.yaml")):
        rule_ids, _ = validate_ruleset(path.read_text())
        assert rule_ids, path


def test_rule_ids_are_unique_across_the_tree_and_namespaced_by_upstream():
    rules = load_vendored_rules()
    ids = [r["id"] for r in rules]
    assert len(ids) == len(set(ids))
    # `raptor-` prefixed upstream, so nothing collides with Keystone's own built-in
    assert all(i.startswith("raptor-") for i in ids)
    assert not (set(ids) & {"dangerous-copy", "unbounded-input", "command-execution"})


def test_the_tree_has_the_expected_rule_count():
    """A bare count, so a partial or over-eager re-vendor is visible."""
    assert len(load_vendored_rules()) == 50


# --------------------------------------------------------------------------- #
# Grouping
# --------------------------------------------------------------------------- #
def test_every_rule_lands_in_exactly_one_group():
    """No rule silently dropped, and none double-counted across groups."""
    rules = load_vendored_rules()
    seen: list[str] = []
    for group in GROUPS:
        seen.extend(r["id"] for r in select(rules, group))
    assert sorted(seen) == sorted(r["id"] for r in rules)
    assert len(seen) == len(set(seen)), "a rule appears in two groups"


def test_group_shape_is_pinned():
    assert [(g.name, n) for g, _, n in build_groups()] == [
        ("0xdea · Memory safety (C/C++)", 20),
        ("0xdea · Dangerous functions (C/C++)", 9),
        ("0xdea · Correctness & control flow (C/C++)", 10),
        ("0xdea · Privilege, secrets & crypto (C/C++)", 8),
        ("0xdea · Recon & noisy (C/C++)", 3),
    ]


def test_the_recon_rules_are_isolated_from_the_signal_groups():
    """41 of 46 hits on the ksthunk corpus came from these two; they must not ride
    along in a group an analyst reaches for to find memory bugs."""
    grouped = {g.name: yaml.safe_load(c)["rules"] for g, c, _ in build_groups()}
    recon = {r["id"] for r in grouped["0xdea · Recon & noisy (C/C++)"]}
    assert recon == {"raptor-typos", "raptor-interesting-api-calls", "raptor-bad-words"}
    for name, rules in grouped.items():
        if name != "0xdea · Recon & noisy (C/C++)":
            assert not ({r["id"] for r in rules} & recon), name


def test_memory_group_carries_the_classes_that_matter_on_decompiled_code():
    memory = next(c for g, c, _ in build_groups() if "Memory safety" in g.name)
    ids = {r["id"] for r in yaml.safe_load(memory)["rules"]}
    for expected in ("raptor-use-after-free", "raptor-double-free", "raptor-off-by-one"):
        assert expected in ids


def test_every_composed_group_validates_and_fits_the_size_cap():
    for group, content, count in build_groups():
        rule_ids, _ = validate_ruleset(content)
        assert len(rule_ids) == count, group.name


def test_composition_is_byte_stable():
    """content_sha256 is the no-op check; a non-deterministic dump would make every
    boot append a version."""
    assert build_groups()[0][1] == build_groups()[0][1]
    rules = load_vendored_rules()
    assert compose(rules[:3]) == compose(rules[:3])


def test_an_unmapped_class_is_reported_not_swallowed(caplog, tmp_path):
    """A rule upstream adds under a class we don't map must be loud, or the next
    re-vendor loses it silently."""
    shutil.copytree(VENDOR_ROOT / "rules", tmp_path / "rules")
    (tmp_path / "rules" / "c" / "zz-new.yaml").write_text(
        "rules:\n"
        "  - id: raptor-brand-new\n"
        "    languages: [c]\n"
        "    severity: INFO\n"
        "    message: m\n"
        "    pattern: foo(...)\n"
        "    metadata: {vulnerability_class: Some Unmapped Class}\n"
    )
    with caplog.at_level("WARNING"):
        build_groups(tmp_path)
    assert "raptor-brand-new" in caplog.text
    assert "NOT imported" in caplog.text


def test_a_missing_tree_is_survivable(tmp_path):
    assert build_groups(tmp_path) == []


# --------------------------------------------------------------------------- #
# Seeding
# --------------------------------------------------------------------------- #
def test_bootstrap_seeds_the_groups_as_built_ins(app, session):
    services.bootstrap(session)
    session.commit()
    builtins = {
        rs.name: rs for rs in session.query(RuleSet).filter_by(team_id=None, is_builtin=True)
    }
    for group in GROUPS:
        assert group.name in builtins
        rs = builtins[group.name]
        assert rs.team_id is None  # visible to every team
        assert services.latest_version(session, rs.id).version_no == 1
    # the deployment default is still Keystone's own set, not a vendored one
    assert services.get_or_create_settings(session).default_rule_set_id not in {
        builtins[g.name].id for g in GROUPS
    }


def test_reseeding_an_unchanged_tree_adds_no_versions(app, session):
    services.bootstrap(session)
    session.commit()
    before = session.query(RuleSetVersion).count()
    services.ensure_vendored_rulesets(session)
    services.ensure_vendored_rulesets(session)
    session.commit()
    assert session.query(RuleSetVersion).count() == before


def test_a_revendor_that_changes_a_rule_appends_a_version(app, session, monkeypatch, tmp_path):
    services.bootstrap(session)
    session.commit()
    memory = (
        session.query(RuleSet)
        .filter(RuleSet.team_id.is_(None), RuleSet.name.like("%Memory safety%"))
        .one()
    )
    assert len(memory.versions) == 1

    shutil.copytree(VENDOR_ROOT / "rules", tmp_path / "rules")
    target = tmp_path / "rules" / "c" / "double-free.yaml"
    edited = target.read_text().replace("severity: ERROR", "severity: WARNING")
    assert edited != target.read_text()  # the fixture edit must actually bite
    target.write_text(edited)

    import keystone_api.rule_import as ri

    monkeypatch.setattr(ri, "VENDOR_ROOT", tmp_path)
    services.ensure_vendored_rulesets(session)
    session.commit()
    session.refresh(memory)
    assert [v.version_no for v in memory.versions] == [1, 2]
    # …and only that group moved
    others = (
        session.query(RuleSet)
        .filter(RuleSet.team_id.is_(None), RuleSet.name.like("%Dangerous functions%"))
        .one()
    )
    assert len(others.versions) == 1


def test_a_seeded_group_is_pickable_and_pinnable(app, client, session):
    """End of the line: it shows in the library and an analysis can pin it."""
    services.bootstrap(session)
    session.commit()
    tok = client.post(
        "/auth/login", json={"username": "admin", "password": "change-me"}
    ).get_json()["access_token"]
    rows = client.get("/rule-sets", headers={"Authorization": f"Bearer {tok}"}).get_json()
    memory = next(r for r in rows if "Memory safety" in r["name"])
    assert memory["is_builtin"] and memory["latest_version"]["rule_count"] == 20
    assert "raptor-use-after-free" in memory["latest_version"]["rule_ids"]


# --------------------------------------------------------------------------- #
# Upstream's own fixtures (needs the semgrep binary — worker-only extra)
# --------------------------------------------------------------------------- #
@pytest.mark.integration
@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep is a worker-only extra")
def test_semgrep_accepts_every_vendored_rule():
    """Structural validation is ours; this is Semgrep's own verdict on the tree."""
    proc = subprocess.run(
        ["semgrep", "--validate", "--config", str(VENDOR_ROOT / "rules" / "c"), "--json"],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
