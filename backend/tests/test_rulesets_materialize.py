"""Materializing pinned rule set versions for Semgrep, and the rule-id namespacing
that keeps two rule sets with the same rule id distinguishable."""

from __future__ import annotations

import yaml

from keystone_engine.rulesets import (
    materialize,
    namespaced_id,
    rule_set_version_of,
)
from keystone_engine.semgrep import group_by_rule_class, parse_semgrep, rule_class, run_semgrep

A = "rules:\n  - {id: dangerous-copy, languages: [c], severity: ERROR, message: A, pattern: 'memcpy(...)'}\n"
B = "rules:\n  - {id: dangerous-copy, languages: [c], severity: ERROR, message: B, pattern: 'strcpy(...)'}\n"


def test_materialize_writes_one_file_per_version_in_order(tmp_path):
    paths = materialize([(19, A), (7, B)], tmp_path)
    assert [p.split("/")[-1] for p in paths] == ["rs19.yaml", "rs7.yaml"]
    assert all(tmp_path.joinpath(p.split("/")[-1]).exists() for p in paths)


def test_rule_ids_are_namespaced_by_version(tmp_path):
    (path,) = materialize([(19, A)], tmp_path)
    doc = yaml.safe_load(open(path))
    assert doc["rules"][0]["id"] == "ks19.dangerous-copy"
    # everything else about the rule survives the rewrite
    assert doc["rules"][0]["pattern"] == "memcpy(...)"


def test_colliding_rule_ids_stay_distinguishable(tmp_path):
    """The bug this exists to prevent: two rule sets both defining `dangerous-copy`
    would otherwise be indistinguishable in the findings."""
    materialize([(19, A), (7, B)], tmp_path)
    a = yaml.safe_load(open(tmp_path / "rs19.yaml"))["rules"][0]["id"]
    b = yaml.safe_load(open(tmp_path / "rs7.yaml"))["rules"][0]["id"]
    assert a != b
    assert rule_set_version_of(a) == 19 and rule_set_version_of(b) == 7


def test_namespacing_does_not_disturb_rule_class_grouping():
    """…while still grouping by weakness class, which is what the picker wants."""
    assert rule_class(namespaced_id(19, "dangerous-copy")) == "dangerous-copy"
    assert rule_class(namespaced_id(7, "dangerous-copy")) == "dangerous-copy"


def test_rule_set_version_of_handles_the_legacy_path():
    assert rule_set_version_of("dangerous-copy") is None
    assert rule_set_version_of(None) is None
    assert rule_set_version_of("rules.c.integer-overflow") is None


def test_rule_set_version_of_survives_a_path_prefix():
    """Semgrep may prefix a check_id with the config path; the marker is still found."""
    assert rule_set_version_of("tmp.keystone-rulesets.4.ks19.dangerous-copy") == 19


def test_unparseable_content_is_written_through(tmp_path):
    """Semgrep reports a broken rule file better than we could — don't kill the
    scan here."""
    (path,) = materialize([(3, "rules: [")], tmp_path)
    assert open(path).read() == "rules: ["


def test_parse_semgrep_carries_provenance():
    raw = {
        "results": [
            {
                "check_id": "ks19.dangerous-copy",
                "path": "/d/f.c",
                "start": {"line": 12},
                "extra": {"message": "m"},
            },
            {
                "check_id": "legacy-rule",
                "path": "/d/g.c",
                "start": {"line": 3},
                "extra": {"message": "m"},
            },
        ]
    }
    findings = parse_semgrep(raw)
    assert [f.rule_set_version_id for f in findings] == [19, None]


def test_two_rulesets_group_together_but_keep_provenance():
    raw = {
        "results": [
            {"check_id": "ks19.dangerous-copy", "path": "a.c", "start": {"line": 1}, "extra": {}},
            {"check_id": "ks7.dangerous-copy", "path": "b.c", "start": {"line": 2}, "extra": {}},
        ]
    }
    groups = group_by_rule_class(parse_semgrep(raw))
    assert list(groups) == ["dangerous-copy"] and len(groups["dangerous-copy"]) == 2
    assert {f.rule_set_version_id for f in groups["dangerous-copy"]} == {19, 7}


def test_run_semgrep_passes_every_config_in_order():
    seen = {}

    def runner(target_dir, configs):
        seen["dir"], seen["configs"] = target_dir, configs
        return {"results": []}

    run_semgrep("/decompiled", ["/r/rs19.yaml", "/r/rs7.yaml"], runner=runner)
    assert seen["configs"] == ["/r/rs19.yaml", "/r/rs7.yaml"]


def test_run_semgrep_still_accepts_a_bare_string():
    """The legacy env-config path must keep working after the list change."""
    seen = {}

    def runner(target_dir, configs):
        seen["configs"] = configs
        return {"results": []}

    run_semgrep("/decompiled", "/app/semgrep-rules/decompiled-c.yaml", runner=runner)
    assert seen["configs"] == ["/app/semgrep-rules/decompiled-c.yaml"]
