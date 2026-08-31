"""Materialize pinned ruleset versions to disk for Semgrep.

Two jobs, one of which is not obvious.

The obvious one: write each pinned version's YAML to a file and hand the paths to
`--config`. Only paths this module just wrote ever reach Semgrep — never a
registry name or a URL — so the worker needs no network egress for a scan.

The subtle one: **namespacing rule ids**. With a local `--config file.yaml`,
Semgrep's `check_id` is the rule's bare `id`, so two rulesets that both define
`dangerous-copy` would be indistinguishable in the findings and would silently
merge in `group_by_rule_class`. Every rule id is rewritten to `ks{version_id}.{id}`
on the way out. Because `semgrep.rule_class` takes the leaf after the last dot,
grouping still yields `dangerous-copy` — classes stay merged across rulesets,
which is the right grouping — while `rule_set_version_of` recovers exactly which
ruleset fired. Authors write natural ids; namespacing is a runtime concern.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

# `ks<version_id>.` — written by `materialize`, read back by `rule_set_version_of`.
NS_PREFIX_RE = re.compile(r"\bks(\d+)\.")


def namespaced_id(version_id: int, rule_id: str) -> str:
    return f"ks{version_id}.{rule_id}"


def rule_set_version_of(check_id: str | None) -> int | None:
    """The ruleset version id a Semgrep check_id came from, or None for findings
    produced by the legacy single-config path (which has no prefix)."""
    if not check_id:
        return None
    m = NS_PREFIX_RE.search(check_id)
    return int(m.group(1)) if m else None


def materialize(versions: list[tuple[int, str]], dest: str | Path) -> list[str]:
    """Write `(version_id, yaml_content)` pairs into `dest`, namespacing every rule
    id. Returns the `--config` paths in the order given.

    A version whose YAML will not parse, or carries no `rules:` list, is written
    through unchanged: Semgrep reports the error itself, with better wording than
    we could invent, rather than the scan dying here.
    """
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    paths: list[str] = []

    for version_id, content in versions:
        try:
            doc = yaml.safe_load(content)
        except yaml.YAMLError:
            doc = None
        if isinstance(doc, dict) and isinstance(doc.get("rules"), list):
            for rule in doc["rules"]:
                if isinstance(rule, dict) and isinstance(rule.get("id"), str):
                    rule["id"] = namespaced_id(version_id, rule["id"])
            out = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
        else:
            out = content

        path = dest / f"rs{version_id}.yaml"
        path.write_text(out, encoding="utf-8")
        paths.append(str(path))

    return paths
