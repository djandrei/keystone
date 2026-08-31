"""Semgrep ruleset validation and normalization.

Structural validation runs **in the API**, which has no Semgrep — it is a
worker-only extra (`pyproject.toml` `[engine]`). So this module checks only what
PyYAML plus the documented rule schema can decide, and the real
`semgrep --validate` runs later in the worker (`worker.validate_ruleset_task`).
A document that fails here is rejected at save; one that fails there is saved and
badged unvalidated.

`yaml.safe_load` is the load path, never `yaml.load`: it refuses `!!python/...`
tags outright rather than relying on us to spot them.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

import yaml

# Bounds. A real ruleset is a few KiB; these stop a paste from becoming a DoS.
MAX_CONTENT_BYTES = 256 * 1024
MAX_RULES = 500
MAX_MESSAGE_CHARS = 4096

RULE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
SEVERITIES = {"INFO", "WARNING", "ERROR"}
# A rule must match something. `mode: taint` carries its own source/sink keys.
PATTERN_KEYS = (
    "pattern",
    "patterns",
    "pattern-either",
    "pattern-regex",
    "pattern-sources",
)


class RulesetError(ValueError):
    """Structural validation failed; `errors` lists every problem, not just the first."""

    def __init__(self, errors: list[str]) -> None:
        super().__init__("; ".join(errors))
        self.errors = errors


def content_sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def validate_ruleset(content: str) -> tuple[list[str], list[str]]:
    """Validate a Semgrep YAML document. Returns `(rule_ids, languages)`.

    Raises `RulesetError` carrying *every* problem found, so the editor can show
    a complete list instead of one error per save attempt.
    """
    errors: list[str] = []

    if not content or not content.strip():
        raise RulesetError(["ruleset is empty"])
    if len(content.encode("utf-8")) > MAX_CONTENT_BYTES:
        raise RulesetError([f"ruleset exceeds {MAX_CONTENT_BYTES // 1024} KiB"])

    try:
        doc: Any = yaml.safe_load(content)
    except yaml.YAMLError as e:
        # The mark carries line/column; surface it, the editor has no other clue.
        mark = getattr(e, "problem_mark", None)
        where = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        raise RulesetError([f"invalid YAML{where}: {getattr(e, 'problem', e)}"]) from e

    if not isinstance(doc, dict):
        raise RulesetError(["top level must be a mapping with a `rules:` key"])
    rules = doc.get("rules")
    if not isinstance(rules, list) or not rules:
        raise RulesetError(["`rules:` must be a non-empty list"])
    if len(rules) > MAX_RULES:
        raise RulesetError([f"{len(rules)} rules exceeds the limit of {MAX_RULES}"])

    rule_ids: list[str] = []
    languages: list[str] = []
    seen: set[str] = set()

    for i, rule in enumerate(rules):
        at = f"rule {i + 1}"
        if not isinstance(rule, dict):
            errors.append(f"{at}: must be a mapping")
            continue

        rid = rule.get("id")
        if not isinstance(rid, str) or not RULE_ID_RE.match(rid):
            errors.append(f"{at}: `id` must be 1-128 chars of [A-Za-z0-9._-] (got {rid!r})")
        else:
            at = f"rule `{rid}`"
            if rid in seen:
                errors.append(f"{at}: duplicate id")
            seen.add(rid)
            rule_ids.append(rid)

        langs = rule.get("languages")
        if not isinstance(langs, list) or not langs or not all(isinstance(x, str) for x in langs):
            errors.append(f"{at}: `languages` must be a non-empty list of strings")
        else:
            languages.extend(langs)

        msg = rule.get("message")
        if not isinstance(msg, str) or not msg.strip():
            errors.append(f"{at}: `message` is required")
        elif len(msg) > MAX_MESSAGE_CHARS:
            errors.append(f"{at}: `message` exceeds {MAX_MESSAGE_CHARS} characters")

        sev = rule.get("severity")
        if sev not in SEVERITIES:
            errors.append(f"{at}: `severity` must be one of {sorted(SEVERITIES)} (got {sev!r})")

        if not any(k in rule for k in PATTERN_KEYS) and rule.get("mode") != "taint":
            errors.append(f"{at}: needs at least one of {list(PATTERN_KEYS)} (or `mode: taint`)")

    if errors:
        raise RulesetError(errors)
    # dict.fromkeys, not set(), so the order the author wrote them survives
    return rule_ids, list(dict.fromkeys(languages))


def rule_messages(content: str) -> list[str]:
    """Every `message` in the document — the text that reaches the triage prompt.

    Used by the injection screen. Never raises: a document that will not parse has
    no messages to screen, and validation reports that separately."""
    try:
        doc = yaml.safe_load(content)
    except yaml.YAMLError:
        return []
    if not isinstance(doc, dict) or not isinstance(doc.get("rules"), list):
        return []
    return [
        r["message"]
        for r in doc["rules"]
        if isinstance(r, dict) and isinstance(r.get("message"), str)
    ]
