"""Structural validation of authored Semgrep rule sets (docs/rule-sets-plan.md §7).

This is the layer that runs in the API, which has no Semgrep — so it checks only
what PyYAML plus the rule schema can decide."""

from __future__ import annotations

import pytest

from keystone_api.rulesets import (
    MAX_CONTENT_BYTES,
    RulesetError,
    content_sha256,
    rule_messages,
    validate_ruleset,
)

GOOD = """
rules:
  - id: dangerous-copy
    languages: [c]
    severity: ERROR
    message: Unbounded copy into a fixed buffer.
    patterns:
      - pattern-either:
          - pattern: memcpy(...)
          - pattern: strcpy(...)
  - id: command-execution
    languages: [c]
    severity: WARNING
    message: Executes a command.
    pattern: system(...)
"""


def test_valid_ruleset_returns_ids_and_languages():
    rule_ids, langs = validate_ruleset(GOOD)
    assert rule_ids == ["dangerous-copy", "command-execution"]
    assert langs == ["c"]


def test_the_shipped_builtin_validates():
    """The ruleset the image ships must pass its own validator — otherwise the
    bootstrap seed silently degrades to a warning."""
    from keystone_api.services import BUILTIN_RULESET_PATH

    rule_ids, langs = validate_ruleset(BUILTIN_RULESET_PATH.read_text())
    assert "dangerous-copy" in rule_ids and langs == ["c"]


@pytest.mark.parametrize(
    "content,fragment",
    [
        ("", "empty"),
        ("   ", "empty"),
        ("just a string", "top level must be a mapping"),
        ("rules: []", "non-empty list"),
        ("rules: {}", "non-empty list"),
        ("rules:\n  - [1, 2]", "must be a mapping"),
        (
            "rules:\n  - {id: 'a b', languages: [c], severity: ERROR, message: m, pattern: x}",
            "`id`",
        ),
        ("rules:\n  - {id: a, severity: ERROR, message: m, pattern: x}", "`languages`"),
        ("rules:\n  - {id: a, languages: [c], severity: ERROR, pattern: x}", "`message`"),
        (
            "rules:\n  - {id: a, languages: [c], severity: LOUD, message: m, pattern: x}",
            "`severity`",
        ),
        ("rules:\n  - {id: a, languages: [c], severity: ERROR, message: m}", "needs at least one"),
        ("rules:\n  - foo: [", "invalid YAML"),
    ],
)
def test_rejects(content, fragment):
    with pytest.raises(RulesetError) as e:
        validate_ruleset(content)
    assert any(fragment in err for err in e.value.errors), e.value.errors


def test_duplicate_rule_ids_rejected():
    dup = (
        "rules:\n"
        "  - {id: a, languages: [c], severity: ERROR, message: m, pattern: x}\n"
        "  - {id: a, languages: [c], severity: ERROR, message: m, pattern: y}\n"
    )
    with pytest.raises(RulesetError) as e:
        validate_ruleset(dup)
    assert any("duplicate id" in err for err in e.value.errors)


def test_reports_every_error_not_just_the_first():
    """The editor shows a list; one-error-per-save is a miserable loop."""
    bad = "rules:\n  - {id: 'bad id', languages: [], severity: NOPE}\n"
    with pytest.raises(RulesetError) as e:
        validate_ruleset(bad)
    assert len(e.value.errors) >= 4


def test_python_object_tag_refused_by_safe_load():
    """`yaml.safe_load`, never `yaml.load` — a construction tag must not be honored."""
    with pytest.raises(RulesetError) as e:
        validate_ruleset("rules: !!python/object/apply:os.system ['id']\n")
    assert any("invalid YAML" in err for err in e.value.errors)


def test_taint_mode_accepted_without_a_pattern_key():
    taint = (
        "rules:\n"
        "  - id: t\n"
        "    mode: taint\n"
        "    languages: [c]\n"
        "    severity: WARNING\n"
        "    message: source to sink\n"
        "    pattern-sources: [{pattern: 'recv(...)'}]\n"
        "    pattern-sinks: [{pattern: 'memcpy(...)'}]\n"
    )
    assert validate_ruleset(taint)[0] == ["t"]


def test_oversize_rejected():
    with pytest.raises(RulesetError):
        validate_ruleset("rules:\n" + "# pad\n" * (MAX_CONTENT_BYTES // 6 + 10))


def test_too_many_rules_rejected():
    one = "  - {{id: r{}, languages: [c], severity: ERROR, message: m, pattern: x}}\n"
    with pytest.raises(RulesetError) as e:
        validate_ruleset("rules:\n" + "".join(one.format(i) for i in range(501)))
    assert "exceeds the limit" in e.value.errors[0]


def test_oversize_message_rejected():
    big = "rules:\n  - {{id: a, languages: [c], severity: ERROR, message: '{}', pattern: x}}\n"
    with pytest.raises(RulesetError) as e:
        validate_ruleset(big.format("x" * 5000))
    assert any("exceeds" in err for err in e.value.errors)


def test_content_sha256_is_stable_and_content_sensitive():
    assert content_sha256(GOOD) == content_sha256(GOOD)
    assert content_sha256(GOOD) != content_sha256(GOOD + "\n")


def test_rule_messages_extracts_the_text_that_reaches_the_prompt():
    assert rule_messages(GOOD) == [
        "Unbounded copy into a fixed buffer.",
        "Executes a command.",
    ]


def test_rule_messages_never_raises_on_junk():
    assert rule_messages("{[") == []
    assert rule_messages("- a\n- b") == []
