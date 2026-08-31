"""Import a vendored third-party Semgrep rule tree as Keystone rule sets.

Currently one source: `semgrep-rules/0xdea/` (see its `UPSTREAM.md`). The tree
there is a faithful copy of the upstream repo; the *grouping* into rule sets lives
here, so re-vendoring stays a clean `diff -r` and the editorial decisions stay in
reviewable code.

Why grouped at all: upstream is used as one `--config rules/c`, which on a real
decompiled corpus means the two recon rules (`typos`, `interesting-api-calls`)
dominate the findings — 41 of 46 hits on the 114-function ksthunk corpus. Splitting
by upstream's own `metadata.vulnerability_class` lets an analyst scan for memory
issues without triaging that noise, and leaves the recon rules available as an
explicit opt-in.

Composition is deterministic (rules sorted by id, `safe_dump` with stable options),
so `content_sha256` is stable: re-seeding an unchanged tree is a no-op, and a
re-vendor that changes a rule appends a new version by itself.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

log = logging.getLogger("keystone.rule_import")

VENDOR_ROOT = Path(__file__).resolve().parent.parent / "semgrep-rules" / "0xdea"

# Rules upstream files under a security class but which, on decompiled code, behave
# as broad recon rather than as vulnerability findings. Pulled out by id so the
# grouping below can stay "upstream's class, minus these".
_RECON_IDS = frozenset(
    {
        "raptor-typos",  # 33 of 46 hits on the ksthunk corpus
        "raptor-interesting-api-calls",  # an attack-surface inventory, not a bug
        "raptor-bad-words",  # upstream files it under rules/noisy/ itself
    }
)


@dataclass(frozen=True)
class RuleGroup:
    """One Keystone rule set composed from a subset of the vendored tree."""

    name: str
    description: str
    # Matched against each rule's metadata.vulnerability_class.
    classes: tuple[str, ...] = ()
    # Rules pulled in by id regardless of their upstream class.
    extra_ids: tuple[str, ...] = ()
    # Rules excluded by id even when their class matches.
    exclude_ids: frozenset[str] = field(default_factory=frozenset)


# Derived from upstream's own `metadata.vulnerability_class`; the deviations are
# named explicitly rather than silently reclassified.
GROUPS: tuple[RuleGroup, ...] = (
    RuleGroup(
        name="0xdea · Memory safety (C/C++)",
        description=(
            "Use-after-free, double free, off-by-one, stack-address return, "
            "unbounded and mismatched copies, integer wraparound feeding a "
            "allocation or copy. The highest-signal group against decompiled code."
        ),
        classes=("Memory Issues",),
    ),
    RuleGroup(
        name="0xdea · Dangerous functions (C/C++)",
        description=(
            "Calls that are unsafe by construction — gets, strcpy/strcat, sprintf, "
            "alloca, scanf, mktemp, ato*, signal, access/stat races. Call-shaped, so "
            "these survive decompilation better than anything type-based."
        ),
        classes=("Dangerous Method or Function",),
        exclude_ids=_RECON_IDS,
    ),
    RuleGroup(
        name="0xdea · Correctness & control flow (C/C++)",
        description=(
            "Missing break or default in a switch, missing return, unchecked scanf, "
            "signed/unsigned conversion, integer truncation, suspicious assert, "
            "unsafe strlen. Bugs that become vulnerabilities in the right context."
        ),
        classes=("Other Security", "Improper Validation"),
        exclude_ids=_RECON_IDS,
    ),
    RuleGroup(
        name="0xdea · Privilege, secrets & crypto (C/C++)",
        description=(
            "setuid/setgid ordering and unchecked returns, memory-address exposure, "
            "incorrect memset for scrubbing, command injection, hard-coded secrets, "
            "weak rand/srand, regex denial of service."
        ),
        classes=(
            "Mishandled Sensitive Information",
            "Improper Authorization",
            "Command Injection",
            "Hard-coded Secrets",
            "Cryptographic Issues",
            "Denial-of-Service (DoS)",
        ),
        exclude_ids=_RECON_IDS,
    ),
    RuleGroup(
        name="0xdea · Recon & noisy (C/C++)",
        description=(
            "High-volume, low-precision by design: an inventory of interesting API "
            "calls, likely typos, and suspicious strings. Useful for orienting on an "
            "unfamiliar binary — expect to triage a lot. Opt in deliberately."
        ),
        extra_ids=tuple(sorted(_RECON_IDS)),
    ),
)


def _vuln_class(rule: dict) -> str:
    vc = (rule.get("metadata") or {}).get("vulnerability_class")
    if isinstance(vc, list):
        return vc[0] if vc else ""
    return vc or ""


def load_vendored_rules(root: Path | None = None) -> list[dict]:
    """Every rule in the vendored tree, as parsed dicts. Order-independent — the
    caller sorts."""
    root = root or VENDOR_ROOT
    rules: list[dict] = []
    for path in sorted((root / "rules").rglob("*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and isinstance(doc.get("rules"), list):
            rules.extend(r for r in doc["rules"] if isinstance(r, dict) and r.get("id"))
    return rules


def select(rules: list[dict], group: RuleGroup) -> list[dict]:
    """The rules belonging to `group`, sorted by id so composition is deterministic."""
    wanted = [
        r
        for r in rules
        if r["id"] not in group.exclude_ids
        and (_vuln_class(r) in group.classes or r["id"] in group.extra_ids)
    ]
    return sorted(wanted, key=lambda r: r["id"])


def compose(rules: list[dict]) -> str:
    """A single Semgrep document from a list of rules. Byte-stable for stable input,
    which is what makes `content_sha256` a meaningful no-op check."""
    return yaml.safe_dump(
        {"rules": rules}, sort_keys=False, allow_unicode=True, default_flow_style=False
    )


def build_groups(root: Path | None = None) -> list[tuple[RuleGroup, str, int]]:
    """`(group, composed_yaml, rule_count)` for every non-empty group.

    Raises nothing on a missing tree — returns an empty list, so a deployment that
    dropped the vendored rules still boots.

    Cached per root: the tree is 50 files that `bootstrap` would otherwise re-parse
    on every call (which the test suite makes a lot of). Call `build_groups.reset()`
    after editing a tree in place.
    """
    return _build_groups(str((root or VENDOR_ROOT).resolve()))


@lru_cache(maxsize=8)
def _build_groups(root_str: str) -> list[tuple[RuleGroup, str, int]]:
    root = Path(root_str)
    if not (root / "rules").is_dir():
        log.warning("vendored rule tree not found at %s — nothing to import", root)
        return []

    rules = load_vendored_rules(root)
    if not rules:
        log.warning("vendored rule tree at %s contains no rules", root)
        return []

    out: list[tuple[RuleGroup, str, int]] = []
    claimed: set[str] = set()
    for group in GROUPS:
        picked = select(rules, group)
        if not picked:
            log.warning("rule group %r matched nothing — skipping", group.name)
            continue
        claimed |= {r["id"] for r in picked}
        out.append((group, compose(picked), len(picked)))

    # A rule upstream adds under a class we do not map would otherwise vanish
    # silently on the next re-vendor. Say so rather than quietly dropping it.
    missed = sorted({r["id"] for r in rules} - claimed)
    if missed:
        log.warning(
            "%d vendored rule(s) match no group and were NOT imported: %s",
            len(missed),
            ", ".join(missed),
        )
    return out


build_groups.reset = _build_groups.cache_clear  # type: ignore[attr-defined]
