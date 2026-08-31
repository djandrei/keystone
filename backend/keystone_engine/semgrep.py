"""VR stage 0: decompile-to-disk (cached by sha256) + Semgrep + parsed findings.

The Semgrep invocation is injectable so unit tests run without the semgrep binary
or rule packs; the default runner shells out to `semgrep --json`. Findings are
grouped by rule class so the VR pipeline can pick a class to focus on."""

from __future__ import annotations

import json
import subprocess
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path

from keystone_engine.mcp import GhidraMcpClient
from keystone_engine.results import VRFinding
from keystone_engine.rulesets import rule_set_version_of

SemgrepRunner = Callable[[str, list[str]], dict]


def decompile_program_to_dir(
    client: GhidraMcpClient, program: str, sha256: str, base_dir: str | Path
) -> Path:
    """Decompile every real function to `{base_dir}/{sha256}/{fn}.c` in one batched
    call. Cached: a `.complete` marker short-circuits re-decompilation."""
    target = Path(base_dir) / sha256
    if (target / ".complete").exists():
        return target
    target.mkdir(parents=True, exist_ok=True)

    fns = client.list_functions(program, limit=5000).get("functions", [])
    names = [
        f["name"]
        for f in fns
        if not f.get("is_thunk") and not f.get("is_external") and f.get("name")
    ]
    if names:
        resp = client.decompile_function(program, names if len(names) > 1 else names[0])
        rows = resp.get("results") or [{"target": names[0], "c": resp.get("c", "")}]
        for r in rows:
            code = r.get("c") or ""
            (target / f"{_safe(r['target'])}.c").write_text(code)
    (target / ".complete").touch()
    return target


def _safe(name: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in name) or "fn"


# Per-rule-per-file cap. A `pattern-regex` can backtrack catastrophically and no
# validator can reliably spot it beforehand; a rule that times out 3 times is
# dropped, so one bad pattern degrades the scan instead of hanging the worker.
RULE_TIMEOUT_SECONDS = 30
RULE_TIMEOUT_THRESHOLD = 3


def _default_semgrep_runner(target_dir: str, configs: list[str]) -> dict:
    cmd = [
        "semgrep",
        "--json",
        "--quiet",
        "--timeout",
        str(RULE_TIMEOUT_SECONDS),
        "--timeout-threshold",
        str(RULE_TIMEOUT_THRESHOLD),
    ]
    for config in configs:
        cmd += ["--config", config]
    cmd.append(target_dir)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    return json.loads(proc.stdout or "{}")


def rule_class(check_id: str) -> str:
    """The rule's class — its leaf segment (e.g. rules.c.integer-overflow ->
    integer-overflow), used to group and to steer the VR run."""
    for sep in (".", "/"):
        if sep in check_id:
            check_id = check_id.rsplit(sep, 1)[-1]
    return check_id or "unknown"


def parse_semgrep(raw: dict) -> list[VRFinding]:
    findings: list[VRFinding] = []
    for r in raw.get("results", []):
        start = r.get("start", {})
        extra = r.get("extra", {})
        check_id = r.get("check_id")
        findings.append(
            VRFinding(
                rule=check_id,
                file=r.get("path"),
                line=start.get("line"),
                semgrep_message=extra.get("message"),
                # The rule's own declared severity — the only signal the engine has
                # about how much a class is worth spending LLM budget on.
                severity=extra.get("severity"),
                # None unless the rule came through `rulesets.materialize`.
                rule_set_version_id=rule_set_version_of(check_id),
            )
        )
    return findings


def run_semgrep(
    target_dir: str | Path,
    configs: str | list[str],
    *,
    runner: SemgrepRunner | None = None,
) -> list[VRFinding]:
    """Scan `target_dir` with one or more `--config` sources. A bare string is
    accepted so the legacy single-ruleset path (and its callers) still work."""
    runner = runner or _default_semgrep_runner
    raw = runner(str(target_dir), [configs] if isinstance(configs, str) else list(configs))
    return parse_semgrep(raw)


def group_by_rule_class(findings: list[VRFinding]) -> dict[str, list[VRFinding]]:
    groups: dict[str, list[VRFinding]] = defaultdict(list)
    for f in findings:
        groups[rule_class(f.rule or "unknown")].append(f)
    return dict(groups)


# Semgrep's declared severities, ranked. Anything unrecognized sorts lowest.
SEVERITY_RANK: dict[str, int] = {"ERROR": 3, "WARNING": 2, "INFO": 1}


def class_severity(findings: list[VRFinding]) -> int:
    """The highest severity any rule in this class declared."""
    return max((SEVERITY_RANK.get((f.severity or "").upper(), 0) for f in findings), default=0)


def rank_rule_classes(groups: dict[str, list[VRFinding]]) -> list[str]:
    """Rule classes worth triaging first: by highest declared severity, then by
    volume.

    Ranking by count alone lets the noisiest rules win, which is wrong once broad
    recon rules are in the library — on a 114-function decompiled corpus, `typos`
    and `bad-words` (both INFO) outnumbered `integer-truncation` (WARNING, and the
    actual CVE class) by ten to one. Severity is a property of the rule its author
    declared, so it is the honest tiebreaker the engine has.
    """
    return sorted(
        groups,
        key=lambda k: (class_severity(groups[k]), len(groups[k]), k),
        reverse=True,
    )


def pick_rule_class(groups: dict[str, list[VRFinding]]) -> str | None:
    """The class to triage when nobody chooses one."""
    ranked = rank_rule_classes(groups)
    return ranked[0] if ranked else None


def rule_class_summary(groups: dict[str, list[VRFinding]]) -> list[dict]:
    """Per-class `{rule, count, severity}` in ranked order — what the interactive
    picker is shown, so the human sees the same ordering the auto-pick would use."""
    inverse = {v: k for k, v in SEVERITY_RANK.items()}
    return [
        {
            "rule": name,
            "count": len(groups[name]),
            "severity": inverse.get(class_severity(groups[name])),
        }
        for name in rank_rule_classes(groups)
    ]
