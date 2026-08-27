"""The VR analysis path: decompile -> Semgrep -> rule pick -> triage -> reachability
-> vulnerability report. Emits ProgressEvents per Step and returns
(findings, Report), mirroring re_path.run.

Agents and the Semgrep runner are injectable so it tests with fakes."""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any, Generator

from keystone_engine.events import EventType, ProgressEvent
from keystone_engine.mcp import GhidraMcpClient
from keystone_engine.pipelines.re_path import BinaryRef, _Seq
from keystone_engine.results import Report, VRFinding
from keystone_engine.semgrep import (
    decompile_program_to_dir,
    group_by_rule_class,
    run_semgrep,
)
from keystone_engine.signatures.reachability import assess_reachability, make_reachability_agent
from keystone_engine.signatures.triage import make_triage_agent, triage_findings


def _code_lookup(finding: VRFinding) -> str:
    if finding.file and Path(finding.file).exists():
        return Path(finding.file).read_text()
    return ""


def assemble_vr_report(binary: BinaryRef, findings: list[VRFinding], rule_class: str | None) -> Report:
    lines = [
        f"# VR Analysis — {binary.filename or binary.program}",
        "",
        f"**Rule class:** {rule_class or 'n/a'}  ·  **Findings:** {len(findings)}",
        "",
    ]
    suspicious = [f for f in findings if f.classification in ("true_positive", "needs_review")]
    lines.append(f"## Suspicious findings ({len(suspicious)})")
    for f in suspicious:
        lines += [
            "",
            f"### {f.rule} — {f.file}:{f.line}",
            f"- **Classification:** {f.classification}  ·  **Risk:** {f.risk_level or '?'}  ·  **CWE:** {f.cwe_id or '—'}",
            f"- **Reachable:** {f.reachable or 'unknown'}  ·  **Confidence:** {f.confidence or '?'}",
            f"- **Entry path:** {f.entry_path or '—'}",
            f"- **Reasoning:** {f.reasoning or '—'}",
        ]
    if not suspicious:
        lines.append("\n_No suspicious findings survived triage._")
    return Report(format="md", content="\n".join(lines) + "\n")


def run(
    binary: BinaryRef,
    client: GhidraMcpClient,
    *,
    rule: str | None = None,
    base_dir: str | None = None,
    semgrep_config: str = "auto",
    semgrep_runner: Any | None = None,
    triage_agent: Any | None = None,
    reachability_agent: Any | None = None,
    rule_resolver: Any | None = None,
    budget: int | None = None,
) -> Generator[ProgressEvent, None, tuple[list[VRFinding], Report]]:
    seq = _Seq()
    base_dir = base_dir or str(Path(tempfile.gettempdir()) / "keystone-decompiled")

    yield ProgressEvent.step_start("decompile", seq.next(), program=binary.program)
    target = decompile_program_to_dir(client, binary.program, binary.sha256, base_dir)
    yield ProgressEvent.step_finish("decompile", seq.next(), dir=str(target))

    yield ProgressEvent.step_start("semgrep", seq.next())
    findings = run_semgrep(target, semgrep_config, runner=semgrep_runner)
    groups = group_by_rule_class(findings)
    yield ProgressEvent.step_finish(
        "semgrep", seq.next(), total=len(findings), classes={k: len(v) for k, v in groups.items()}
    )

    yield ProgressEvent.step_start("rule_pick", seq.next())
    counts = {k: len(v) for k, v in groups.items()}
    if rule is not None:
        chosen = rule
    elif rule_resolver is not None and groups:
        # pause for an interactive rule selection; the resolver blocks until the
        # user answers (or times out to the auto-pick).
        yield ProgressEvent(type=EventType.needs_input, seq=seq.next(), step="rule_pick", data={"classes": counts})
        chosen = rule_resolver(counts)
    else:
        chosen = max(groups, key=lambda k: len(groups[k])) if groups else None
    selected = groups.get(chosen, []) if chosen else []
    yield ProgressEvent.step_finish("rule_pick", seq.next(), rule=chosen, selected=len(selected))

    yield ProgressEvent.step_start("triage", seq.next())
    triage_agent = triage_agent or make_triage_agent()
    triaged = triage_findings(selected, _code_lookup, triage_agent, budget=budget)
    yield ProgressEvent.step_finish("triage", seq.next(), triaged=len(triaged))

    yield ProgressEvent.step_start("reachability", seq.next())
    reachability_agent = reachability_agent or make_reachability_agent(client, binary.program)
    assessed = assess_reachability(triaged, _code_lookup, reachability_agent)
    yield ProgressEvent.step_finish(
        "reachability", seq.next(), assessed=sum(1 for f in assessed if f.reachable)
    )

    report = assemble_vr_report(binary, assessed, chosen)
    yield ProgressEvent(type=EventType.done, seq=seq.next(), step="done", data={"findings": len(assessed)})
    return assessed, report
