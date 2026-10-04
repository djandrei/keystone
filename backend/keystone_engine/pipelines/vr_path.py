"""The VR analysis path: decompile -> Semgrep -> rule pick -> triage -> reachability
-> vulnerability report. Emits ProgressEvents per Step and returns
(findings, Report), mirroring re_path.run.

Agents and the Semgrep runner are injectable so it tests with fakes."""

from __future__ import annotations

import logging
import tempfile
from collections.abc import Generator
from pathlib import Path
from typing import Any

from keystone_engine.events import EventType, ProgressEvent
from keystone_engine.mcp import GhidraMcpClient
from keystone_engine.pipelines.re_path import BinaryRef, _Seq
from keystone_engine.results import Report, VRFinding
from keystone_engine.security import detect_injection
from keystone_engine.semgrep import (
    decompile_program_to_dir,
    group_by_rule_class,
    pick_rule_class,
    rule_class_summary,
    run_semgrep,
)
from keystone_engine.signatures.naming import (
    NamedFunction,
    make_naming_agent,
    name_functions,
)
from keystone_engine.signatures.reachability import assess_reachability, make_reachability_agent
from keystone_engine.signatures.triage import make_triage_agent, triage_findings

log = logging.getLogger("keystone.vr")


def _code_lookup(finding: VRFinding) -> str:
    if finding.file and Path(finding.file).exists():
        return Path(finding.file).read_text()
    return ""


# A pathological rule class could match hundreds of functions; bound the cost and
# say what was skipped rather than silently truncating.
FUNCTION_NAMING_MAX = 50


def _name_finding_functions(
    client: GhidraMcpClient,
    program: str,
    decompiled_dir: Path,
    findings: list[VRFinding],
    agent: Any | None,
    reserved: set[str] | None,
) -> list[NamedFunction]:
    """Friendly names for the functions the triaged findings sit in.

    `VRFinding.file` is `{_safe(function_name)}.c`, so the function is the file
    stem. Addresses come from `list_functions`; a stem that matches no function —
    or a function with no address — is skipped, since a name is stored against the
    address.
    """
    stems: list[str] = []
    for f in findings:
        if f.file:
            stem = Path(f.file).stem
            if stem not in stems:
                stems.append(stem)
    if not stems:
        return []

    if len(stems) > FUNCTION_NAMING_MAX:
        log.info(
            "naming the first %d of %d functions with findings; %d skipped",
            FUNCTION_NAMING_MAX,
            len(stems),
            len(stems) - FUNCTION_NAMING_MAX,
        )
        stems = stems[:FUNCTION_NAMING_MAX]

    addresses = {
        f["name"]: f.get("address")
        for f in client.list_functions(program, limit=5000).get("functions", [])
        if f.get("name")
    }
    candidates, code_of = [], {}
    for stem in stems:
        if not addresses.get(stem):
            continue
        candidates.append(NamedFunction(original_name=stem, address=addresses[stem]))
        src = Path(decompiled_dir) / f"{stem}.c"
        code_of[stem] = src.read_text() if src.exists() else ""
    if not candidates:
        return []
    return name_functions(candidates, code_of, agent or make_naming_agent(), reserved=reserved)


def assemble_vr_report(
    binary: BinaryRef, findings: list[VRFinding], rule_class: str | None
) -> Report:
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
    semgrep_config: str | list[str] = "auto",
    semgrep_runner: Any | None = None,
    triage_agent: Any | None = None,
    reachability_agent: Any | None = None,
    naming_agent: Any | None = None,
    reserved_names: set[str] | None = None,
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
    summary = rule_class_summary(groups)
    # The class to use when nobody picks one: highest declared severity first, not
    # the largest bucket — see `semgrep.rank_rule_classes`.
    auto = pick_rule_class(groups)

    if rule is not None:
        chosen = rule
    elif rule_resolver is not None and groups:
        # Pause for an interactive selection. The resolver only waits for a human;
        # deciding the fallback is this pipeline's job, so a timeout lands on the
        # same ranked default an unattended run would have used.
        yield ProgressEvent(
            type=EventType.needs_input,
            seq=seq.next(),
            step="rule_pick",
            data={"classes": counts, "class_summary": summary, "auto": auto},
        )
        chosen = rule_resolver(counts) or auto
    else:
        chosen = auto
    selected = groups.get(chosen, []) if chosen else []
    yield ProgressEvent.step_finish("rule_pick", seq.next(), rule=chosen, selected=len(selected))

    # Screen the selected findings' decompiled code for injection before it reaches
    # the triage/reachability agents (which sanitize + fence it internally).
    injection = detect_injection("\n".join(_code_lookup(f) for f in selected))
    yield ProgressEvent.security(injection.to_dict(), seq.next())

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

    # Name only the functions the analyst is actually triaging. VR decompiles
    # EVERY function — real binaries run to thousands of them — so naming the
    # lot is neither affordable nor useful. The findings already point at the
    # interesting ones.
    yield ProgressEvent.step_start("name_functions", seq.next())
    named = _name_finding_functions(
        client, binary.program, target, assessed, naming_agent, reserved_names
    )
    yield ProgressEvent.step_finish(
        "name_functions",
        seq.next(),
        named=sum(1 for n in named if n.suggested_name),
        total=len(named),
    )

    report = assemble_vr_report(binary, assessed, chosen)
    yield ProgressEvent(
        type=EventType.done, seq=seq.next(), step="done", data={"findings": len(assessed)}
    )
    return assessed, report, named
