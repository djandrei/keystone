"""VR triage: classify each Semgrep finding (with the decompiled code + rule) into
true_positive / false_positive / needs_review, with a risk level and a CWE.

A ChainOfThought over TriageSignature; the per-finding loop honors a budget cap so
a noisy scan can't blow the LLM budget."""
from __future__ import annotations

from typing import Any, Callable

from keystone_engine.results import VRFinding


def _triage_signature() -> Any:
    import dspy

    class TriageSignature(dspy.Signature):
        """Classify a static-analysis finding using the decompiled code it points
        at. Be skeptical: most Semgrep hits on decompiled code are false positives.
        Assign a CWE when the finding is a real weakness."""

        finding_message: str = dspy.InputField(desc="The Semgrep finding message")
        code: str = dspy.InputField(desc="Decompiled C of the function the finding is in")
        rule: str = dspy.InputField(desc="The Semgrep rule id that fired")
        classification: str = dspy.OutputField(desc="One of: true_positive, false_positive, needs_review")
        risk_level: str = dspy.OutputField(desc="One of: critical, high, medium, low, informational")
        cwe_id: str = dspy.OutputField(desc="CWE id like CWE-190, or empty if not applicable")
        reasoning: str = dspy.OutputField(desc="Concise justification grounded in the code")

    return TriageSignature


def make_triage_agent() -> Any:
    import dspy

    return dspy.ChainOfThought(_triage_signature())


CodeLookup = Callable[[VRFinding], str]


def triage_findings(
    findings: list[VRFinding],
    code_lookup: CodeLookup,
    agent: Any,
    *,
    budget: int | None = None,
) -> list[VRFinding]:
    """Triage each finding (up to `budget`), returning copies annotated with
    classification / risk_level / cwe_id / reasoning."""
    results: list[VRFinding] = []
    for i, f in enumerate(findings):
        if budget is not None and i >= budget:
            break
        pred = agent(finding_message=f.semgrep_message or "", code=code_lookup(f), rule=f.rule or "")
        cwe = getattr(pred, "cwe_id", None) or None
        results.append(
            f.model_copy(
                update={
                    "classification": getattr(pred, "classification", None),
                    "risk_level": getattr(pred, "risk_level", None),
                    "cwe_id": cwe,
                    "reasoning": getattr(pred, "reasoning", None),
                }
            )
        )
    return results
