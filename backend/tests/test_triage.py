"""Stage 3.1: VR triage — per-finding classification with CWE, budget cap."""

from __future__ import annotations

from keystone_engine.results import VRFinding
from keystone_engine.signatures.triage import make_triage_agent, triage_findings


class StubAgent:
    """Returns a canned triage per finding, echoing the rule for variety."""

    def __call__(self, finding_message, code, rule):
        class Pred:
            classification = "true_positive" if "overflow" in rule else "false_positive"
            risk_level = "high"
            cwe_id = "CWE-190"
            reasoning = f"Based on {rule}"

        return Pred()


FINDINGS = [
    VRFinding(rule="rules.integer-overflow", file="a.c", line=3, semgrep_message="overflow"),
    VRFinding(rule="rules.format-string", file="b.c", line=9, semgrep_message="fmt"),
    VRFinding(rule="rules.integer-overflow", file="c.c", line=1, semgrep_message="overflow"),
]


def test_triage_populates_classification_and_cwe():
    out = triage_findings(FINDINGS, lambda f: "int x;", StubAgent())
    assert len(out) == 3
    assert out[0].classification == "true_positive" and out[0].cwe_id == "CWE-190"
    assert out[1].classification == "false_positive"
    assert all(f.reasoning for f in out)


def test_budget_cap_limits_triage():
    out = triage_findings(FINDINGS, lambda f: "x", StubAgent(), budget=2)
    assert len(out) == 2


def test_triage_signature_runs_with_fake_lm():
    import dspy

    from keystone_engine.llm.fake import fake_lm

    dspy.configure(
        lm=fake_lm(
            [
                {
                    "reasoning": "unchecked length feeds memcpy",
                    "classification": "true_positive",
                    "risk_level": "high",
                    "cwe_id": "CWE-190",
                }
            ]
        )
    )
    agent = make_triage_agent()
    out = triage_findings(FINDINGS[:1], lambda f: "memcpy(b,s,n)", agent)
    assert out[0].classification == "true_positive" and out[0].cwe_id == "CWE-190"
