"""Stage 3.2: VR reachability — runs only on suspicious findings."""

from __future__ import annotations

from keystone_engine.results import VRFinding
from keystone_engine.signatures.reachability import assess_reachability


class StubAgent:
    calls = 0

    def __call__(self, finding_message, function_code, function_name):
        StubAgent.calls += 1

        class Pred:
            reachable = "yes"
            entry_path = "ioctl_handler -> parse_header"
            confidence = "medium"

        return Pred()


def test_only_suspicious_findings_are_assessed():
    StubAgent.calls = 0
    findings = [
        VRFinding(rule="r", file="a.c", classification="true_positive"),
        VRFinding(rule="r", file="b.c", classification="false_positive"),
        VRFinding(rule="r", file="c.c", classification="needs_review"),
    ]
    out = assess_reachability(findings, lambda f: "code", StubAgent())
    # true_positive + needs_review assessed; false_positive skipped
    assert StubAgent.calls == 2
    assert out[0].reachable == "yes" and out[0].entry_path.startswith("ioctl")
    assert out[1].reachable is None  # untouched
    assert out[2].reachable == "yes" and out[2].confidence == "medium"
