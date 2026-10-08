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


def test_the_agent_gets_the_function_name_not_the_decompiled_file_path():
    """VRFinding.file is the path of the decompiled `{function}.c`; the agent's
    `function_name` input must be the function, which is the file's stem."""
    seen: list[str] = []

    class RecordingAgent(StubAgent):
        def __call__(self, finding_message, function_code, function_name):
            seen.append(function_name)
            return super().__call__(finding_message, function_code, function_name)

    findings = [
        VRFinding(
            rule="r",
            file="/tmp/keystone-decompiled/abc/parse_header.c",
            classification="true_positive",
        ),
        VRFinding(rule="r", file=None, classification="needs_review"),
    ]
    assess_reachability(findings, lambda f: "code", RecordingAgent())
    assert seen == ["parse_header", ""]
