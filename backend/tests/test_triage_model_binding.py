"""T3: a triage-bound agent uses the triage LM; others use the global LM."""

from __future__ import annotations


def test_set_lm_binds_triage_model_per_agent():
    import dspy
    from dspy.utils.dummies import DummyLM

    from keystone_engine.signatures.triage import make_triage_agent

    dspy.configure(lm=DummyLM([{"reasoning": "r", "answer": "ANALYSIS"}]))
    bound = dspy.ChainOfThought("question -> answer")
    bound.set_lm(DummyLM([{"reasoning": "r", "answer": "TRIAGE"}]))
    # the bound agent uses its own LM...
    assert bound(question="x").answer == "TRIAGE"
    # ...while an unbound one falls through to the global (analysis) LM
    assert dspy.ChainOfThought("question -> answer")(question="x").answer == "ANALYSIS"

    # a triage agent can be built + bound the way the worker does it
    agent = make_triage_agent()
    agent.set_lm(
        DummyLM(
            [
                {
                    "reasoning": "r",
                    "classification": "false_positive",
                    "risk_level": "low",
                    "cwe_id": "",
                    "answer": "",
                }
            ]
        )
    )
    assert agent is not None and hasattr(agent, "set_lm")
