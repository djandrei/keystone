"""Deterministic fake LM for unit tests — no network, no real model.

Wraps DSPy's DummyLM so pipeline tests can assert on a fixed event/result shape."""

from __future__ import annotations

from typing import Any


def fake_lm(answers: list[dict[str, Any]] | dict[str, dict[str, Any]], **kw: Any) -> Any:
    """Return a configured DummyLM that replays `answers` for successive calls."""
    from dspy.utils.dummies import DummyLM

    return DummyLM(answers, **kw)
