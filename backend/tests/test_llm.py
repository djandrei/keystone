"""Stage 2.2: LM factory, retry wrapper, and fake-LM determinism."""

from __future__ import annotations

import pytest

from keystone_engine.llm import LlmParseError, make_lm, react_with_retry


class FakeParse(Exception):
    pass


def test_retry_succeeds_after_parse_error():
    calls = {"n": 0}

    def run():
        calls["n"] += 1
        if calls["n"] < 2:
            raise FakeParse("bad json")
        return "ok"

    assert react_with_retry(run, retries=2, parse_errors=(FakeParse,)) == "ok"
    assert calls["n"] == 2


def test_retry_gives_up_cleanly():
    def run():
        raise FakeParse("always bad")

    seen: list[int] = []
    with pytest.raises(LlmParseError):
        react_with_retry(
            run, retries=2, parse_errors=(FakeParse,), on_retry=lambda a, e: seen.append(a)
        )
    assert seen == [0, 1, 2]  # every attempt reported


def test_fallback_used_after_retries():
    def run():
        raise FakeParse("bad")

    assert (
        react_with_retry(run, retries=1, parse_errors=(FakeParse,), fallback=lambda: "fell-back")
        == "fell-back"
    )


def test_non_parse_error_propagates_immediately():
    def run():
        raise ValueError("real bug")

    with pytest.raises(ValueError):
        react_with_retry(run, retries=3, parse_errors=(FakeParse,))


def test_make_lm_prefixes_model_and_sets_api_base():
    lm = make_lm("https://llm.example/api", "qwen/qwen3-8b", "secret", cache=False)
    assert lm.model == "openai/qwen/qwen3-8b"
    assert lm.kwargs["api_base"] == "https://llm.example/api"
    # already-prefixed model isn't double-prefixed
    assert make_lm("https://x", "openai/gpt-oss-20b", "k").model == "openai/gpt-oss-20b"


def test_fake_lm_is_deterministic():
    import dspy

    from keystone_engine.llm.fake import fake_lm

    dspy.configure(lm=fake_lm([{"answer": "42"}]))
    out = dspy.Predict("question -> answer")(question="what is it?")
    assert out.answer == "42"


def test_resolve_lm_target_openai_and_anthropic():
    from keystone_engine.llm.lm import resolve_lm_target

    # OpenAI-compatible: openai/ prefix, api_base verbatim
    assert resolve_lm_target("https://llm.example/api", "qwen/qwen3-8b") == (
        "openai/qwen/qwen3-8b",
        "https://llm.example/api",
    )
    # Anthropic-compatible (MiniMax): anthropic/ prefix, api_base -> /messages
    assert resolve_lm_target("https://api.minimax.io/anthropic/v1", "MiniMax-M3") == (
        "anthropic/MiniMax-M3",
        "https://api.minimax.io/anthropic/v1/messages",
    )
    # a bare anthropic base still resolves to /v1/messages
    assert resolve_lm_target("https://api.minimax.io/anthropic", "MiniMax-M3")[1] == (
        "https://api.minimax.io/anthropic/v1/messages"
    )
    # an explicit provider prefix on the model wins over inference
    assert resolve_lm_target("https://api.minimax.io/anthropic/v1", "openai/foo")[0] == "openai/foo"


def test_make_lm_anthropic_endpoint():
    lm = make_lm("https://api.minimax.io/anthropic/v1", "MiniMax-M3", "k", cache=False)
    assert lm.model == "anthropic/MiniMax-M3"
    assert lm.kwargs["api_base"] == "https://api.minimax.io/anthropic/v1/messages"
