"""Resilience for LLM calls: re-sample on adapter parse failures, then fail clean.

Small models (e.g. MiniMax) intermittently emit malformed tool-call JSON that
DSPy surfaces as `AdapterParseError`. A single re-sample usually clears it; an
optional adapter fallback (e.g. force JSONAdapter) is the last resort before
giving up."""
from __future__ import annotations

from typing import Callable, TypeVar

T = TypeVar("T")


class LlmParseError(RuntimeError):
    """The LLM produced unparseable output after retries and any fallback."""


def _default_parse_errors() -> tuple[type[Exception], ...]:
    try:
        from dspy.utils.exceptions import AdapterParseError

        return (AdapterParseError,)
    except Exception:  # dspy absent (pure-logic tests) — caller passes explicit types
        return ()


def react_with_retry(
    run: Callable[[], T],
    *,
    retries: int = 2,
    fallback: Callable[[], T] | None = None,
    parse_errors: tuple[type[Exception], ...] | None = None,
    on_retry: Callable[[int, Exception], None] | None = None,
) -> T:
    """Call `run`; on a parse error re-sample up to `retries` times, then try
    `fallback` once, then raise `LlmParseError`. Non-parse errors propagate
    immediately."""
    errors = parse_errors if parse_errors is not None else _default_parse_errors()
    last: Exception | None = None
    for attempt in range(retries + 1):
        try:
            return run()
        except errors as e:  # type: ignore[misc]
            last = e
            if on_retry:
                on_retry(attempt, e)
    if fallback is not None:
        try:
            return fallback()
        except errors as e:  # type: ignore[misc]
            last = e
    raise LlmParseError(f"unparseable LLM output after {retries + 1} attempts") from last
