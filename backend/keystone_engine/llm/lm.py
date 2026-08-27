"""Model-agnostic DSPy LM factory.

The engine never reads the DB — the worker pulls the endpoint/model from
`system_settings` and the key from the deployment secret, and passes them here.
The `openai/` prefix routes litellm to any OpenAI-compatible endpoint."""
from __future__ import annotations

from typing import Any


def make_lm(endpoint_url: str, model: str, api_key: str, *, cache: bool = True, **kw: Any) -> Any:
    """Build a `dspy.LM` for an OpenAI-compatible endpoint. `endpoint_url` is used
    verbatim as the API base (include any `/api` suffix the gateway needs)."""
    import dspy

    prefixed = model if model.startswith("openai/") else f"openai/{model}"
    return dspy.LM(prefixed, api_base=endpoint_url.rstrip("/"), api_key=api_key, cache=cache, **kw)


def configure_lm(lm: Any) -> None:
    """Set the process-wide default LM (DSPy modules read it from context)."""
    import dspy

    dspy.configure(lm=lm)
