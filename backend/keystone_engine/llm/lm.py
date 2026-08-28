"""Model-agnostic DSPy LM factory.

The engine never reads the DB — the worker pulls the endpoint/model from
`system_settings` and the key from the deployment secret, and passes them here.

Provider is inferred so both wire protocols work from one Settings form:
- OpenAI-compatible endpoints (OpenAI, OpenWebUI, vLLM, ...) -> `openai/<model>`,
  api_base used verbatim; litellm appends `/chat/completions`.
- Anthropic-compatible endpoints (e.g. MiniMax's `.../anthropic/v1`) -> `anthropic/
  <model>`, and litellm 1.98 treats api_base as the COMPLETE URL, so we point it at
  the `/messages` endpoint.
A model id that already carries a known provider prefix wins over inference."""

from __future__ import annotations

from typing import Any

_KNOWN_PROVIDERS = (
    "openai/",
    "anthropic/",
    "azure/",
    "gemini/",
    "vertex_ai/",
    "bedrock/",
    "mistral/",
    "groq/",
    "cohere/",
    "ollama/",
)


def _anthropic_api_base(base: str) -> str:
    """litellm-anthropic uses api_base as the full messages URL; normalize to it."""
    if base.endswith("/messages"):
        return base
    if base.endswith("/v1"):
        return base + "/messages"
    return base.rstrip("/") + "/v1/messages"


def resolve_lm_target(endpoint_url: str, model: str) -> tuple[str, str]:
    """Return (litellm_model, api_base) for the endpoint. Pure, so it's testable."""
    base = endpoint_url.rstrip("/")
    if model.startswith(_KNOWN_PROVIDERS):
        provider = model.split("/", 1)[0]
        prefixed = model
    elif "anthropic" in base.lower():
        provider, prefixed = "anthropic", f"anthropic/{model}"
    else:
        provider, prefixed = "openai", f"openai/{model}"
    api_base = _anthropic_api_base(base) if provider == "anthropic" else base
    return prefixed, api_base


def make_lm(endpoint_url: str, model: str, api_key: str, *, cache: bool = True, **kw: Any) -> Any:
    """Build a `dspy.LM` for an OpenAI- or Anthropic-compatible endpoint."""
    import dspy

    prefixed, api_base = resolve_lm_target(endpoint_url, model)
    return dspy.LM(prefixed, api_base=api_base, api_key=api_key, cache=cache, **kw)


def configure_lm(lm: Any) -> None:
    """Set the process-wide default LM (DSPy modules read it from context)."""
    import dspy

    dspy.configure(lm=lm)
