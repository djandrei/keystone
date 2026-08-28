"""Resolve the LM targets for an analysis (analysis model + optional triage model).

Two-model cascade: a cheap model triages the high-volume VR findings, the capable
default model does the deep work. The triage endpoint/key fall back to the analysis
ones, so the common case is just a cheaper model name on the same provider."""

from __future__ import annotations

from .config import Settings
from .models import SystemSettings


def resolve_triage_target(
    sysset: SystemSettings, settings: Settings
) -> tuple[str, str, str] | None:
    """Return (endpoint, model, key) for the VR triage LM, or None to reuse the
    analysis model. A blank triage_model — or no endpoint anywhere — means None."""
    model = (sysset.triage_model or "").strip()
    if not model:
        return None
    endpoint = (sysset.triage_endpoint_url or sysset.llm_endpoint_url or "").strip()
    if not endpoint:
        return None
    key = settings.triage_api_key or settings.llm_api_key
    return endpoint, model, key
