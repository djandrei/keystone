"""System settings (admin-only): LLM endpoint + default model + the default rule set.

The LLM *key* is a deployment secret (config.llm_api_key) and is never stored in
or returned from the database — only the endpoint URL and default model live in
`system_settings`.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from flask import Blueprint, g, jsonify, request
from pydantic import BaseModel, Field, ValidationError

from .audit import audit
from .config import get_settings
from .context import get_db
from .models import Role
from .rbac import require_role
from .services import get_or_create_settings, update_settings

settings_bp = Blueprint("settings", __name__, url_prefix="/settings")


class UpdateSettingsRequest(BaseModel):
    llm_endpoint_url: str | None = Field(default=None, max_length=255)
    default_model: str | None = Field(default=None, max_length=120)
    triage_model: str | None = Field(default=None, max_length=120)
    triage_endpoint_url: str | None = Field(default=None, max_length=255)
    # The rule set a VR analysis falls back to when the request pins none. Replaces
    # the old free-JSON `semgrep_config`, which nothing ever read.
    default_rule_set_id: int | None = None


class TestConnectionRequest(BaseModel):
    llm_endpoint_url: str | None = Field(default=None, max_length=255)
    target: str = "analysis"  # or "triage"


def _public(row) -> dict:  # type: ignore[no-untyped-def]
    return {
        "llm_endpoint_url": row.llm_endpoint_url,
        "default_model": row.default_model,
        "triage_model": row.triage_model,
        "triage_endpoint_url": row.triage_endpoint_url,
        "default_rule_set_id": row.default_rule_set_id,
        "updated_by": row.updated_by,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        # whether a deployment key is configured — never the key itself
        "llm_key_configured": bool(get_settings().llm_api_key),
        # triage has a key if a triage-specific one is set OR it falls back to the LLM key
        "triage_key_configured": bool(get_settings().triage_api_key or get_settings().llm_api_key),
    }


def _probe_target(url: str, api_key: str) -> tuple[str, dict]:
    """The /models endpoint + auth headers for a provider (OpenAI vs Anthropic)."""
    base = url.rstrip("/")
    endpoint = base + "/models"
    if "anthropic" in base.lower():
        headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01"}
    else:
        headers = {"Authorization": f"Bearer {api_key}"}
    return endpoint, headers


def probe_llm(url: str, api_key: str, timeout: float = 5.0) -> dict:
    """Live reachability probe against the endpoint's /models. Returns
    {ok, models?|error}. Isolated so tests can monkeypatch it."""
    endpoint, headers = _probe_target(url, api_key)
    req = urllib.request.Request(endpoint, headers=headers)
    try:
        with urllib.request.urlopen(
            req, timeout=timeout
        ) as resp:  # noqa: S310 (admin-supplied URL)
            payload = json.loads(resp.read().decode("utf-8"))
        models = [m.get("id") for m in payload.get("data", []) if isinstance(m, dict)]
        return {"ok": True, "models": [m for m in models if m]}
    except urllib.error.HTTPError as e:
        return {"ok": False, "error": f"HTTP {e.code}"}
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        return {"ok": False, "error": str(e)}


@settings_bp.get("")
@require_role(Role.admin)
def get_settings_route():  # type: ignore[no-untyped-def]
    db = get_db()
    row = get_or_create_settings(db)
    db.commit()
    return jsonify(_public(row))


@settings_bp.put("")
@require_role(Role.admin)
def put_settings_route():  # type: ignore[no-untyped-def]
    try:
        body = UpdateSettingsRequest.model_validate(request.get_json(silent=True) or {})
    except ValidationError as e:
        return jsonify(error="invalid_request", detail=e.errors()), 400
    db = get_db()
    fields = {k: v for k, v in body.model_dump(exclude_none=True).items()}
    if "default_rule_set_id" in fields:
        from .models import RuleSet

        if db.get(RuleSet, fields["default_rule_set_id"]) is None:
            return jsonify(error="invalid_rule_set", detail="no such rule set"), 400
    fields["updated_by"] = g.principal.user.id
    row = update_settings(db, **fields)
    audit(
        db,
        g.principal,
        "settings.update",
        "system_settings",
        1,
        {k: v for k, v in fields.items() if k != "updated_by"},
    )
    db.commit()
    return jsonify(_public(row))


@settings_bp.post("/test-connection")
@require_role(Role.admin)
def test_connection_route():  # type: ignore[no-untyped-def]
    try:
        body = TestConnectionRequest.model_validate(request.get_json(silent=True) or {})
    except ValidationError as e:
        return jsonify(error="invalid_request", detail=e.errors()), 400
    db = get_db()
    row = get_or_create_settings(db)
    cfg = get_settings()
    if body.target == "triage":
        url = body.llm_endpoint_url or row.triage_endpoint_url or row.llm_endpoint_url
        key = cfg.triage_api_key or cfg.llm_api_key
    else:
        url = body.llm_endpoint_url or row.llm_endpoint_url
        key = cfg.llm_api_key
    if not url:
        return jsonify(ok=False, error="no_endpoint_configured"), 400
    return jsonify(probe_llm(url, key))
