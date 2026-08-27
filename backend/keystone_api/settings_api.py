"""System settings (admin-only): LLM endpoint + default model + semgrep config.

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
    semgrep_config: dict | None = None


class TestConnectionRequest(BaseModel):
    llm_endpoint_url: str | None = Field(default=None, max_length=255)


def _public(row) -> dict:  # type: ignore[no-untyped-def]
    return {
        "llm_endpoint_url": row.llm_endpoint_url,
        "default_model": row.default_model,
        "semgrep_config": row.semgrep_config,
        "updated_by": row.updated_by,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        # whether a deployment key is configured — never the key itself
        "llm_key_configured": bool(get_settings().llm_api_key),
    }


def probe_llm(url: str, api_key: str, timeout: float = 5.0) -> dict:
    """Live reachability probe against an OpenAI-compatible endpoint's /models.
    Returns {ok, models?|error}. Isolated so tests can monkeypatch it."""
    endpoint = url.rstrip("/") + "/models"
    req = urllib.request.Request(endpoint, headers={"Authorization": f"Bearer {api_key}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (admin-supplied URL)
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
    fields["updated_by"] = g.principal.user.id
    row = update_settings(db, **fields)
    audit(db, g.principal, "settings.update", "system_settings", 1, {k: v for k, v in fields.items() if k != "updated_by"})
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
    url = body.llm_endpoint_url or row.llm_endpoint_url
    if not url:
        return jsonify(ok=False, error="no_endpoint_configured"), 400
    return jsonify(probe_llm(url, get_settings().llm_api_key))
