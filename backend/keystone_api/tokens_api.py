"""Self-service personal API token management."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from flask import Blueprint, g, jsonify, request
from pydantic import BaseModel, Field, ValidationError

from .auth.apitokens import create_api_token, list_api_tokens, revoke_api_token
from .auth.deps import require_auth
from .context import get_db
from .ratelimit import rate_limit

tokens_bp = Blueprint("tokens", __name__, url_prefix="/tokens")


class CreateTokenRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    scopes: list[str] | None = None
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)


def _public(t) -> dict:  # type: ignore[no-untyped-def]
    return {
        "id": t.id, "name": t.name, "scopes": t.scopes,
        "expires_at": t.expires_at.isoformat() if t.expires_at else None,
        "created_at": t.created_at.isoformat() if t.created_at else None,
        "last_used_at": t.last_used_at.isoformat() if t.last_used_at else None,
    }


@tokens_bp.get("")
@require_auth
def list_tokens():  # type: ignore[no-untyped-def]
    db = get_db()
    return jsonify([_public(t) for t in list_api_tokens(db, g.principal.user)])


@tokens_bp.post("")
@require_auth
@rate_limit("token", 20, 60)
def create_token():  # type: ignore[no-untyped-def]
    try:
        body = CreateTokenRequest.model_validate(request.get_json(silent=True) or {})
    except ValidationError as e:
        return jsonify(error="invalid_request", detail=e.errors()), 400
    expires_at = (
        datetime.now(timezone.utc) + timedelta(days=body.expires_in_days)
        if body.expires_in_days
        else None
    )
    db = get_db()
    tok, raw = create_api_token(db, g.principal.user, body.name, body.scopes, expires_at)
    db.commit()
    # the token value is shown exactly ONCE
    return jsonify(**_public(tok), token=raw), 201


@tokens_bp.delete("/<int:token_id>")
@require_auth
def revoke_token(token_id: int):  # type: ignore[no-untyped-def]
    db = get_db()
    ok = revoke_api_token(db, g.principal.user, token_id)
    db.commit()
    return (jsonify(status="ok"), 200) if ok else (jsonify(error="not_found"), 404)
