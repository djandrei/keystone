"""require_auth decorator — resolves a Bearer access JWT into a Principal.

API-token resolution (personal access tokens) is layered on in M1.5.
"""
from __future__ import annotations

from functools import wraps

import jwt
from flask import g, request

from ..context import get_db
from ..models import Role, User
from .principal import Principal
from .tokens import decode_access_token, user_team_ids


def resolve_principal() -> Principal | None:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:]
    try:
        payload = decode_access_token(token)
    except jwt.PyJWTError:
        return None
    if payload.get("type") != "access":
        return None

    db = get_db()
    user = db.get(User, int(payload["sub"]))
    if user is None or not user.is_active:
        return None
    return Principal(user=user, role=Role(payload["role"]), team_ids=user_team_ids(db, user.id))


def require_auth(fn):  # type: ignore[no-untyped-def]
    @wraps(fn)
    def wrapper(*args, **kwargs):  # type: ignore[no-untyped-def]
        principal = resolve_principal()
        if principal is None:
            return {"error": "unauthorized"}, 401
        g.principal = principal
        return fn(*args, **kwargs)

    return wrapper
