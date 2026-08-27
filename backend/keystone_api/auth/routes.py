"""Auth blueprint: login, refresh, logout, me, password."""
from __future__ import annotations

from datetime import datetime, timezone

from flask import Blueprint, g, jsonify, request
from pydantic import ValidationError

from ..context import get_db
from ..ratelimit import rate_limit
from ..models import User
from ..security import hash_password, verify_password
from .deps import require_auth
from .schemas import LoginRequest, LogoutRequest, PasswordChangeRequest, RefreshRequest
from .tokens import (
    create_access_token,
    issue_refresh_token,
    revoke_refresh,
    rotate_refresh,
    user_team_ids,
)

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


def _body(model):  # type: ignore[no-untyped-def]
    try:
        return model.model_validate(request.get_json(silent=True) or {}), None
    except ValidationError as e:
        return None, (jsonify(error="invalid_request", detail=e.errors()), 400)


def _user_public(user: User) -> dict:
    return {"id": user.id, "username": user.username, "email": user.email, "role": user.role.value}


def _tokens(db, user: User) -> dict:
    teams = user_team_ids(db, user.id)
    access = create_access_token(user, teams)
    refresh = issue_refresh_token(db, user, request.headers.get("User-Agent"))
    return {"access_token": access, "refresh_token": refresh, "user": _user_public(user)}


@auth_bp.post("/login")
@rate_limit("login", 30, 60)
def login():  # type: ignore[no-untyped-def]
    data, err = _body(LoginRequest)
    if err:
        return err
    db = get_db()
    user = db.query(User).filter_by(username=data.username).first()
    if user is None or not user.is_active or not verify_password(user.password_hash, data.password):
        return jsonify(error="invalid_credentials"), 401
    user.last_login_at = datetime.now(timezone.utc)
    resp = _tokens(db, user)
    db.commit()
    return jsonify(resp)


@auth_bp.post("/refresh")
def refresh():  # type: ignore[no-untyped-def]
    data, err = _body(RefreshRequest)
    if err:
        return err
    db = get_db()
    result = rotate_refresh(db, data.refresh_token, request.headers.get("User-Agent"))
    if result is None:
        db.rollback()
        return jsonify(error="invalid_refresh_token"), 401
    user, new_refresh = result
    teams = user_team_ids(db, user.id)
    access = create_access_token(user, teams)
    db.commit()
    return jsonify(access_token=access, refresh_token=new_refresh, user=_user_public(user))


@auth_bp.post("/logout")
def logout():  # type: ignore[no-untyped-def]
    data, err = _body(LogoutRequest)
    if err:
        return err
    db = get_db()
    revoke_refresh(db, data.refresh_token)
    db.commit()
    return jsonify(status="ok")


@auth_bp.get("/me")
@require_auth
def me():  # type: ignore[no-untyped-def]
    p = g.principal
    return jsonify(**_user_public(p.user), teams=p.team_ids)


@auth_bp.post("/password")
@require_auth
def change_password():  # type: ignore[no-untyped-def]
    data, err = _body(PasswordChangeRequest)
    if err:
        return err
    db = get_db()
    user = g.principal.user
    if not verify_password(user.password_hash, data.old_password):
        return jsonify(error="invalid_credentials"), 401
    user.password_hash = hash_password(data.new_password)
    db.commit()
    return jsonify(status="ok")
