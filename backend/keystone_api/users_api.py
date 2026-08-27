"""Admin user management (create/list/update/deactivate)."""

from __future__ import annotations

import secrets

from flask import Blueprint, g, jsonify, request
from pydantic import BaseModel, Field, ValidationError

from .audit import audit
from .context import get_db
from .models import Role, User
from .rbac import require_role
from .security import hash_password

users_bp = Blueprint("users", __name__, url_prefix="/users")

# Light structural check; no MX/deliverability (keeps email-validator out of deps).
_EMAIL_RE = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    email: str = Field(pattern=_EMAIL_RE, max_length=255)
    role: Role = Role.analyst
    password: str | None = Field(default=None, min_length=8, max_length=255)


class UpdateUserRequest(BaseModel):
    role: Role | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=8, max_length=255)


def _public(u: User) -> dict:
    return {
        "id": u.id,
        "username": u.username,
        "email": u.email,
        "role": u.role.value,
        "is_active": u.is_active,
        "created_at": u.created_at.isoformat() if u.created_at else None,
        "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
    }


@users_bp.get("")
@require_role(Role.admin)
def list_users():  # type: ignore[no-untyped-def]
    db = get_db()
    return jsonify([_public(u) for u in db.query(User).order_by(User.id).all()])


@users_bp.post("")
@require_role(Role.admin)
def create_user():  # type: ignore[no-untyped-def]
    try:
        body = CreateUserRequest.model_validate(request.get_json(silent=True) or {})
    except ValidationError as e:
        return jsonify(error="invalid_request", detail=e.errors()), 400
    db = get_db()
    if db.query(User).filter_by(username=body.username).first():
        return jsonify(error="username_taken"), 409
    if db.query(User).filter_by(email=body.email).first():
        return jsonify(error="email_taken"), 409

    temp = body.password or secrets.token_urlsafe(12)
    user = User(
        username=body.username,
        email=body.email,
        password_hash=hash_password(temp),
        role=body.role,
    )
    db.add(user)
    db.flush()
    audit(
        db,
        g.principal,
        "user.create",
        "user",
        user.id,
        {"username": user.username, "role": user.role.value},
    )
    db.commit()
    # temp password returned ONCE when the admin didn't set one
    resp = _public(user)
    if body.password is None:
        resp["temp_password"] = temp
    return jsonify(resp), 201


@users_bp.get("/<int:user_id>")
@require_role(Role.admin)
def get_user(user_id: int):  # type: ignore[no-untyped-def]
    db = get_db()
    user = db.get(User, user_id)
    if user is None:
        return jsonify(error="not_found"), 404
    return jsonify(_public(user))


@users_bp.patch("/<int:user_id>")
@require_role(Role.admin)
def update_user(user_id: int):  # type: ignore[no-untyped-def]
    try:
        body = UpdateUserRequest.model_validate(request.get_json(silent=True) or {})
    except ValidationError as e:
        return jsonify(error="invalid_request", detail=e.errors()), 400
    db = get_db()
    user = db.get(User, user_id)
    if user is None:
        return jsonify(error="not_found"), 404

    changed: dict = {}
    if body.role is not None:
        user.role = body.role
        changed["role"] = body.role.value
    if body.is_active is not None:
        user.is_active = body.is_active
        changed["is_active"] = body.is_active
    if body.password is not None:
        user.password_hash = hash_password(body.password)
        changed["password"] = "reset"
    if changed:
        audit(db, g.principal, "user.update", "user", user.id, changed)
    db.commit()
    return jsonify(_public(user))


@users_bp.delete("/<int:user_id>")
@require_role(Role.admin)
def deactivate_user(user_id: int):  # type: ignore[no-untyped-def]
    db = get_db()
    user = db.get(User, user_id)
    if user is None:
        return jsonify(error="not_found"), 404
    if user.id == g.principal.user.id:
        return jsonify(error="cannot_deactivate_self"), 400
    user.is_active = False
    audit(db, g.principal, "user.deactivate", "user", user.id)
    db.commit()
    return jsonify(status="ok")
