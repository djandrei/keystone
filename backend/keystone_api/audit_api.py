"""Admin audit-trail listing (filter by user/action/target/date, paginated)."""
from __future__ import annotations

from datetime import datetime

from flask import Blueprint, jsonify, request

from .context import get_db
from .models import AuditLog, Role, User
from .rbac import require_role

audit_bp = Blueprint("audit", __name__, url_prefix="/audit")


def _public(row: AuditLog, usernames: dict) -> dict:
    return {
        "id": row.id,
        "user_id": row.user_id,
        "username": usernames.get(row.user_id),
        "action": row.action,
        "target_type": row.target_type,
        "target_id": row.target_id,
        "detail": row.detail,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@audit_bp.get("")
@require_role(Role.admin)
def list_audit():  # type: ignore[no-untyped-def]
    db = get_db()
    q = db.query(AuditLog)

    if (user_id := request.args.get("user_id", type=int)) is not None:
        q = q.filter(AuditLog.user_id == user_id)
    if (action := request.args.get("action")):
        q = q.filter(AuditLog.action.ilike(f"%{action}%"))
    if (target_type := request.args.get("target_type")):
        q = q.filter(AuditLog.target_type == target_type)
    for field, is_from in (("date_from", True), ("date_to", False)):
        raw = request.args.get(field)
        if raw:
            try:
                dt = datetime.fromisoformat(raw)
            except ValueError:
                return jsonify(error=f"invalid_{field}"), 400
            q = q.filter(AuditLog.created_at >= dt if is_from else AuditLog.created_at <= dt)

    total = q.count()
    limit = min(request.args.get("limit", default=50, type=int), 200)
    offset = max(request.args.get("offset", default=0, type=int), 0)
    rows = q.order_by(AuditLog.id.desc()).limit(limit).offset(offset).all()

    ids = {r.user_id for r in rows if r.user_id is not None}
    usernames = {u.id: u.username for u in db.query(User).filter(User.id.in_(ids)).all()} if ids else {}
    return jsonify(items=[_public(r, usernames) for r in rows], total=total, limit=limit, offset=offset)
