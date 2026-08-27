"""Team management + membership.

Team creation is admin-only. Membership can be managed by an admin or by a
`lead` of that specific team. Listing/reading is team-scoped for non-admins.
"""
from __future__ import annotations

from flask import Blueprint, g, jsonify, request
from pydantic import BaseModel, Field, ValidationError

from .audit import audit
from .context import get_db
from .models import Role, Team, TeamMember, TeamRole, User
from .auth.deps import require_auth
from .rbac import can_access_team, is_team_lead, require_role

teams_bp = Blueprint("teams", __name__, url_prefix="/teams")


class CreateTeamRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)


class AddMemberRequest(BaseModel):
    user_id: int
    team_role: TeamRole = TeamRole.member


def _team_public(team: Team) -> dict:
    return {
        "id": team.id,
        "name": team.name,
        "created_at": team.created_at.isoformat() if team.created_at else None,
        "created_by": team.created_by,
    }


def _member_public(m: TeamMember) -> dict:
    return {
        "user_id": m.user_id,
        "username": m.user.username,
        "team_role": m.team_role.value,
        "added_at": m.added_at.isoformat() if m.added_at else None,
    }


@teams_bp.get("")
@require_auth
def list_teams():  # type: ignore[no-untyped-def]
    db = get_db()
    p = g.principal
    q = db.query(Team).order_by(Team.id)
    if not p.is_admin:
        q = q.filter(Team.id.in_(p.team_ids or [-1]))
    return jsonify([_team_public(t) for t in q.all()])


@teams_bp.post("")
@require_role(Role.admin)
def create_team():  # type: ignore[no-untyped-def]
    try:
        body = CreateTeamRequest.model_validate(request.get_json(silent=True) or {})
    except ValidationError as e:
        return jsonify(error="invalid_request", detail=e.errors()), 400
    db = get_db()
    if db.query(Team).filter_by(name=body.name).first():
        return jsonify(error="name_taken"), 409
    team = Team(name=body.name, created_by=g.principal.user.id)
    db.add(team)
    db.flush()
    audit(db, g.principal, "team.create", "team", team.id, {"name": team.name})
    db.commit()
    return jsonify(_team_public(team)), 201


@teams_bp.get("/<int:team_id>")
@require_auth
def get_team(team_id: int):  # type: ignore[no-untyped-def]
    db = get_db()
    team = db.get(Team, team_id)
    if team is None:
        return jsonify(error="not_found"), 404
    if not can_access_team(g.principal, team_id):
        return jsonify(error="forbidden"), 403
    members = db.query(TeamMember).filter_by(team_id=team_id).all()
    return jsonify(**_team_public(team), members=[_member_public(m) for m in members])


@teams_bp.post("/<int:team_id>/members")
@require_auth
def add_member(team_id: int):  # type: ignore[no-untyped-def]
    db = get_db()
    team = db.get(Team, team_id)
    if team is None:
        return jsonify(error="not_found"), 404
    if not is_team_lead(db, g.principal, team_id):
        return jsonify(error="forbidden"), 403
    try:
        body = AddMemberRequest.model_validate(request.get_json(silent=True) or {})
    except ValidationError as e:
        return jsonify(error="invalid_request", detail=e.errors()), 400
    if db.get(User, body.user_id) is None:
        return jsonify(error="user_not_found"), 404
    if db.get(TeamMember, (team_id, body.user_id)) is not None:
        return jsonify(error="already_member"), 409
    db.add(TeamMember(team_id=team_id, user_id=body.user_id, team_role=body.team_role))
    audit(db, g.principal, "team.member_add", "team", team_id, {"user_id": body.user_id, "team_role": body.team_role.value})
    db.commit()
    return jsonify(status="ok"), 201


@teams_bp.delete("/<int:team_id>/members/<int:user_id>")
@require_auth
def remove_member(team_id: int, user_id: int):  # type: ignore[no-untyped-def]
    db = get_db()
    if db.get(Team, team_id) is None:
        return jsonify(error="not_found"), 404
    if not is_team_lead(db, g.principal, team_id):
        return jsonify(error="forbidden"), 403
    m = db.get(TeamMember, (team_id, user_id))
    if m is None:
        return jsonify(error="not_found"), 404
    db.delete(m)
    audit(db, g.principal, "team.member_remove", "team", team_id, {"user_id": user_id})
    db.commit()
    return jsonify(status="ok")
