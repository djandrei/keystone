"""Project buckets: named groupings of binaries within a team.

Managed by any analyst/admin who can access the team. The per-team 'Unassigned'
default project is system-owned — it can't be renamed or deleted — and a project
that still holds binaries can't be deleted (move them out first)."""

from __future__ import annotations

from flask import Blueprint, g, jsonify, request
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import func

from .audit import audit
from .auth.deps import require_auth
from .context import get_db
from .models import Binary, Project, Role
from .rbac import can_access_team, require_role

projects_bp = Blueprint("projects", __name__, url_prefix="/projects")


class CreateProjectRequest(BaseModel):
    team_id: int
    name: str = Field(min_length=1, max_length=120)


class RenameProjectRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)


def _public(p: Project, binary_count: int = 0) -> dict:
    return {
        "id": p.id,
        "team_id": p.team_id,
        "name": p.name,
        "is_default": p.is_default,
        "binary_count": binary_count,
        "created_by": p.created_by,
        "created_at": p.created_at.isoformat() if p.created_at else None,
    }


@projects_bp.get("")
@require_auth
def list_projects():  # type: ignore[no-untyped-def]
    db = get_db()
    p = g.principal
    q = db.query(Project)
    team_id = request.args.get("team_id", type=int)
    if team_id is not None:
        if not can_access_team(p, team_id):
            return jsonify(error="forbidden"), 403
        q = q.filter(Project.team_id == team_id)
    elif not p.is_admin:
        q = q.filter(Project.team_id.in_(p.team_ids or [-1]))
    # non-default first (alphabetical), the Unassigned default last
    projects = q.order_by(Project.is_default.asc(), Project.name.asc()).all()
    ids = [pr.id for pr in projects]
    counts = (
        dict(
            db.query(Binary.project_id, func.count(Binary.id))
            .filter(Binary.project_id.in_(ids))
            .group_by(Binary.project_id)
            .all()
        )
        if ids
        else {}
    )
    return jsonify([_public(pr, int(counts.get(pr.id, 0))) for pr in projects])


@projects_bp.post("")
@require_role(Role.admin, Role.analyst)
def create_project():  # type: ignore[no-untyped-def]
    try:
        body = CreateProjectRequest.model_validate(request.get_json(silent=True) or {})
    except ValidationError as e:
        return jsonify(error="invalid_request", detail=e.errors()), 400
    db = get_db()
    if not can_access_team(g.principal, body.team_id):
        return jsonify(error="forbidden"), 403
    if db.query(Project).filter_by(team_id=body.team_id, name=body.name).first():
        return jsonify(error="name_taken"), 409
    proj = Project(team_id=body.team_id, name=body.name, created_by=g.principal.user.id)
    db.add(proj)
    db.flush()
    audit(db, g.principal, "project.create", "project", proj.id, {"name": proj.name})
    db.commit()
    return jsonify(_public(proj)), 201


@projects_bp.patch("/<int:project_id>")
@require_role(Role.admin, Role.analyst)
def rename_project(project_id: int):  # type: ignore[no-untyped-def]
    db = get_db()
    proj = db.get(Project, project_id)
    if proj is None:
        return jsonify(error="not_found"), 404
    if not can_access_team(g.principal, proj.team_id):
        return jsonify(error="forbidden"), 403
    if proj.is_default:
        return jsonify(error="cannot_modify_default"), 400
    try:
        body = RenameProjectRequest.model_validate(request.get_json(silent=True) or {})
    except ValidationError as e:
        return jsonify(error="invalid_request", detail=e.errors()), 400
    clash = (
        db.query(Project)
        .filter(Project.team_id == proj.team_id, Project.name == body.name, Project.id != proj.id)
        .first()
    )
    if clash:
        return jsonify(error="name_taken"), 409
    proj.name = body.name
    audit(db, g.principal, "project.rename", "project", proj.id, {"name": body.name})
    db.commit()
    return jsonify(_public(proj))


@projects_bp.delete("/<int:project_id>")
@require_role(Role.admin, Role.analyst)
def delete_project(project_id: int):  # type: ignore[no-untyped-def]
    db = get_db()
    proj = db.get(Project, project_id)
    if proj is None:
        return jsonify(error="not_found"), 404
    if not can_access_team(g.principal, proj.team_id):
        return jsonify(error="forbidden"), 403
    if proj.is_default:
        return jsonify(error="cannot_delete_default"), 400
    count = int(
        db.query(func.count(Binary.id)).filter(Binary.project_id == project_id).scalar() or 0
    )
    if count:
        return jsonify(error="has_binaries", binaries=count), 409
    db.delete(proj)
    audit(db, g.principal, "project.delete", "project", project_id, {"name": proj.name})
    db.commit()
    return "", 204
