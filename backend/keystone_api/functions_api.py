"""Friendly function names: read them, choose which reach the report, correct them.

Names are stored per binary and never written back into Ghidra — one project holds
every team's programs, so a rename there would cross the team boundary Keystone
enforces in Postgres (docs/function-naming-plan.md §3).

Authorization rides on the analysis and its binary: no new surface. If you can see
the analysis you can read its names; analysts and admins can change them.
"""

from __future__ import annotations

from flask import Blueprint, g, jsonify, request
from pydantic import BaseModel, Field, ValidationError

from .audit import audit
from .auth.deps import require_auth
from .context import get_db
from .models import Analysis, AnalysisFunction, FunctionName, Role
from .rbac import can_access_team, require_role

functions_bp = Blueprint("functions", __name__)


class ToggleRequest(BaseModel):
    include: list[int] = Field(default_factory=list)
    exclude: list[int] = Field(default_factory=list)


class RenameRequest(BaseModel):
    # An empty string clears the suggestion, leaving the original symbol showing.
    suggested_name: str | None = Field(default=None, max_length=255)
    purpose: str | None = Field(default=None, max_length=2000)


def _public(fn: FunctionName, link: AnalysisFunction | None) -> dict:
    return {
        "id": fn.id,
        "address": fn.address,
        "original_name": fn.original_name,
        "suggested_name": fn.suggested_name,
        # What the UI and the report show — never the friendly name alone.
        "display_name": fn.display_name,
        "purpose": fn.purpose,
        "source": fn.source,
        "included": bool(link.included) if link else False,
        "position": link.position if link else 0,
    }


def _analysis_or_404(db, analysis_id: int) -> Analysis | None:
    a = db.get(Analysis, analysis_id)
    if a is None or not can_access_team(g.principal, a.team_id):
        return None
    return a


def _rows(db, analysis_id: int) -> list[tuple[FunctionName, AnalysisFunction]]:
    return (
        db.query(FunctionName, AnalysisFunction)
        .join(AnalysisFunction, AnalysisFunction.function_name_id == FunctionName.id)
        .filter(AnalysisFunction.analysis_id == analysis_id)
        .order_by(AnalysisFunction.position, FunctionName.address)
        .all()
    )


@functions_bp.get("/analyses/<int:analysis_id>/functions")
@require_auth
def list_functions(analysis_id: int):  # type: ignore[no-untyped-def]
    db = get_db()
    a = _analysis_or_404(db, analysis_id)
    if a is None:
        return jsonify(error="not_found"), 404
    return jsonify([_public(fn, link) for fn, link in _rows(db, analysis_id)])


@functions_bp.patch("/analyses/<int:analysis_id>/functions")
@require_role(Role.admin, Role.analyst)
def toggle_functions(analysis_id: int):  # type: ignore[no-untyped-def]
    """Bulk include/exclude. The report re-renders from this on the next read —
    there is no stored artifact to regenerate (docs/function-naming-plan.md §8)."""
    db = get_db()
    a = _analysis_or_404(db, analysis_id)
    if a is None:
        return jsonify(error="not_found"), 404
    try:
        body = ToggleRequest.model_validate(request.get_json(silent=True) or {})
    except ValidationError as e:
        return jsonify(error="invalid_request", detail=e.errors()), 400

    wanted = {**{i: True for i in body.include}, **{i: False for i in body.exclude}}
    if not wanted:
        return jsonify(error="invalid_request", detail="include or exclude required"), 400

    links = {
        link.function_name_id: link
        for link in db.query(AnalysisFunction).filter_by(analysis_id=analysis_id).all()
    }
    unknown = sorted(set(wanted) - set(links))
    if unknown:
        return jsonify(error="unknown_function", ids=unknown), 400
    for fid, included in wanted.items():
        links[fid].included = included

    audit(
        db,
        g.principal,
        "function.include",
        "analysis",
        analysis_id,
        {"include": body.include, "exclude": body.exclude},
    )
    db.commit()
    return jsonify([_public(fn, link) for fn, link in _rows(db, analysis_id)])


@functions_bp.patch("/function-names/<int:function_id>")
@require_role(Role.admin, Role.analyst)
def rename_function(function_id: int):  # type: ignore[no-untyped-def]
    """A hand correction. Marks the row `source='user'`, which the naming pass
    then skips forever — a re-run must never undo it."""
    db = get_db()
    fn = db.get(FunctionName, function_id)
    if fn is None:
        return jsonify(error="not_found"), 404

    from .models import Binary

    binary = db.get(Binary, fn.binary_id)
    if binary is None or not can_access_team(g.principal, binary.team_id):
        return jsonify(error="not_found"), 404

    try:
        body = RenameRequest.model_validate(request.get_json(silent=True) or {})
    except ValidationError as e:
        return jsonify(error="invalid_request", detail=e.errors()), 400
    if body.suggested_name is None and body.purpose is None:
        return jsonify(error="invalid_request", detail="nothing to change"), 400

    if body.suggested_name is not None:
        name = body.suggested_name.strip()
        if name:
            from keystone_engine.signatures.naming import NAME_RE

            if not NAME_RE.match(name):
                return jsonify(error="invalid_name", detail="must be a plain identifier"), 400
            fn.suggested_name = name
        else:
            fn.suggested_name = None  # clear it; the original symbol shows again
    if body.purpose is not None:
        fn.purpose = body.purpose.strip() or None
    fn.source = "user"

    audit(
        db,
        g.principal,
        "function.rename",
        "function_name",
        fn.id,
        {"name": fn.suggested_name, "original": fn.original_name},
    )
    db.commit()
    return jsonify(_public(fn, None))
