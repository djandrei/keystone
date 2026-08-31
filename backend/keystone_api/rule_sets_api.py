"""The Semgrep rule-set library: a team-scoped, immutably-versioned collection of
patterns an analyst picks from when starting a VR analysis.

Two tiers (docs/rule-sets-plan.md §2):

- **System built-ins** — `team_id IS NULL`. Readable by everyone, writable only by
  admins. A team customizes one by cloning it, never by editing it.
- **Team rule sets** — owned by one team, created and edited by any analyst who
  can access that team. Same guard as `projects_api`.

Content is never mutated: every edit appends a `RuleSetVersion`, so an analysis
that pinned v3 can still be explained by v3's exact text after v7 lands.
"""

from __future__ import annotations

from flask import Blueprint, g, jsonify, request
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import func, or_

from keystone_engine.security import detect_injection

from .audit import audit
from .auth.deps import require_auth
from .context import get_db
from .models import AnalysisRuleSet, Role, RuleSet, RuleSetVersion
from .rbac import can_access_team, require_role
from .rulesets import RulesetError, rule_messages, validate_ruleset
from .services import add_rule_set_version, latest_version

rule_sets_bp = Blueprint("rule_sets", __name__, url_prefix="/rule-sets")


class CreateRuleSetRequest(BaseModel):
    # Omitted/None => a system built-in, which requires admin.
    team_id: int | None = None
    name: str = Field(min_length=1, max_length=120)
    description: str | None = None
    languages: list[str] | None = None
    content: str


class UpdateRuleSetRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = None
    archived: bool | None = None


class NewVersionRequest(BaseModel):
    content: str
    notes: str | None = Field(default=None, max_length=2000)


class CloneRequest(BaseModel):
    team_id: int
    name: str | None = Field(default=None, min_length=1, max_length=120)


class ValidateRequest(BaseModel):
    content: str


# --------------------------------------------------------------------------- #
# Serialization
# --------------------------------------------------------------------------- #
def _version_public(v: RuleSetVersion, *, with_content: bool = False) -> dict:
    body = {
        "id": v.id,
        "version_no": v.version_no,
        "content_sha256": v.content_sha256,
        "rule_ids": v.rule_ids or [],
        "rule_count": len(v.rule_ids or []),
        "notes": v.notes,
        "security": v.security,
        "created_by": v.created_by,
        "created_at": v.created_at.isoformat() if v.created_at else None,
    }
    if with_content:
        body["content"] = v.content
    return body


def _public(rs: RuleSet, latest: RuleSetVersion | None = None) -> dict:
    return {
        "id": rs.id,
        "team_id": rs.team_id,
        "name": rs.name,
        "description": rs.description,
        "languages": rs.languages or [],
        "is_builtin": rs.is_builtin,
        # {author, license, url, commit} for imported rules; None for own work.
        "attribution": rs.attribution,
        "archived": rs.archived_at is not None,
        "created_by": rs.created_by,
        "created_at": rs.created_at.isoformat() if rs.created_at else None,
        "latest_version": _version_public(latest) if latest else None,
    }


# --------------------------------------------------------------------------- #
# Authorization
# --------------------------------------------------------------------------- #
def _may_write(rs_team_id: int | None) -> bool:
    """Built-ins are admin-only; a team rule set follows the team boundary. The
    caller has already passed `require_role(admin, analyst)`."""
    if rs_team_id is None:
        return g.principal.is_admin
    return can_access_team(g.principal, rs_team_id)


def _may_read(rs: RuleSet) -> bool:
    return rs.team_id is None or can_access_team(g.principal, rs.team_id)


def _screen(content: str) -> dict | None:
    """Injection screen over the authored rule *messages* — the text that reaches
    the triage prompt (see docs/security.md). Stored on the version and badged in
    the UI; never a reason to reject a save, since a teammate is not an attacker."""
    report = detect_injection("\n".join(rule_messages(content)))
    return report.to_dict() if report.suspected else None


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@rule_sets_bp.get("")
@require_auth
def list_rule_sets():  # type: ignore[no-untyped-def]
    """The picker's source. Built-ins are included by default and sort first, so an
    analyst who has authored nothing still has something to choose."""
    db = get_db()
    p = g.principal
    q = db.query(RuleSet)

    include_builtin = request.args.get("include_builtin", "1") != "0"
    team_id = request.args.get("team_id", type=int)

    if team_id is not None:
        if not can_access_team(p, team_id):
            return jsonify(error="forbidden"), 403
        scope = RuleSet.team_id == team_id
    elif p.is_admin:
        scope = None
    else:
        scope = RuleSet.team_id.in_(p.team_ids or [-1])

    if include_builtin:
        q = q.filter(or_(RuleSet.team_id.is_(None), scope)) if scope is not None else q
    elif scope is not None:
        q = q.filter(scope)
    else:
        q = q.filter(RuleSet.team_id.isnot(None))

    if request.args.get("archived", "0") != "1":
        q = q.filter(RuleSet.archived_at.is_(None))
    if term := request.args.get("q"):
        q = q.filter(RuleSet.name.ilike(f"%{term}%"))

    rows = q.order_by(RuleSet.team_id.is_(None).desc(), RuleSet.name.asc()).all()
    latest = _latest_for(db, [r.id for r in rows])
    return jsonify([_public(r, latest.get(r.id)) for r in rows])


def _latest_for(db, ids: list[int]) -> dict[int, RuleSetVersion]:
    """Latest version per rule set in two queries, never one per row."""
    if not ids:
        return {}
    tops = (
        db.query(RuleSetVersion.rule_set_id, func.max(RuleSetVersion.version_no))
        .filter(RuleSetVersion.rule_set_id.in_(ids))
        .group_by(RuleSetVersion.rule_set_id)
        .all()
    )
    if not tops:
        return {}
    wanted = {(rid, no) for rid, no in tops}
    rows = (
        db.query(RuleSetVersion)
        .filter(RuleSetVersion.rule_set_id.in_([rid for rid, _ in tops]))
        .all()
    )
    return {v.rule_set_id: v for v in rows if (v.rule_set_id, v.version_no) in wanted}


@rule_sets_bp.post("")
@require_role(Role.admin, Role.analyst)
def create_rule_set():  # type: ignore[no-untyped-def]
    try:
        body = CreateRuleSetRequest.model_validate(request.get_json(silent=True) or {})
    except ValidationError as e:
        return jsonify(error="invalid_request", detail=e.errors()), 400
    if not _may_write(body.team_id):
        return jsonify(error="forbidden"), 403

    db = get_db()
    clash = db.query(RuleSet).filter_by(team_id=body.team_id, name=body.name).first()
    if clash:
        return jsonify(error="name_taken"), 409

    try:
        _, langs = validate_ruleset(body.content)
    except RulesetError as e:
        return jsonify(error="invalid_ruleset", errors=e.errors), 400

    rs = RuleSet(
        team_id=body.team_id,
        name=body.name,
        description=body.description,
        # Fall back to the languages the rules themselves declare.
        languages=body.languages or langs,
        is_builtin=body.team_id is None,
        created_by=g.principal.user.id,
    )
    db.add(rs)
    db.flush()
    version = add_rule_set_version(
        db, rs, body.content, created_by=g.principal.user.id, security=_screen(body.content)
    )
    audit(db, g.principal, "rule_set.create", "rule_set", rs.id, {"name": rs.name})
    db.commit()
    return jsonify(_public(rs, version)), 201


@rule_sets_bp.get("/<int:rule_set_id>")
@require_auth
def get_rule_set(rule_set_id: int):  # type: ignore[no-untyped-def]
    db = get_db()
    rs = db.get(RuleSet, rule_set_id)
    if rs is None or not _may_read(rs):
        return jsonify(error="not_found"), 404
    versions = (
        db.query(RuleSetVersion)
        .filter_by(rule_set_id=rs.id)
        .order_by(RuleSetVersion.version_no.desc())
        .all()
    )
    body = _public(rs, versions[0] if versions else None)
    body["versions"] = [_version_public(v) for v in versions]
    # The newest version carries its content so the editor opens ready to edit.
    if versions:
        body["content"] = versions[0].content
    return jsonify(body)


@rule_sets_bp.patch("/<int:rule_set_id>")
@require_role(Role.admin, Role.analyst)
def update_rule_set(rule_set_id: int):  # type: ignore[no-untyped-def]
    """Metadata only. Content changes go through POST /versions — that is the
    whole point of the immutable-version model."""
    db = get_db()
    rs = db.get(RuleSet, rule_set_id)
    if rs is None:
        return jsonify(error="not_found"), 404
    if not _may_write(rs.team_id):
        return jsonify(error="forbidden"), 403
    try:
        body = UpdateRuleSetRequest.model_validate(request.get_json(silent=True) or {})
    except ValidationError as e:
        return jsonify(error="invalid_request", detail=e.errors()), 400

    if body.name is not None and body.name != rs.name:
        clash = (
            db.query(RuleSet)
            .filter(RuleSet.team_id == rs.team_id, RuleSet.name == body.name, RuleSet.id != rs.id)
            .first()
        )
        if clash:
            return jsonify(error="name_taken"), 409
        rs.name = body.name
    if body.description is not None:
        rs.description = body.description
    if body.archived is not None:
        rs.archived_at = func.now() if body.archived else None

    audit(db, g.principal, "rule_set.update", "rule_set", rs.id, {"name": rs.name})
    db.commit()
    db.refresh(rs)
    return jsonify(_public(rs, latest_version(db, rs.id)))


@rule_sets_bp.delete("/<int:rule_set_id>")
@require_role(Role.admin, Role.analyst)
def delete_rule_set(rule_set_id: int):  # type: ignore[no-untyped-def]
    """Hard delete, refused once any analysis has pinned a version of it — that pin
    is what keeps an old report explainable. Archive instead."""
    db = get_db()
    rs = db.get(RuleSet, rule_set_id)
    if rs is None:
        return jsonify(error="not_found"), 404
    if not _may_write(rs.team_id):
        return jsonify(error="forbidden"), 403

    used = int(
        db.query(func.count(AnalysisRuleSet.analysis_id))
        .join(RuleSetVersion, RuleSetVersion.id == AnalysisRuleSet.rule_set_version_id)
        .filter(RuleSetVersion.rule_set_id == rs.id)
        .scalar()
        or 0
    )
    if used:
        return jsonify(error="in_use", analyses=used, hint="archive it instead"), 409

    db.delete(rs)
    audit(db, g.principal, "rule_set.delete", "rule_set", rule_set_id, {"name": rs.name})
    db.commit()
    return "", 204


@rule_sets_bp.post("/<int:rule_set_id>/versions")
@require_role(Role.admin, Role.analyst)
def add_version(rule_set_id: int):  # type: ignore[no-untyped-def]
    db = get_db()
    rs = db.get(RuleSet, rule_set_id)
    if rs is None:
        return jsonify(error="not_found"), 404
    if not _may_write(rs.team_id):
        return jsonify(error="forbidden"), 403
    try:
        body = NewVersionRequest.model_validate(request.get_json(silent=True) or {})
    except ValidationError as e:
        return jsonify(error="invalid_request", detail=e.errors()), 400
    try:
        version = add_rule_set_version(
            db,
            rs,
            body.content,
            created_by=g.principal.user.id,
            notes=body.notes,
            security=_screen(body.content),
        )
    except RulesetError as e:
        return jsonify(error="invalid_ruleset", errors=e.errors), 400
    if version is None:
        return jsonify(error="unchanged", detail="content matches the latest version"), 409

    audit(
        db,
        g.principal,
        "rule_set.version",
        "rule_set",
        rs.id,
        {"version_no": version.version_no},
    )
    db.commit()
    return jsonify(_version_public(version, with_content=True)), 201


@rule_sets_bp.get("/<int:rule_set_id>/versions/<int:version_no>")
@require_auth
def get_version(rule_set_id: int, version_no: int):  # type: ignore[no-untyped-def]
    db = get_db()
    rs = db.get(RuleSet, rule_set_id)
    if rs is None or not _may_read(rs):
        return jsonify(error="not_found"), 404
    v = db.query(RuleSetVersion).filter_by(rule_set_id=rs.id, version_no=version_no).first()
    if v is None:
        return jsonify(error="not_found"), 404
    return jsonify(_version_public(v, with_content=True))


@rule_sets_bp.post("/<int:rule_set_id>/clone")
@require_role(Role.admin, Role.analyst)
def clone_rule_set(rule_set_id: int):  # type: ignore[no-untyped-def]
    """Fork a rule set into a team — how a team customizes a built-in it may not
    edit. The clone starts at v1 with the source's latest content."""
    db = get_db()
    rs = db.get(RuleSet, rule_set_id)
    if rs is None or not _may_read(rs):
        return jsonify(error="not_found"), 404
    try:
        body = CloneRequest.model_validate(request.get_json(silent=True) or {})
    except ValidationError as e:
        return jsonify(error="invalid_request", detail=e.errors()), 400
    if not can_access_team(g.principal, body.team_id):
        return jsonify(error="forbidden"), 403

    src = latest_version(db, rs.id)
    if src is None:
        return jsonify(error="no_content", detail="rule set has no versions"), 409

    name = body.name or f"{rs.name} (copy)"
    if db.query(RuleSet).filter_by(team_id=body.team_id, name=name).first():
        return jsonify(error="name_taken"), 409

    clone = RuleSet(
        team_id=body.team_id,
        name=name,
        description=rs.description,
        languages=rs.languages,
        is_builtin=False,
        # A fork of somebody's rules is still their work — the credit travels.
        attribution=rs.attribution,
        created_by=g.principal.user.id,
    )
    db.add(clone)
    db.flush()
    version = add_rule_set_version(
        db,
        clone,
        src.content,
        created_by=g.principal.user.id,
        notes=f"cloned from {rs.name} v{src.version_no}",
        security=src.security,
    )
    audit(
        db,
        g.principal,
        "rule_set.clone",
        "rule_set",
        clone.id,
        {"from": rs.id, "name": name},
    )
    db.commit()
    return jsonify(_public(clone, version)), 201


@rule_sets_bp.post("/validate")
@require_role(Role.admin, Role.analyst)
def validate():  # type: ignore[no-untyped-def]
    """Structural validation only — Semgrep itself is a worker-only dependency.
    See docs/rule-sets-plan.md §7."""
    try:
        body = ValidateRequest.model_validate(request.get_json(silent=True) or {})
    except ValidationError as e:
        return jsonify(error="invalid_request", detail=e.errors()), 400
    try:
        rule_ids, langs = validate_ruleset(body.content)
    except RulesetError as e:
        return jsonify(ok=False, errors=e.errors)
    return jsonify(
        ok=True,
        errors=[],
        rule_ids=rule_ids,
        languages=langs,
        security=_screen(body.content),
    )
