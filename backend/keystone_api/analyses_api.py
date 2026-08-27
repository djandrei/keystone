"""Analysis lifecycle over HTTP: start (per binary), list/read (team-scoped),
fetch the report artifact, and cancel. Enqueue + cancel-signal are injectable
(app.config) so the API tests need no Celery/Redis."""
from __future__ import annotations

from flask import Blueprint, Response, current_app, g, jsonify, request

from .audit import audit
from .auth.deps import require_auth
from .config import get_settings
from .context import get_db
from .models import Analysis, AnalysisMode, AnalysisStatus, Binary, Report, Role, VRFinding
from .rbac import can_access_team, require_role, scope_to_teams
from .services import get_or_create_settings
from .storage import ObjectStore, get_object_store

analyses_bp = Blueprint("analyses", __name__)

_TERMINAL = {AnalysisStatus.succeeded, AnalysisStatus.failed, AnalysisStatus.canceled}


def _store() -> ObjectStore:
    return current_app.config.get("OBJECT_STORE") or get_object_store()


def _enqueue(analysis_id: int) -> None:
    fn = current_app.config.get("ENQUEUE")
    if fn:
        fn(analysis_id)
        return
    from worker import run_analysis  # lazy: keeps API import free of celery

    run_analysis.delay(analysis_id)


def _signal_cancel(analysis_id: int) -> None:
    fn = current_app.config.get("CANCEL_SIGNAL")
    if fn:
        fn(analysis_id)
        return
    import redis

    redis.Redis.from_url(get_settings().redis_url).set(f"analysis:{analysis_id}:cancel", "1", ex=3600)


def _signal_rule(analysis_id: int, rule: str) -> None:
    fn = current_app.config.get("RULE_SIGNAL")
    if fn:
        fn(analysis_id, rule)
        return
    import redis

    redis.Redis.from_url(get_settings().redis_url).set(f"analysis:{analysis_id}:rule", rule, ex=3600)


def _finding_public(f: VRFinding) -> dict:
    return {
        "id": f.id,
        "rule": f.rule,
        "file": f.file,
        "line": f.line,
        "semgrep_message": f.semgrep_message,
        "classification": f.classification.value if f.classification else None,
        "risk_level": f.risk_level.value if f.risk_level else None,
        "cwe_id": f.cwe_id,
        "reasoning": f.reasoning,
        "reachable": f.reachable,
        "entry_path": f.entry_path,
        "confidence": f.confidence,
    }


def _public(a: Analysis, *, with_result: bool = False) -> dict:
    body = {
        "id": a.id,
        "team_id": a.team_id,
        "binary_id": a.binary_id,
        "mode": a.mode.value,
        "status": a.status.value,
        "model": a.model,
        "params": a.params,
        "created_by": a.created_by,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "started_at": a.started_at.isoformat() if a.started_at else None,
        "finished_at": a.finished_at.isoformat() if a.finished_at else None,
        "error": a.error,
        "progress": a.progress,
    }
    if with_result and a.re_result is not None:
        r = a.re_result
        body["re_result"] = {
            "binary_type": r.binary_type,
            "purpose": r.purpose,
            "key_functions": r.key_functions,
            "attack_surface": r.attack_surface,
            "language_runtime": r.language_runtime,
            "tool_calls": r.tool_calls,
        }
    return body


@analyses_bp.post("/binaries/<int:binary_id>/analyses")
@require_role(Role.admin, Role.analyst)
def start_analysis(binary_id: int):  # type: ignore[no-untyped-def]
    db = get_db()
    binary = db.get(Binary, binary_id)
    if binary is None:
        return jsonify(error="not_found"), 404
    if not can_access_team(g.principal, binary.team_id):
        return jsonify(error="forbidden"), 403

    payload = request.get_json(silent=True) or {}
    mode_raw = payload.get("mode", "re")
    try:
        mode = AnalysisMode(mode_raw)
    except ValueError:
        return jsonify(error="invalid_mode", allowed=[m.value for m in AnalysisMode]), 400

    sysset = get_or_create_settings(db)
    analysis = Analysis(
        team_id=binary.team_id,
        binary_id=binary.id,
        mode=mode,
        status=AnalysisStatus.queued,
        model=sysset.default_model,
        params=payload.get("params"),
        created_by=g.principal.user.id,
    )
    db.add(analysis)
    db.flush()
    audit(db, g.principal, "analysis.start", "analysis", analysis.id, {"mode": mode.value, "binary_id": binary.id})
    db.commit()
    _enqueue(analysis.id)
    return jsonify(_public(analysis)), 201


@analyses_bp.get("/analyses")
@require_auth
def list_analyses():  # type: ignore[no-untyped-def]
    db = get_db()
    q = scope_to_teams(db.query(Analysis), Analysis, g.principal).order_by(Analysis.id.desc())
    for field, col in (("binary_id", Analysis.binary_id), ("team_id", Analysis.team_id)):
        val = request.args.get(field, type=int)
        if val is not None:
            q = q.filter(col == val)
    if (mode := request.args.get("mode")):
        try:
            q = q.filter(Analysis.mode == AnalysisMode(mode))
        except ValueError:
            return jsonify(error="invalid_mode"), 400
    if (status := request.args.get("status")):
        try:
            q = q.filter(Analysis.status == AnalysisStatus(status))
        except ValueError:
            return jsonify(error="invalid_status"), 400
    return jsonify([_public(a) for a in q.all()])


@analyses_bp.get("/analyses/<int:analysis_id>")
@require_auth
def get_analysis(analysis_id: int):  # type: ignore[no-untyped-def]
    db = get_db()
    a = db.get(Analysis, analysis_id)
    if a is None:
        return jsonify(error="not_found"), 404
    if not can_access_team(g.principal, a.team_id):
        return jsonify(error="forbidden"), 403
    return jsonify(_public(a, with_result=True))


@analyses_bp.get("/analyses/<int:analysis_id>/report")
@require_auth
def get_report(analysis_id: int):  # type: ignore[no-untyped-def]
    db = get_db()
    a = db.get(Analysis, analysis_id)
    if a is None or not can_access_team(g.principal, a.team_id):
        return jsonify(error="not_found"), 404
    report = db.get(Report, analysis_id)
    if report is None or not report.storage_key:
        return jsonify(error="no_report"), 404
    try:
        content = _store().get(report.storage_key)
    except Exception:
        return jsonify(error="report_unavailable"), 404
    return Response(content, mimetype="text/markdown")


@analyses_bp.post("/analyses/<int:analysis_id>/cancel")
@require_role(Role.admin, Role.analyst)
def cancel_analysis(analysis_id: int):  # type: ignore[no-untyped-def]
    db = get_db()
    a = db.get(Analysis, analysis_id)
    if a is None:
        return jsonify(error="not_found"), 404
    if not can_access_team(g.principal, a.team_id):
        return jsonify(error="forbidden"), 403
    if a.status in _TERMINAL:
        return jsonify(error="already_terminal", status=a.status.value), 409
    _signal_cancel(analysis_id)
    if a.status is AnalysisStatus.queued:
        a.status = AnalysisStatus.canceled  # not yet picked up — cancel outright
    audit(db, g.principal, "analysis.cancel", "analysis", analysis_id)
    db.commit()
    return jsonify(status="canceling")


@analyses_bp.post("/analyses/<int:analysis_id>/select-rule")
@require_role(Role.admin, Role.analyst)
def select_rule(analysis_id: int):  # type: ignore[no-untyped-def]
    db = get_db()
    a = db.get(Analysis, analysis_id)
    if a is None:
        return jsonify(error="not_found"), 404
    if not can_access_team(g.principal, a.team_id):
        return jsonify(error="forbidden"), 403
    payload = request.get_json(silent=True) or {}
    rule = payload.get("rule")
    if not rule:
        return jsonify(error="rule is required"), 400
    _signal_rule(analysis_id, rule)
    a.params = {**(a.params or {}), "rule": rule}
    audit(db, g.principal, "analysis.select_rule", "analysis", analysis_id, {"rule": rule})
    db.commit()
    return jsonify(status="ok", rule=rule)


@analyses_bp.get("/analyses/<int:analysis_id>/findings")
@require_auth
def get_findings(analysis_id: int):  # type: ignore[no-untyped-def]
    db = get_db()
    a = db.get(Analysis, analysis_id)
    if a is None or not can_access_team(g.principal, a.team_id):
        return jsonify(error="not_found"), 404
    rows = db.query(VRFinding).filter_by(analysis_id=analysis_id).order_by(VRFinding.id).all()
    return jsonify([_finding_public(f) for f in rows])
