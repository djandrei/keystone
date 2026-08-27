"""Binary upload, storage and listing — team-scoped.

Upload flow: read (capped) -> sha256 fingerprint -> content-addressed MinIO put
(dedup) -> magic-byte sniff -> best-effort write to the shared samples dir for
later Ghidra import -> team-scoped `binaries` row (UNIQUE(team_id, sha256) dedups
per team). Samples are NEVER executed."""
from __future__ import annotations

import hashlib
import os
import re

from flask import Blueprint, current_app, g, jsonify, request

from .audit import audit
from .config import get_settings
from .context import get_db
from .models import Binary, Role
from .auth.deps import require_auth
from .rbac import can_access_team, require_role, scope_to_teams
from .sniff import sniff
from .storage import ObjectStore, get_object_store

binaries_bp = Blueprint("binaries", __name__, url_prefix="/binaries")


def _store() -> ObjectStore:
    return current_app.config.get("OBJECT_STORE") or get_object_store()


def _sanitize_program_name(filename: str) -> str:
    base = os.path.basename(filename or "binary")
    return re.sub(r"[^A-Za-z0-9._-]", "_", base) or "binary"


def _public(b: Binary) -> dict:
    return {
        "id": b.id,
        "team_id": b.team_id,
        "sha256": b.sha256,
        "filename": b.filename,
        "size": b.size,
        "format": b.format,
        "arch": b.arch,
        "platform": b.platform,
        "ghidra_program_name": b.ghidra_program_name,
        "uploaded_by": b.uploaded_by,
        "created_at": b.created_at.isoformat() if b.created_at else None,
    }


@binaries_bp.post("")
@require_role(Role.admin, Role.analyst)
def upload_binary():  # type: ignore[no-untyped-def]
    settings = current_app.config.get("KEYSTONE") or get_settings()
    file = request.files.get("file")
    team_id_raw = request.form.get("team_id")
    if file is None or not team_id_raw:
        return jsonify(error="file and team_id are required"), 400
    try:
        team_id = int(team_id_raw)
    except ValueError:
        return jsonify(error="team_id must be an integer"), 400
    if not can_access_team(g.principal, team_id):
        return jsonify(error="forbidden"), 403

    # read with a hard cap (+1 to detect oversize without loading the whole thing)
    data = file.read(settings.upload_max_bytes + 1)
    if len(data) > settings.upload_max_bytes:
        return jsonify(error="file_too_large", max_bytes=settings.upload_max_bytes), 413
    if not data:
        return jsonify(error="empty_file"), 400

    sha256 = hashlib.sha256(data).hexdigest()
    info = sniff(data)
    key = f"binaries/{sha256}"

    db = get_db()
    existing = db.query(Binary).filter_by(team_id=team_id, sha256=sha256).first()
    if existing:
        return jsonify(**_public(existing), deduplicated=True), 200

    store = _store()
    if not store.exists(key):
        store.put(key, data)

    # best-effort stage for Ghidra import (shared samples volume)
    program_name = _sanitize_program_name(file.filename or sha256)
    try:
        os.makedirs(settings.sample_dir, exist_ok=True)
        with open(os.path.join(settings.sample_dir, f"{sha256}_{program_name}"), "wb") as fh:
            fh.write(data)
    except OSError:
        pass  # samples dir not mounted here; the worker stages it at analysis time

    row = Binary(
        team_id=team_id,
        sha256=sha256,
        filename=file.filename or program_name,
        size=len(data),
        format=info["format"],
        arch=info["arch"],
        platform=info["platform"],
        ghidra_program_name=program_name,
        storage_key=key,
        uploaded_by=g.principal.user.id,
    )
    db.add(row)
    db.flush()
    audit(db, g.principal, "binary.upload", "binary", row.id, {"sha256": sha256, "team_id": team_id})
    db.commit()
    return jsonify(_public(row)), 201


@binaries_bp.get("")
@require_auth
def list_binaries():  # type: ignore[no-untyped-def]
    db = get_db()
    q = scope_to_teams(db.query(Binary), Binary, g.principal).order_by(Binary.id.desc())
    team_id = request.args.get("team_id", type=int)
    if team_id is not None:
        q = q.filter(Binary.team_id == team_id)
    return jsonify([_public(b) for b in q.all()])


@binaries_bp.get("/<int:binary_id>")
@require_auth
def get_binary(binary_id: int):  # type: ignore[no-untyped-def]
    db = get_db()
    b = db.get(Binary, binary_id)
    if b is None:
        return jsonify(error="not_found"), 404
    if not can_access_team(g.principal, b.team_id):
        return jsonify(error="forbidden"), 403
    return jsonify(_public(b))
