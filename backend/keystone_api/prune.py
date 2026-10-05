"""Delete binaries and everything attached to them.

Removing a binary is more than one DELETE: its analyses (and their re_result /
findings / report, via cascade) and the content-addressed object both have to go,
and the object only if no *other* binary still points at it (identical bytes
dedupe to one object). This function does all of that and
returns counts. `dry_run` reports what would go without touching anything.

The CLI (`python -m keystone_api.cli prune-binaries`) wraps it; it is importable
so tests exercise it directly."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from .models import Analysis, Binary


def _select(session: Session, max_bytes: int | None, ids: list[int] | None):  # type: ignore[no-untyped-def]
    q = session.query(Binary)
    if ids:
        return q.filter(Binary.id.in_(ids)).all()
    if max_bytes is not None:
        return q.filter(Binary.size <= max_bytes).all()
    return []


def prune_binaries(
    session: Session,
    store: Any,
    *,
    max_bytes: int | None = None,
    ids: list[int] | None = None,
    dry_run: bool = False,
) -> dict:
    """Delete the selected binaries (by `ids`, else size <= `max_bytes`) and all
    attached rows/objects. Returns {binaries, analyses, objects,
    matched:[{id,filename,size}]}. Selecting nothing is a no-op."""
    targets = _select(session, max_bytes, ids)
    counts: dict = {
        "binaries": 0,
        "analyses": 0,
        "objects": 0,
        "matched": [{"id": b.id, "filename": b.filename, "size": b.size} for b in targets],
    }
    if not targets:
        return counts

    if dry_run:
        counts["binaries"] = len(targets)
        counts["analyses"] = sum(
            session.query(Analysis).filter_by(binary_id=b.id).count() for b in targets
        )
        return counts

    for b in targets:
        storage_key = b.storage_key
        for a in session.query(Analysis).filter_by(binary_id=b.id).all():
            session.delete(a)  # cascades to re_result / findings / report
            counts["analyses"] += 1
        session.flush()
        session.delete(b)
        session.flush()
        counts["binaries"] += 1

        # only drop the object once no other binary references those bytes (dedup)
        still_used = session.query(Binary).filter_by(storage_key=storage_key).count()
        if store is not None and still_used == 0:
            try:
                store.delete(storage_key)
                counts["objects"] += 1
            except Exception:  # noqa: BLE001 — object may already be gone / store down
                pass

    return counts
