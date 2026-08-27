"""Analysis job lifecycle — the boundary that adapts engine events to DB writes
and Redis publishes.

`run_analysis_core` is deliberately framework-free and fully injectable so it unit-
tests without Celery, Redis, Ghidra or an LLM. The Celery task in `worker.py`
wires the real adapters (engine pipeline, MinIO persist, Redis publish/cancel)."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from keystone_engine.events import EventType, ProgressEvent

from .models import Analysis, AnalysisStatus


def _now() -> datetime:
    return datetime.now(UTC)


PipelineFn = Callable[[Analysis], Iterator[ProgressEvent]]
PersistFn = Callable[[Session, Analysis, object], None]
PublishFn = Callable[[int, dict], None]
CancelFn = Callable[[int], bool]


def run_analysis_core(
    analysis_id: int,
    session: Session,
    *,
    pipeline: PipelineFn,
    persist: PersistFn,
    publish: PublishFn = lambda _id, _ev: None,
    is_canceled: CancelFn = lambda _id: False,
    now: Callable[[], datetime] = _now,
) -> AnalysisStatus:
    """Drive one analysis: queued→running→succeeded/failed/canceled, persisting a
    progress snapshot and publishing each event. Cancel is checked between steps.
    Returns the terminal status."""
    analysis = session.get(Analysis, analysis_id)
    if analysis is None:
        return AnalysisStatus.failed

    analysis.status = AnalysisStatus.running
    analysis.started_at = now()
    session.commit()

    events: list[dict] = []
    gen = pipeline(analysis)
    try:
        while True:
            if is_canceled(analysis_id):
                analysis.status = AnalysisStatus.canceled
                analysis.finished_at = now()
                session.commit()
                publish(analysis_id, {"type": "canceled"})
                return AnalysisStatus.canceled
            try:
                event = next(gen)
            except StopIteration as stop:
                result = stop.value
                break
            events.append(event.model_dump())
            if event.type is EventType.security:
                analysis.security = event.data  # surface the injection signal
            # a fresh list each time so the JSON column sees a real change
            # (mutating one list in place shares the reference and is missed)
            analysis.progress = {"events": list(events)}
            session.commit()
            publish(analysis_id, event.model_dump())

        persist(session, analysis, result)
        analysis.status = AnalysisStatus.succeeded
        analysis.finished_at = now()
        session.commit()
        publish(analysis_id, {"type": "done"})
        return AnalysisStatus.succeeded

    except Exception as exc:  # noqa: BLE001 — record any engine/tool failure on the row
        session.rollback()
        analysis = session.get(Analysis, analysis_id)
        if analysis is not None:
            analysis.status = AnalysisStatus.failed
            analysis.error = str(exc)[:2000]
            analysis.finished_at = now()
            session.commit()
        publish(analysis_id, {"type": "error", "message": str(exc)})
        return AnalysisStatus.failed
