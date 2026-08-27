"""Progress events emitted by pipelines as they run."""

from __future__ import annotations

import enum

from pydantic import BaseModel


class EventType(str, enum.Enum):
    step_start = "step_start"
    step_finish = "step_finish"
    log = "log"
    tool_call = "tool_call"
    needs_input = "needs_input"  # pipeline pauses for a user decision (e.g. VR rule pick)
    error = "error"
    done = "done"


class ProgressEvent(BaseModel):
    """One entry in an analysis's live Step stream. Ordered by `seq`."""

    type: EventType
    seq: int = 0
    step: str | None = None
    message: str | None = None
    data: dict | None = None

    @classmethod
    def step_start(cls, step: str, seq: int = 0, **data: object) -> ProgressEvent:
        return cls(type=EventType.step_start, step=step, seq=seq, data=data or None)

    @classmethod
    def step_finish(cls, step: str, seq: int = 0, **data: object) -> ProgressEvent:
        return cls(type=EventType.step_finish, step=step, seq=seq, data=data or None)

    @classmethod
    def log(cls, message: str, seq: int = 0, step: str | None = None) -> ProgressEvent:
        return cls(type=EventType.log, message=message, seq=seq, step=step)
