"""Keystone analysis engine — UI-free, framework-free.

Knows only its own contracts (`ProgressEvent`, result models). No Flask, no
SQLAlchemy, no React: the worker adapts engine events/results to DB writes and
Redis publishes. An import-lint test enforces the boundary so a CLI or a different
UI could drive the same engine.
"""

from .events import EventType, ProgressEvent
from .results import Report, REResult, VRFinding

__all__ = ["EventType", "ProgressEvent", "REResult", "VRFinding", "Report"]
