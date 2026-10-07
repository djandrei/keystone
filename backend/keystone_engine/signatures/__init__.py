"""keystone_engine.signatures — DSPy signatures + classifiers."""

from .platform import (
    build_platform_agent,
    classify_platform_from_imports,
    detect_platform,
    platform_from_filename,
)
from .reachability import assess_reachability, make_reachability_agent
from .triage import make_triage_agent, triage_findings

__all__ = [
    "detect_platform",
    "platform_from_filename",
    "classify_platform_from_imports",
    "build_platform_agent",
    "make_triage_agent",
    "triage_findings",
    "make_reachability_agent",
    "assess_reachability",
]
