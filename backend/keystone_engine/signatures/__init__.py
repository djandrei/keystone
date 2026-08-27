"""keystone_engine.signatures — DSPy signatures + classifiers."""
from .triage import make_triage_agent, triage_findings
from .platform import (
    classify_platform,
    classify_platform_from_imports,
    classify_platform_simple,
    make_platform_classifier,
)

__all__ = [
    "classify_platform",
    "classify_platform_simple",
    "classify_platform_from_imports",
    "make_platform_classifier",
    "make_triage_agent",
    "triage_findings",
]
