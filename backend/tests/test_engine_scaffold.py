"""Stage 2.0: the engine imports cleanly, its contracts round-trip, and it stays
free of any UI/framework/ORM import (the boundary the whole design rests on)."""
from __future__ import annotations

import ast
import pathlib

import keystone_engine as engine
from keystone_engine.events import EventType, ProgressEvent
from keystone_engine.results import Report, REResult, VRFinding

ENGINE_DIR = pathlib.Path(engine.__file__).parent
FORBIDDEN = {"flask", "sqlalchemy", "keystone_api", "celery", "redis"}


def test_public_contracts_exported():
    assert engine.ProgressEvent is ProgressEvent
    assert engine.REResult is REResult
    assert engine.VRFinding is VRFinding
    assert engine.Report is Report


def test_event_round_trip():
    e = ProgressEvent.step_start("overview", seq=1, binary="ls")
    dumped = e.model_dump()
    assert dumped["type"] == "step_start" and dumped["step"] == "overview"
    assert ProgressEvent.model_validate(dumped) == e
    assert EventType("needs_input") is EventType.needs_input


def test_result_round_trip():
    r = REResult(binary_type="ELF", language_runtime="C", tool_calls=7)
    assert REResult.model_validate(r.model_dump()) == r
    f = VRFinding(rule="int-overflow", cwe_id="CWE-190", classification="true_positive")
    assert VRFinding.model_validate(f.model_dump()) == f
    assert Report(content="# report").format == "md"


def test_engine_imports_no_ui_or_framework():
    """Walk every engine module's import statements; none may pull in the API,
    Flask, SQLAlchemy, Celery or Redis."""
    offenders: list[str] = []
    for py in ENGINE_DIR.rglob("*.py"):
        tree = ast.parse(py.read_text(), filename=str(py))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                root = name.split(".")[0]
                if root in FORBIDDEN:
                    offenders.append(f"{py.relative_to(ENGINE_DIR)}: {name}")
    assert not offenders, f"engine must not import UI/framework/ORM: {offenders}"
