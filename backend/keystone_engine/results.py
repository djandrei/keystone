"""Typed engine results — the domain models the pipelines produce.

Deliberately mirror the DB columns (keystone_api.models) field-for-field, but carry
no ORM: the worker maps these onto SQLAlchemy rows at the boundary.
"""

from __future__ import annotations

from pydantic import BaseModel


class REResult(BaseModel):
    binary_type: str | None = None
    purpose: str | None = None
    key_functions: str | None = None
    attack_surface: str | None = None
    language_runtime: str | None = None
    tool_calls: int | None = None
    raw: dict | None = None


class VRFinding(BaseModel):
    rule: str | None = None
    file: str | None = None
    line: int | None = None
    semgrep_message: str | None = None
    classification: str | None = None  # true_positive | false_positive | needs_review
    risk_level: str | None = None  # critical | high | medium | low | informational
    cwe_id: str | None = None
    reasoning: str | None = None
    reachable: str | None = None
    entry_path: str | None = None
    confidence: str | None = None


class Report(BaseModel):
    format: str = "md"
    content: str = ""
