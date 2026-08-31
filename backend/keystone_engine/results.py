"""Typed engine results — the domain models the pipelines produce.

Deliberately mirror the DB columns (keystone_api.models) field-for-field, but carry
no ORM: the worker maps these onto SQLAlchemy rows at the boundary.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class REResult(BaseModel):
    binary_type: str | None = None
    purpose: str | None = None
    key_functions: str | None = None
    attack_surface: str | None = None
    language_runtime: str | None = None
    tool_calls: int | None = None
    raw: dict | None = None
    # Friendly names for the decompiled functions. Carried on the result rather
    # than persisted by the engine — the engine has no DB.
    function_names: list = Field(default_factory=list)


class VRFinding(BaseModel):
    rule: str | None = None
    file: str | None = None
    line: int | None = None
    semgrep_message: str | None = None
    # The rule's declared severity (ERROR/WARNING/INFO). Used to rank rule classes
    # for triage; not persisted — it is a property of the rule, not the finding.
    severity: str | None = None
    classification: str | None = None  # true_positive | false_positive | needs_review
    risk_level: str | None = None  # critical | high | medium | low | informational
    cwe_id: str | None = None
    reasoning: str | None = None
    reachable: str | None = None
    entry_path: str | None = None
    confidence: str | None = None
    # Which pinned ruleset version fired this rule (see rulesets.materialize).
    rule_set_version_id: int | None = None


class Report(BaseModel):
    format: str = "md"
    content: str = ""
