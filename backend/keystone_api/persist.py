"""Map engine result models onto DB rows + a stored report artifact."""

from __future__ import annotations

from sqlalchemy.orm import Session

from keystone_engine.results import (
    Report as EngineReport,
)
from keystone_engine.results import (
    REResult as EngineRE,
)
from keystone_engine.results import (
    VRFinding as EngineVR,
)

from .models import Analysis, Classification, Report, REResult, RiskLevel, VRFinding
from .storage import ObjectStore


def _report_key(analysis_id: int) -> str:
    return f"reports/{analysis_id}.md"


def persist_re_result(
    session: Session, analysis: Analysis, result: object, *, store: ObjectStore
) -> None:
    re_result, report = result  # type: ignore[misc]
    assert isinstance(re_result, EngineRE) and isinstance(report, EngineReport)
    session.add(
        REResult(
            analysis_id=analysis.id,
            binary_type=re_result.binary_type,
            purpose=re_result.purpose,
            key_functions=re_result.key_functions,
            attack_surface=re_result.attack_surface,
            language_runtime=re_result.language_runtime,
            tool_calls=re_result.tool_calls,
            raw=re_result.raw,
        )
    )
    persist_function_names(session, analysis, re_result.function_names or [])
    key = _report_key(analysis.id)
    store.put(key, report.content.encode("utf-8"))
    session.add(Report(analysis_id=analysis.id, format=report.format, storage_key=key))


def _enum_or_none(enum_cls, value):  # type: ignore[no-untyped-def]
    try:
        return enum_cls(value) if value else None
    except ValueError:
        return None


def persist_vr_result(
    session: Session, analysis: Analysis, result: object, *, store: ObjectStore
) -> None:
    findings, report = result  # type: ignore[misc]
    for f in findings:
        assert isinstance(f, EngineVR)
        session.add(
            VRFinding(
                analysis_id=analysis.id,
                rule=f.rule,
                file=f.file,
                line=f.line,
                semgrep_message=f.semgrep_message,
                classification=_enum_or_none(Classification, f.classification),
                risk_level=_enum_or_none(RiskLevel, f.risk_level),
                cwe_id=f.cwe_id,
                reasoning=f.reasoning,
                reachable=f.reachable,
                entry_path=f.entry_path,
                confidence=f.confidence,
                rule_set_version_id=f.rule_set_version_id,
            )
        )
    key = _report_key(analysis.id)
    store.put(key, report.content.encode("utf-8"))
    session.add(Report(analysis_id=analysis.id, format=report.format, storage_key=key))


def persist_function_names(
    session: Session, analysis: Analysis, named: list, *, created_by: int | None = None
) -> int:
    """Store friendly names for `analysis`'s binary and link them to the analysis.

    Upsert keyed on (binary_id, address). A row whose `source` is 'user' is left
    alone — a naming re-run must never undo a hand correction. Returns how many
    rows the model actually changed.

    Linking is separate from naming: names belong to the binary and outlive any one
    analysis, while inclusion in a report is per analysis (and defaults to on).
    """
    from keystone_api.models import AnalysisFunction, FunctionName

    existing = {
        f.address: f
        for f in session.query(FunctionName).filter_by(binary_id=analysis.binary_id).all()
    }
    changed = 0
    rows: list[FunctionName] = []

    for item in named:
        row = existing.get(item.address)
        if row is None:
            row = FunctionName(
                binary_id=analysis.binary_id,
                address=item.address,
                original_name=item.original_name,
                suggested_name=item.suggested_name,
                purpose=item.purpose,
                created_by=created_by,
            )
            session.add(row)
            session.flush()
            existing[item.address] = row
            changed += 1
        elif row.source != "user" and item.suggested_name:
            # Re-running naming may improve a machine name; it never touches one a
            # person edited.
            row.suggested_name = item.suggested_name
            row.purpose = item.purpose
            changed += 1
        rows.append(row)

    linked = {
        link.function_name_id
        for link in session.query(AnalysisFunction).filter_by(analysis_id=analysis.id).all()
    }
    for position, row in enumerate(rows):
        if row.id not in linked:
            session.add(
                AnalysisFunction(
                    analysis_id=analysis.id, function_name_id=row.id, position=position
                )
            )
    return changed
