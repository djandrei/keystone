"""Celery entrypoint: `celery -A worker.app worker`.

Wires the real adapters (engine pipeline + Ghidra import, MinIO persist, Redis
publish/cancel) into the framework-free `run_analysis_core`."""
from __future__ import annotations

import json
import time

from celery import Celery

from keystone_api.config import get_settings
from keystone_api.db import get_session, init_db
from keystone_api.jobs import run_analysis_core
from keystone_api.models import Analysis, AnalysisMode, Binary
from keystone_api.persist import persist_re_result, persist_vr_result
from keystone_api.services import get_or_create_settings
from keystone_api.storage import get_object_store
from keystone_engine.llm import configure_lm, make_lm
from keystone_engine.mcp import GhidraMcpClient
from keystone_engine.events import EventType, ProgressEvent
from keystone_engine.pipelines import BinaryRef, re_path
from keystone_engine.results import Report, REResult, VRFinding

settings = get_settings()
app = Celery("keystone", broker=settings.redis_url, backend=settings.redis_url)
# One long analysis per worker slot at a time; ack after completion so a crashed
# worker's task is redelivered rather than lost.
app.conf.update(
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    task_track_started=True,
    broker_connection_retry_on_startup=True,
)


def _redis():  # type: ignore[no-untyped-def]
    import redis

    return redis.Redis.from_url(settings.redis_url)


def _publish(analysis_id: int, event: dict) -> None:
    _redis().publish(f"analysis:{analysis_id}", json.dumps(event))


def _is_canceled(analysis_id: int) -> bool:
    return bool(_redis().get(f"analysis:{analysis_id}:cancel"))


def _make_rule_resolver(analysis_id: int, timeout: int = 300, interval: int = 2):
    """Block until the user POSTs a rule selection (Redis key), else auto-pick."""
    def resolve(counts: dict) -> str | None:
        r = _redis()
        key = f"analysis:{analysis_id}:rule"
        waited = 0
        while waited < timeout:
            val = r.get(key)
            if val:
                return val.decode() if isinstance(val, bytes) else val
            time.sleep(interval)
            waited += interval
        return max(counts, key=lambda k: counts[k]) if counts else None

    return resolve


def _fake_pipeline(_a):
    """Deterministic canned RE run — no Ghidra, no LLM (engine_fake mode)."""
    yield ProgressEvent.step_start("overview", 1)
    yield ProgressEvent.step_finish("overview", 2, imports=3)
    yield ProgressEvent.step_start("decompile", 3)
    yield ProgressEvent.step_finish("decompile", 4, count=2)
    yield ProgressEvent.step_start("analyze", 5)
    result = REResult(
        binary_type="cli_tool", purpose="Deterministic fake analysis for the M2 e2e.",
        key_functions="main", attack_surface="argv parsing", language_runtime="C",
        tool_calls=2, raw={"fake": True},
    )
    report = Report(format="md", content="# RE Analysis\n\n**Language / runtime:** C\n")
    yield ProgressEvent.step_finish("analyze", 6, language_runtime="C")
    yield ProgressEvent(type=EventType.done, seq=7, step="done", data={"language_runtime": "C"})
    return (result, report)


def _fake_vr_pipeline(analysis_id: int, params: dict):
    """Deterministic canned VR run with the interactive rule pick (engine_fake)."""
    def gen(_a):
        counts = {"kernel-integer-wraparound": 2, "format-string": 1}
        yield ProgressEvent.step_start("decompile", 1)
        yield ProgressEvent.step_finish("decompile", 2, count=4)
        yield ProgressEvent.step_start("semgrep", 3)
        yield ProgressEvent.step_finish("semgrep", 4, total=3, classes=counts)
        yield ProgressEvent.step_start("rule_pick", 5)
        if params.get("rule"):
            chosen = params["rule"]
        elif params.get("interactive"):
            yield ProgressEvent(type=EventType.needs_input, seq=6, step="rule_pick", data={"classes": counts})
            chosen = _make_rule_resolver(analysis_id)(counts)
        else:
            chosen = max(counts, key=lambda k: counts[k])
        yield ProgressEvent.step_finish("rule_pick", 7, rule=chosen, selected=2)
        yield ProgressEvent.step_start("triage", 8)
        yield ProgressEvent.step_finish("triage", 9, triaged=2)
        yield ProgressEvent.step_start("reachability", 10)
        yield ProgressEvent.step_finish("reachability", 11, assessed=1)
        findings = [
            VRFinding(rule=chosen, file="parse_header.c", line=3, semgrep_message="unchecked length into memcpy",
                      classification="true_positive", risk_level="high", cwe_id="CWE-190",
                      reasoning="length is attacker-controlled and feeds memcpy without a bound check",
                      reachable="yes", entry_path="DriverIoControl -> parse_header", confidence="high"),
            VRFinding(rule=chosen, file="log.c", line=8, semgrep_message="benign",
                      classification="false_positive", risk_level="informational"),
        ]
        report = Report(format="md", content=f"# VR Analysis\n\n**Rule class:** {chosen}\n\nCWE-190 in parse_header\n")
        yield ProgressEvent(type=EventType.done, seq=12, step="done", data={"findings": len(findings)})
        return (findings, report)

    return gen


@app.task(name="run_analysis")
def run_analysis(analysis_id: int) -> str:
    init_db(settings.database_url)
    session = get_session()
    try:
        analysis = session.get(Analysis, analysis_id)
        if analysis is None:
            return "failed"
        binary = session.get(Binary, analysis.binary_id)
        client = GhidraMcpClient(base_url=settings.mcp_endpoint)

        sysset = get_or_create_settings(session)
        if sysset.llm_endpoint_url and sysset.default_model:
            configure_lm(make_lm(sysset.llm_endpoint_url, sysset.default_model, settings.llm_api_key))
        store = get_object_store()

        sample_path = f"{settings.sample_dir}/{binary.sha256}_{binary.ghidra_program_name}"
        ref = BinaryRef(program=binary.ghidra_program_name, sha256=binary.sha256, filename=binary.filename)

        if settings.engine_fake:
            if analysis.mode is AnalysisMode.vr:
                pipeline = _fake_vr_pipeline(analysis_id, analysis.params or {})
                persist = lambda s, a, r: persist_vr_result(s, a, r, store=store)
            else:
                pipeline = _fake_pipeline
                persist = lambda s, a, r: persist_re_result(s, a, r, store=store)
            status = run_analysis_core(
                analysis_id, session, pipeline=pipeline, persist=persist,
                publish=_publish, is_canceled=_is_canceled,
            )
            return status.value

        def pipeline(_a):  # type: ignore[no-untyped-def]
            client.analyze_binary(sample_path)  # idempotent import into Ghidra
            if _a.mode is AnalysisMode.vr:
                from keystone_engine.pipelines import vr_path

                params = _a.params or {}
                resolver = None
                if not params.get("rule") and params.get("interactive"):
                    resolver = _make_rule_resolver(analysis_id)
                return vr_path.run(ref, client, rule=params.get("rule"), rule_resolver=resolver)
            return re_path.run(ref, client)

        def persist(s, a, result):  # type: ignore[no-untyped-def]
            if a.mode is AnalysisMode.vr:
                persist_vr_result(s, a, result, store=store)
            else:
                persist_re_result(s, a, result, store=store)

        status = run_analysis_core(
            analysis_id, session, pipeline=pipeline, persist=persist, publish=_publish, is_canceled=_is_canceled
        )
        return status.value
    finally:
        session.close()
