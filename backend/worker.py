"""Celery entrypoint: `celery -A worker.app worker`.

Wires the real adapters (engine pipeline + Ghidra import, MinIO persist, Redis
publish/cancel) into the framework-free `run_analysis_core`."""
from __future__ import annotations

import json

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
from keystone_engine.pipelines import BinaryRef, re_path

settings = get_settings()
app = Celery("keystone", broker=settings.redis_url, backend=settings.redis_url)


def _redis():  # type: ignore[no-untyped-def]
    import redis

    return redis.Redis.from_url(settings.redis_url)


def _publish(analysis_id: int, event: dict) -> None:
    _redis().publish(f"analysis:{analysis_id}", json.dumps(event))


def _is_canceled(analysis_id: int) -> bool:
    return bool(_redis().get(f"analysis:{analysis_id}:cancel"))


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

        def pipeline(_a):  # type: ignore[no-untyped-def]
            client.analyze_binary(sample_path)  # idempotent import into Ghidra
            if _a.mode is AnalysisMode.vr:
                from keystone_engine.pipelines import vr_path  # available from M3.3

                return vr_path.run(ref, client, rule=(_a.params or {}).get("rule"))
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
