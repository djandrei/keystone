"""The worker sends a binary to ghidra-headless-mcp in one request that uploads,
imports and discards it, and takes the program name from the analysis. The two
stacks share no files."""

from __future__ import annotations

import pytest

from keystone_api import services
from keystone_api.config import Settings
from keystone_api.models import Analysis, AnalysisMode, Binary, Team, User


class FakeStore:
    def __init__(self, objects):
        self.objects = objects

    def get(self, key):
        return self.objects[key]


class FakeClient:
    instances: list = []

    def __init__(self, *a, **k):
        self.calls: list = []
        FakeClient.instances.append(self)

    def import_binary(self, filename, data):
        self.calls.append(("import_binary", filename, data))
        return {"filename": filename, "analysis": {"program": f"{filename}-prog"}}


def test_pipeline_imports_with_one_call_and_uses_the_analysis_program(session, monkeypatch):
    import worker

    services.bootstrap(session)
    team = session.query(Team).filter_by(name="Default").one()
    u = session.query(User).filter_by(username="admin").one()
    b = Binary(
        team_id=team.id,
        sha256="a" * 64,
        filename="ls",
        size=4,
        storage_key="binaries/aaa",
        ghidra_program_name="ls",
        uploaded_by=u.id,
    )
    session.add(b)
    session.flush()
    a = Analysis(team_id=team.id, binary_id=b.id, mode=AnalysisMode.re, created_by=u.id)
    session.add(a)
    session.commit()

    seen = {}

    def fake_re_run(ref, client, **kw):
        seen["program"] = ref.program
        raise RuntimeError("stop after import")  # the pipeline proper is tested elsewhere

    FakeClient.instances.clear()
    monkeypatch.setattr(
        worker,
        "settings",
        Settings(env="test", database_url="sqlite://", engine_fake=False, mcp_api_key="k"),
    )
    monkeypatch.setattr(worker, "GhidraMcpClient", FakeClient)
    monkeypatch.setattr(worker, "get_object_store", lambda: FakeStore({"binaries/aaa": b"\x7fELF"}))
    monkeypatch.setattr(worker, "_publish", lambda i, e: None)
    monkeypatch.setattr(worker, "_is_canceled", lambda i: False)
    monkeypatch.setattr(worker.re_path, "run", fake_re_run)

    with pytest.raises(RuntimeError, match="stop after import"):
        worker._run_analysis(a.id, session)

    assert FakeClient.instances[0].calls == [("import_binary", f"{'a' * 64}_ls", b"\x7fELF")]
    assert seen["program"] == f"{'a' * 64}_ls-prog"
