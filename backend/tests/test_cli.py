"""Management CLI: bootstrap / seed / prune-binaries (flags, dry-run, confirm)."""

from __future__ import annotations

import pytest

from keystone_api import cli
from keystone_api.db import get_session
from keystone_api.models import Binary, Project, Team, User


class FakeStore:
    def __init__(self):
        self.objects: dict[str, bytes] = {}

    def put(self, k, d):
        self.objects[k] = d

    def exists(self, k):
        return k in self.objects

    def get(self, k):
        return self.objects[k]

    def delete(self, k):
        self.objects.pop(k, None)


@pytest.fixture(autouse=True)
def _keep_test_engine(monkeypatch):
    # the CLI calls init_db() with no url; keep the in-memory test engine instead
    monkeypatch.setattr(cli, "init_db", lambda *a, **k: None)
    monkeypatch.setattr("keystone_api.storage.get_object_store", lambda: FakeStore())


def _default_project(team_id):
    s = get_session()
    try:
        return s.query(Project).filter_by(team_id=team_id, is_default=True).one().id
    finally:
        s.close()


def _add_binary(size=10, sha="s" * 64):
    s = get_session()
    try:
        team = s.query(Team).filter_by(name="Default").one()
        u = s.query(User).filter_by(username="admin").one()
        pid = s.query(Project).filter_by(team_id=team.id, is_default=True).one().id
        b = Binary(
            team_id=team.id,
            project_id=pid,
            sha256=sha,
            filename="x",
            size=size,
            storage_key="k" + sha[:6],
            uploaded_by=u.id,
        )
        s.add(b)
        s.commit()
        return b.id
    finally:
        s.close()


def _count(model):
    s = get_session()
    try:
        return s.query(model).count()
    finally:
        s.close()


def test_bootstrap(session):
    assert cli.main(["bootstrap"]) == 0
    assert cli.main(["bootstrap"]) == 0  # idempotent
    assert _count(User) == 1 and _count(Team) == 1


def test_seed(session):
    assert cli.main(["seed"]) == 0
    s = get_session()
    try:
        assert s.query(Team).filter_by(name="Blue Team").count() == 1
    finally:
        s.close()


def test_usage_and_unknown_command(session):
    assert cli.main([]) == 2
    assert cli.main(["bogus"]) == 2


def test_prune_dry_run_changes_nothing(session):
    cli.main(["bootstrap"])
    _add_binary(size=10)
    assert cli.main(["prune-binaries", "--max-bytes", "256", "--dry-run"]) == 0
    assert _count(Binary) == 1


def test_prune_no_match(session):
    cli.main(["bootstrap"])
    assert cli.main(["prune-binaries", "--id", "999"]) == 0


def test_prune_confirm_abort(session, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *_: "n")
    cli.main(["bootstrap"])
    _add_binary(size=10)
    assert cli.main(["prune-binaries", "--max-bytes", "256"]) == 1  # aborted
    assert _count(Binary) == 1


def test_prune_yes_deletes(session):
    cli.main(["bootstrap"])
    bid = _add_binary(size=10)
    assert cli.main(["prune-binaries", "--id", str(bid), "--yes"]) == 0
    assert _count(Binary) == 0


def test_init_storage_creates_the_bucket(session, monkeypatch, capsys):
    calls = []

    class FakeS3:
        def __init__(self, settings):
            pass

        def ensure_bucket(self):
            calls.append(1)
            return len(calls) == 1

    monkeypatch.setattr("keystone_api.storage.S3ObjectStore", FakeS3)
    assert cli.main(["init-storage"]) == 0
    assert cli.main(["init-storage"]) == 0
    out = capsys.readouterr().out
    assert "created" in out and "already exists" in out
