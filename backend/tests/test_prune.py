"""prune_binaries: delete binaries + attached analyses/objects, with
dedup-aware object removal and a non-destructive dry run."""

from __future__ import annotations

from keystone_api import services
from keystone_api.models import Analysis, AnalysisMode, Binary, Team, User
from keystone_api.prune import prune_binaries


class FakeStore:
    def __init__(self):
        self.objects: dict[str, bytes] = {}

    def put(self, key, data):
        self.objects[key] = data

    def exists(self, key):
        return key in self.objects

    def get(self, key):
        return self.objects[key]

    def delete(self, key):
        self.objects.pop(key, None)


def _seed(session):
    services.bootstrap(session)
    team = session.query(Team).filter_by(name="Default").one()
    u = session.query(User).filter_by(username="admin").one()
    store = FakeStore()

    def mk(sha, name, size, *, storage_key=None, analyses=0):
        key = storage_key or f"binaries/{sha}"
        b = Binary(
            team_id=team.id,
            sha256=sha,
            filename=name,
            size=size,
            storage_key=key,
            ghidra_program_name=name,
            uploaded_by=u.id,
        )
        session.add(b)
        session.flush()
        store.put(key, b"x" * size)
        for _ in range(analyses):
            session.add(
                Analysis(team_id=team.id, binary_id=b.id, mode=AnalysisMode.re, created_by=u.id)
            )
        session.commit()
        return b

    return store, mk


def test_prune_by_max_bytes(session):
    store, mk = _seed(session)
    stub = mk("s" * 64, "ls", 64, analyses=2)
    real = mk("r" * 64, "crackme", 20000, analyses=1)

    res = prune_binaries(session, store, max_bytes=256)

    assert res["binaries"] == 1 and res["analyses"] == 2
    assert res["objects"] == 1
    # only the real binary + its analysis survive
    assert [b.id for b in session.query(Binary).all()] == [real.id]
    assert session.query(Analysis).count() == 1
    assert stub.storage_key not in store.objects and real.storage_key in store.objects


def test_dry_run_changes_nothing(session):
    store, mk = _seed(session)
    mk("s" * 64, "ls", 64, analyses=2)
    mk("r" * 64, "crackme", 20000)

    res = prune_binaries(session, store, max_bytes=256, dry_run=True)

    assert res["binaries"] == 1 and res["analyses"] == 2
    assert res["matched"] == [{"id": 1, "filename": "ls", "size": 64}]
    # nothing actually removed
    assert session.query(Binary).count() == 2
    assert f"binaries/{'s' * 64}" in store.objects


def test_prune_by_ids(session):
    store, mk = _seed(session)
    a = mk("a" * 64, "one", 10000)
    b = mk("b" * 64, "two", 10000)

    res = prune_binaries(session, store, ids=[a.id])

    assert res["binaries"] == 1
    assert [x.id for x in session.query(Binary).all()] == [b.id]


def test_shared_object_deleted_only_once(session):
    # two binaries (dedup) pointing at the same object: the object goes only when
    # the last referrer is removed.
    store, mk = _seed(session)
    mk("1" * 64, "dup1", 64, storage_key="binaries/shared")
    mk("2" * 64, "dup2", 64, storage_key="binaries/shared")

    res = prune_binaries(session, store, max_bytes=256)

    assert res["binaries"] == 2 and res["objects"] == 1  # deleted once, not twice
    assert "binaries/shared" not in store.objects


def test_select_nothing_is_noop(session):
    store, mk = _seed(session)
    mk("r" * 64, "crackme", 20000)
    res = prune_binaries(session, store)  # neither ids nor max_bytes
    assert res == {"binaries": 0, "analyses": 0, "objects": 0, "matched": []}
    assert session.query(Binary).count() == 1


def test_s3_store_delete_calls_delete_object():
    from keystone_api.storage import S3ObjectStore

    store = S3ObjectStore.__new__(S3ObjectStore)
    store._bucket = "bkt"
    calls = []

    class _Client:
        def delete_object(self, **kw):
            calls.append(kw)

    store._client = _Client()
    store.delete("binaries/abc")
    assert calls == [{"Bucket": "bkt", "Key": "binaries/abc"}]
