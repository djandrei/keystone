"""Stage 2.5: upload -> fingerprint -> store -> team-scoped row; dedup, scoping,
sniffing, size cap. Uses an in-memory object store (no MinIO)."""

from __future__ import annotations

import io
import struct

from keystone_api import Settings, create_app, services
from keystone_api.db import Base, get_engine
from keystone_api.models import AuditLog, Binary, Role, Team, TeamMember, TeamRole, User
from keystone_api.security import hash_password


class FakeStore:
    def __init__(self):
        self.objects: dict[str, bytes] = {}

    def put(self, key, data):
        self.objects[key] = data

    def exists(self, key):
        return key in self.objects

    def get(self, key):
        return self.objects[key]


def _bootstrap(session):
    services.bootstrap(session)
    session.commit()


def _tok(client, u, p):
    return client.post("/auth/login", json={"username": u, "password": p}).get_json()[
        "access_token"
    ]


def _h(tok):
    return {"Authorization": f"Bearer {tok}"}


ELF = b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 11 + struct.pack("<H", 0x3E) + b"\x00" * 40
PE = (
    b"MZ"
    + b"\x00" * 58
    + struct.pack("<I", 0x80)
    + b"\x00" * (0x80 - 0x40)
    + b"PE\x00\x00"
    + struct.pack("<H", 0x8664)
)


def _upload(client, tok, team_id, name, data):
    return client.post(
        "/binaries",
        headers=_h(tok),
        data={"team_id": str(team_id), "file": (io.BytesIO(data), name)},
        content_type="multipart/form-data",
    )


def _mk_analyst(session, name="ana", team="Blue"):
    t = Team(name=team)
    u = User(
        username=name,
        email=f"{name}@x.io",
        password_hash=hash_password("pw123456"),
        role=Role.analyst,
    )
    session.add_all([t, u])
    session.flush()
    session.add(TeamMember(team_id=t.id, user_id=u.id, team_role=TeamRole.member))
    session.commit()
    return u, t


def test_upload_stores_and_sniffs(app, client, session):
    app.config["OBJECT_STORE"] = FakeStore()
    _bootstrap(session)
    ana, team = _mk_analyst(session)
    tok = _tok(client, "ana", "pw123456")
    r = _upload(client, tok, team.id, "prog.elf", ELF)
    assert r.status_code == 201
    body = r.get_json()
    assert body["format"] == "ELF" and body["arch"] == "x86-64" and body["platform"] == "linux"
    assert len(body["sha256"]) == 64
    assert app.config["OBJECT_STORE"].exists(f"binaries/{body['sha256']}")
    assert session.query(AuditLog).filter_by(action="binary.upload").count() == 1


def test_pe_sniff(app, client, session):
    app.config["OBJECT_STORE"] = FakeStore()
    _bootstrap(session)
    ana, team = _mk_analyst(session)
    tok = _tok(client, "ana", "pw123456")
    body = _upload(client, tok, team.id, "x.exe", PE).get_json()
    assert body["format"] == "PE" and body["arch"] == "x86-64" and body["platform"] == "windows"


def test_dedup_same_bytes_same_team(app, client, session):
    store = FakeStore()
    app.config["OBJECT_STORE"] = store
    _bootstrap(session)
    ana, team = _mk_analyst(session)
    tok = _tok(client, "ana", "pw123456")
    r1 = _upload(client, tok, team.id, "a.elf", ELF)
    r2 = _upload(client, tok, team.id, "a.elf", ELF)
    assert r1.status_code == 201 and r2.status_code == 200
    assert r2.get_json().get("deduplicated") is True
    assert session.query(Binary).count() == 1
    assert len(store.objects) == 1


def test_team_scoping(app, client, session):
    app.config["OBJECT_STORE"] = FakeStore()
    _bootstrap(session)
    ana, team = _mk_analyst(session, "ana", "Blue")
    other, other_team = _mk_analyst(session, "bob", "Red")
    ana_tok = _tok(client, "ana", "pw123456")
    bob_tok = _tok(client, "bob", "pw123456")
    up = _upload(client, ana_tok, team.id, "s.elf", ELF).get_json()
    # bob (other team) cannot see ana's binary, nor upload into her team
    assert client.get(f"/binaries/{up['id']}", headers=_h(bob_tok)).status_code == 403
    assert _upload(client, bob_tok, team.id, "s.elf", ELF).status_code == 403
    # bob's list is empty; ana sees her one
    assert client.get("/binaries", headers=_h(bob_tok)).get_json() == []
    assert len(client.get("/binaries", headers=_h(ana_tok)).get_json()) == 1


def test_oversize_rejected(session):
    app = create_app(Settings(env="test", database_url="sqlite://", upload_max_bytes=10))
    import keystone_api.models  # noqa: F401

    Base.metadata.create_all(get_engine())
    app.config["OBJECT_STORE"] = FakeStore()
    client = app.test_client()
    s = None
    from keystone_api.db import get_session

    s = get_session()
    services.bootstrap(s)
    s.commit()
    ana, team = _mk_analyst(s)
    tok = client.post("/auth/login", json={"username": "ana", "password": "pw123456"}).get_json()[
        "access_token"
    ]
    r = _upload(client, tok, team.id, "big.bin", b"x" * 50)
    assert r.status_code == 413
    s.close()


def test_viewer_cannot_upload(app, client, session):
    app.config["OBJECT_STORE"] = FakeStore()
    _bootstrap(session)
    t = Team(name="V")
    v = User(username="vic", email="v@x", password_hash=hash_password("pw123456"), role=Role.viewer)
    session.add_all([t, v])
    session.flush()
    session.add(TeamMember(team_id=t.id, user_id=v.id, team_role=TeamRole.member))
    session.commit()
    tok = _tok(client, "vic", "pw123456")
    assert _upload(client, tok, t.id, "x.elf", ELF).status_code == 403
