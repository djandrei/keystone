from __future__ import annotations

from keystone_api import services
from keystone_api.models import Role, SystemSettings, TeamMember, User
from keystone_api.security import hash_password, verify_password


def test_password_hash_and_verify():
    h = hash_password("s3cret")
    assert h != "s3cret"
    assert verify_password(h, "s3cret")
    assert not verify_password(h, "wrong")


def test_bootstrap_idempotent(session):
    r1 = services.bootstrap(session)
    session.commit()
    assert r1["admin_created"] is True
    admin = session.query(User).filter_by(username=r1["admin"]).one()
    assert admin.role is Role.admin
    # admin is a lead of the Default team
    assert session.query(TeamMember).filter_by(user_id=admin.id).count() == 1

    r2 = services.bootstrap(session)
    session.commit()
    assert r2["admin_created"] is False
    assert session.query(User).filter_by(role=Role.admin).count() == 1


def test_settings_singleton_and_update(session):
    s1 = services.get_or_create_settings(session)
    s2 = services.get_or_create_settings(session)
    assert s1.id == 1 and s2.id == 1
    services.update_settings(session, default_model="gpt-x", llm_endpoint_url="http://llm")
    session.commit()
    row = session.get(SystemSettings, 1)
    assert row.default_model == "gpt-x"
    assert row.llm_endpoint_url == "http://llm"
