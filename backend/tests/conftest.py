from __future__ import annotations

import pytest

from keystone_api import Settings, create_app
from keystone_api.db import Base, get_engine, get_session


@pytest.fixture
def app():
    app = create_app(Settings(env="test", database_url="sqlite://"))
    # Record instead of sending. Without these the analyses API falls back to the
    # real Celery broker and Redis, so a test run inside a live stack turns each
    # analysis it creates into a real run of the live database's analysis with
    # that id. A test that installs its own stand-in replaces these.
    app.config["ENQUEUE"] = lambda aid: app.config.setdefault("_enqueued", []).append(aid)
    app.config["CANCEL_SIGNAL"] = lambda aid: app.config.setdefault("_canceled", []).append(aid)
    app.config["RULE_SIGNAL"] = lambda aid, rule: app.config.setdefault("_rules", []).append(
        (aid, rule)
    )
    import keystone_api.models  # noqa: F401  register tables

    Base.metadata.create_all(get_engine())
    return app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def session(app):
    s = get_session()
    try:
        yield s
    finally:
        s.rollback()
        s.close()
