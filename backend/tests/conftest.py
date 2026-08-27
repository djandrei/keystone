from __future__ import annotations

import pytest

from keystone_api import Settings, create_app
from keystone_api.db import Base, get_engine, get_session


@pytest.fixture
def app():
    app = create_app(Settings(env="test", database_url="sqlite://"))
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
