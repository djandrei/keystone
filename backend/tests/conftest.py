from __future__ import annotations

import pytest

from keystone_api import Settings, create_app


@pytest.fixture
def app():
    return create_app(Settings(env="test"))


@pytest.fixture
def client(app):
    return app.test_client()
