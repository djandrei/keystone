"""Global error handlers: JSON HTTPExceptions + generic 500 with logging/no leak."""

from __future__ import annotations

import pytest

from keystone_api import Settings, create_app
from keystone_api.errors import http_error_slug


def test_unknown_route_returns_json_404(app, client):
    r = client.get("/definitely-not-a-route")
    assert r.status_code == 404
    assert r.get_json() == {"error": "not_found"}


def test_method_not_allowed_returns_json(app, client):
    # /healthz is GET-only -> POST raises MethodNotAllowed (405)
    r = client.post("/healthz")
    assert r.status_code == 405
    assert r.get_json() == {"error": "method_not_allowed"}


def test_http_error_slug():
    from werkzeug.exceptions import MethodNotAllowed, NotFound

    assert http_error_slug(NotFound()) == "not_found"
    assert http_error_slug(MethodNotAllowed()) == "method_not_allowed"


def _prod_app_with_boom():
    """A non-test app (testing/debug off) so the generic handler renders a 500
    instead of re-raising, with a route that raises an unexpected error."""
    app = create_app(Settings(env="development", database_url="sqlite://"))
    import keystone_api.models  # noqa: F401

    @app.get("/_boom")
    def _boom():  # type: ignore[no-untyped-def]
        raise RuntimeError("secret internal detail")

    return app


def test_unhandled_exception_returns_generic_500(caplog):
    app = _prod_app_with_boom()
    with caplog.at_level("ERROR"):
        r = app.test_client().get("/_boom")
    assert r.status_code == 500
    assert r.get_json() == {"error": "internal_error"}
    # the exception text must not leak to the client
    assert "secret internal detail" not in r.get_data(as_text=True)
    # but it IS logged server-side (with the traceback via log.exception)
    assert any("unhandled_exception" in rec.message for rec in caplog.records)


def test_testing_reraises_so_pytest_sees_bugs():
    # env="test" -> app.testing True -> the generic handler re-raises
    app = create_app(Settings(env="test", database_url="sqlite://"))
    import keystone_api.models  # noqa: F401

    @app.get("/_boom")
    def _boom():  # type: ignore[no-untyped-def]
        raise RuntimeError("kaboom")

    with pytest.raises(RuntimeError, match="kaboom"):
        app.test_client().get("/_boom")
