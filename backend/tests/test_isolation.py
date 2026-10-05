"""Tests must never reach the live job queue or Redis.

The analyses API enqueues a Celery task and sets Redis keys unless the app
config supplies stand-ins. Run inside a stack (`docker compose exec backend
pytest`), the fallbacks used the real broker: every analysis a test created
became a real `run_analysis(<id>)` for the live database's analysis of that id,
and cancel/rule keys could reach a live analysis. conftest's `app` fixture
installs recording stand-ins by default."""

from __future__ import annotations


def test_enqueue_and_signals_are_recorded_not_sent(app):
    from keystone_api import analyses_api

    with app.app_context():
        analyses_api._enqueue(1)
        analyses_api._signal_cancel(2)
        analyses_api._signal_rule(3, "cwe-787")

    assert app.config["_enqueued"] == [1]
    assert app.config["_canceled"] == [2]
    assert app.config["_rules"] == [(3, "cwe-787")]
