"""T2: triage LM target resolution + fallback."""

from __future__ import annotations

from keystone_api import services
from keystone_api.config import Settings
from keystone_api.llm_config import resolve_triage_target
from keystone_api.models import SystemSettings


def _settings(session, **fields):
    services.bootstrap(session)
    services.update_settings(
        session, llm_endpoint_url="https://main/api", default_model="Big", **fields
    )
    session.commit()
    return session.get(SystemSettings, 1)


def test_none_when_triage_model_blank(session):
    s = _settings(session)  # no triage_model
    assert resolve_triage_target(s, Settings(env="test")) is None


def test_falls_back_to_analysis_endpoint_and_key(session):
    s = _settings(session, triage_model="Small")  # no triage endpoint/key
    assert resolve_triage_target(s, Settings(env="test", llm_api_key="K")) == (
        "https://main/api",
        "Small",
        "K",
    )


def test_separate_endpoint_and_key(session):
    s = _settings(session, triage_model="Small", triage_endpoint_url="https://triage/api")
    got = resolve_triage_target(s, Settings(env="test", llm_api_key="K", triage_api_key="TK"))
    assert got == ("https://triage/api", "Small", "TK")


def test_none_when_no_endpoint_anywhere(session):
    services.bootstrap(session)
    services.update_settings(
        session, default_model="Big", triage_model="Small"
    )  # no llm_endpoint_url
    session.commit()
    assert resolve_triage_target(session.get(SystemSettings, 1), Settings(env="test")) is None
