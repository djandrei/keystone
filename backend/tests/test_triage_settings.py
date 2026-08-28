"""T1: system settings carry an optional triage model + endpoint."""

from __future__ import annotations

from keystone_api import services
from keystone_api.models import SystemSettings


def test_settings_round_trip_triage_fields(session):
    services.bootstrap(session)
    services.update_settings(
        session,
        default_model="MiniMax-M3",
        triage_model="MiniMax-M2.5",
        triage_endpoint_url="https://api.minimax.io/anthropic/v1",
    )
    session.commit()
    row = session.get(SystemSettings, 1)
    assert row.default_model == "MiniMax-M3"
    assert row.triage_model == "MiniMax-M2.5"
    assert row.triage_endpoint_url == "https://api.minimax.io/anthropic/v1"


def test_triage_fields_default_none(session):
    services.bootstrap(session)
    session.commit()
    row = session.get(SystemSettings, 1)
    assert row.triage_model is None and row.triage_endpoint_url is None
