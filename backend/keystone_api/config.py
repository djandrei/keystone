"""Typed application configuration (env-driven).

Kept intentionally small for M1.0; DB / Redis / MinIO / JWT / LLM settings are
added in later stages (1.2–1.4) as the features that need them land.
"""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="KEYSTONE_", env_file=".env", extra="ignore"
    )

    env: str = "development"
    service_name: str = "keystone-api"


@lru_cache
def get_settings() -> Settings:
    return Settings()
