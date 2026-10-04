"""Typed application configuration (env-driven, `KEYSTONE_` prefix).

Front-loads the settings later stages need (DB, Redis, S3, JWT, admin bootstrap,
MCP, LLM key) so those stages consume config rather than re-editing this file.
Non-secret defaults match `infra/.env.example` for a friction-free dev up.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="KEYSTONE_", env_file=".env", extra="ignore")

    # --- app ---
    env: str = "development"
    service_name: str = "keystone-api"

    # --- database ---
    database_url: str = "postgresql+psycopg://keystone:keystone@postgres:5432/keystone"

    # --- redis / jobs (M2) ---
    redis_url: str = "redis://redis:6379/0"

    # --- object storage: S3 (VersityGW in compose) (M2) ---
    s3_endpoint: str = "http://s3:7070"
    s3_bucket: str = "keystone"
    s3_access_key: str = "keystone"
    s3_secret_key: str = "keystone-dev-secret"

    # --- auth / JWT (M1.4) ---
    jwt_secret: str = "dev-insecure-secret-change-me-in-production-0123456789"
    access_ttl_min: int = 15
    refresh_ttl_days: int = 14

    # --- first-run admin bootstrap (M1.3) ---
    admin_username: str = "admin"
    admin_email: str = "admin@keystone.local"
    admin_password: str = "change-me"

    # --- uploads / storage (M2.5) ---
    upload_max_bytes: int = 104_857_600  # 100 MiB
    sample_dir: str = "/samples"  # shared volume where uploads are written for Ghidra import

    # --- ghidra-headless-mcp (M2) ---
    mcp_endpoint: str = "http://ghidra-headless-mcp:1341"
    # Bearer token for the authenticated MCP server. Deployment secret — never in
    # the DB. Must equal the server's GHMCP_API_KEY (compose feeds both from one var).
    mcp_api_key: str = ""

    # --- VR / semgrep ---
    # Semgrep ruleset for decompiled code. A path (bundled rules), a registry
    # config like "p/c", or "auto".
    semgrep_config: str = "/app/semgrep-rules/decompiled-c.yaml"

    # --- observability (M5.1) ---
    sentry_dsn: str = ""

    # --- engine ---
    # Fake engine: run a deterministic canned pipeline (no Ghidra/LLM) — used by
    # the M2 e2e so the full async path is provable without external services.
    engine_fake: bool = False

    # --- LLM (endpoint + default model live in system_settings; key is a secret) ---
    llm_api_key: str = ""
    # Optional separate key for the triage endpoint; blank -> reuse llm_api_key.
    triage_api_key: str = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()
