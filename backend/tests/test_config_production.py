"""Production refuses to start on a published default or short secret.

The defaults in `config.py` and the placeholders in `infra/.env.example` are in
the public source, so a production deploy still carrying one would sign JWTs
with a key anyone can read, or seed an admin with a password anyone can guess.
"""

import pytest

from keystone_api.config import InsecureProductionConfig, Settings

DEFAULT_JWT_SECRET = Settings.model_fields["jwt_secret"].default
DEFAULT_ADMIN_PASSWORD = Settings.model_fields["admin_password"].default
STRONG_SECRET = "x7Qp2vLr9sKt4wYz8bNc3mHf6jDg1aEu"  # exactly the 32-character minimum


@pytest.mark.parametrize(
    "jwt_secret, admin_password, named",
    [
        (DEFAULT_JWT_SECRET, "a-real-admin-password", "KEYSTONE_JWT_SECRET"),
        ("change-me-in-prod", "a-real-admin-password", "KEYSTONE_JWT_SECRET"),
        ("", "a-real-admin-password", "KEYSTONE_JWT_SECRET"),
        (STRONG_SECRET[:31], "a-real-admin-password", "KEYSTONE_JWT_SECRET"),
        (STRONG_SECRET, DEFAULT_ADMIN_PASSWORD, "KEYSTONE_ADMIN_PASSWORD"),
        (STRONG_SECRET, "", "KEYSTONE_ADMIN_PASSWORD"),
    ],
)
def test_production_rejects_a_default_or_empty_secret(jwt_secret, admin_password, named):
    with pytest.raises(InsecureProductionConfig) as excinfo:
        Settings(env="production", jwt_secret=jwt_secret, admin_password=admin_password)

    message = str(excinfo.value)
    assert named in message
    # Never echo a secret — neither the rejected one nor the one that was fine.
    for secret in (jwt_secret, admin_password):
        if secret:
            assert secret not in message


def test_a_short_jwt_secret_is_rejected_with_the_minimum_stated():
    with pytest.raises(InsecureProductionConfig) as excinfo:
        Settings(
            env="production", jwt_secret=STRONG_SECRET[:31], admin_password="a-real-admin-password"
        )

    assert "at least 32 characters" in str(excinfo.value)


def test_production_names_every_offending_variable_at_once():
    with pytest.raises(InsecureProductionConfig) as excinfo:
        Settings(
            env="production",
            jwt_secret=DEFAULT_JWT_SECRET,
            admin_password=DEFAULT_ADMIN_PASSWORD,
        )

    message = str(excinfo.value)
    assert "KEYSTONE_JWT_SECRET" in message
    assert "KEYSTONE_ADMIN_PASSWORD" in message


def test_production_starts_with_real_secrets():
    cfg = Settings(
        env="production", jwt_secret=STRONG_SECRET, admin_password="a-real-admin-password"
    )

    assert len(STRONG_SECRET) == 32
    assert cfg.jwt_secret == STRONG_SECRET


@pytest.mark.parametrize("env", ["development", "test"])
def test_non_production_keeps_the_dev_defaults(env):
    cfg = Settings(env=env, jwt_secret=DEFAULT_JWT_SECRET, admin_password=DEFAULT_ADMIN_PASSWORD)

    assert cfg.jwt_secret == DEFAULT_JWT_SECRET
