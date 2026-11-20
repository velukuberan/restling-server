"""Tests for verified email-change configuration."""

import pytest
from pydantic import SecretStr, ValidationError

from restling_server.core.config import Settings


@pytest.fixture
def config_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Provide the required database settings."""
    monkeypatch.setenv("POSTGRES_USER", "test")
    monkeypatch.setenv("POSTGRES_PASSWORD", "test")
    monkeypatch.setenv("POSTGRES_DB", "test")


def test_email_change_configuration_defaults(
    config_env: None,
) -> None:
    settings = Settings(
        postgres_user="test",
        postgres_password=SecretStr("test"),
        postgres_db="test",
    )

    assert settings.email_change_expiry_minutes == 30
    assert settings.email_change_cooldown_seconds == 60
    assert settings.email_change_hourly_limit == 5


def test_email_change_configuration_overrides(
    config_env: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("RESTLING_EMAIL_CHANGE_EXPIRY_MINUTES", "45")
    monkeypatch.setenv("RESTLING_EMAIL_CHANGE_COOLDOWN_SECONDS", "120")
    monkeypatch.setenv("RESTLING_EMAIL_CHANGE_HOURLY_LIMIT", "10")

    settings = Settings(
        postgres_user="test",
        postgres_password=SecretStr("test"),
        postgres_db="test",
    )

    assert settings.email_change_expiry_minutes == 45
    assert settings.email_change_cooldown_seconds == 120
    assert settings.email_change_hourly_limit == 10


@pytest.mark.parametrize(
    "variable",
    [
        "RESTLING_EMAIL_CHANGE_EXPIRY_MINUTES",
        "RESTLING_EMAIL_CHANGE_COOLDOWN_SECONDS",
        "RESTLING_EMAIL_CHANGE_HOURLY_LIMIT",
    ],
)
def test_email_change_configuration_rejects_zero(
    config_env: None,
    monkeypatch: pytest.MonkeyPatch,
    variable: str,
) -> None:
    monkeypatch.setenv(variable, "0")

    with pytest.raises(ValidationError):
        Settings(
            postgres_user="test",
            postgres_password=SecretStr("test"),
            postgres_db="test",
        )


def test_email_change_smtp_attempt_limit_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SMTP attempt quota defaults to ten attempts per hour."""
    monkeypatch.delenv(
        "RESTLING_EMAIL_CHANGE_SMTP_ATTEMPT_HOURLY_LIMIT",
        raising=False,
    )

    settings = Settings(
        postgres_user="test",
        postgres_password=SecretStr("test"),
        postgres_db="test",
    )

    assert settings.email_change_smtp_attempt_hourly_limit == 10


def test_email_change_smtp_attempt_limit_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Administrators can configure the SMTP attempt quota."""
    monkeypatch.setenv(
        "RESTLING_EMAIL_CHANGE_SMTP_ATTEMPT_HOURLY_LIMIT",
        "20",
    )

    settings = Settings(
        postgres_user="test",
        postgres_password=SecretStr("test"),
        postgres_db="test",
    )

    assert settings.email_change_smtp_attempt_hourly_limit == 20


def test_email_change_smtp_attempt_limit_rejects_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SMTP attempt quota must be positive."""
    monkeypatch.setenv(
        "RESTLING_EMAIL_CHANGE_SMTP_ATTEMPT_HOURLY_LIMIT",
        "0",
    )

    with pytest.raises(ValidationError):
        Settings(
            postgres_user="test",
            postgres_password=SecretStr("test"),
            postgres_db="test",
        )
