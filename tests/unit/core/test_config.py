"""Unit tests for server configuration validation."""

import pytest
from pydantic import ValidationError

from restling_server.core.config import Settings


def make_settings(
    public_url: str,
    **overrides: object,
) -> Settings:
    """Build settings without depending on local environment files."""
    return Settings.model_validate(
        {
            "postgres_user": "test_user",
            "postgres_password": "test_password",
            "postgres_db": "test_db",
            "RESTLING_PUBLIC_URL": public_url,
            **overrides,
        }
    )


@pytest.mark.parametrize(
    "public_url",
    [
        "https://restling.example.com",
        "https://restling.example.com:8443",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://[::1]:8000",
    ],
)
def test_trusted_public_urls_are_accepted(public_url: str) -> None:
    """Allow HTTPS and local development HTTP URLs."""
    settings = make_settings(public_url)

    assert settings.public_url is not None


@pytest.mark.parametrize(
    "public_url",
    [
        "http://restling.example.com",
        "http://192.168.1.100:8000",
        "https://user:password@restling.example.com",
        "https://restling.example.com?token=abc",
        "https://restling.example.com#activation",
        "not-a-url",
    ],
)
def test_untrusted_public_urls_are_rejected(public_url: str) -> None:
    """Reject insecure or malformed public URLs."""
    with pytest.raises(ValidationError):
        make_settings(public_url)


def test_smtp_is_disabled_by_default() -> None:
    """SMTP remains optional for self-hosted installations."""
    settings = make_settings("http://localhost:8000")

    assert settings.smtp_host is None
    assert settings.smtp_username is None
    assert settings.smtp_password is None
    assert settings.smtp_from_email is None


def test_authenticated_smtp_configuration_is_accepted() -> None:
    """Allow a complete authenticated SMTP configuration."""
    settings = make_settings(
        "https://restling.example.com",
        RESTLING_SMTP_HOST="smtp.example.com",
        RESTLING_SMTP_PORT=587,
        RESTLING_SMTP_SECURITY="starttls",
        RESTLING_SMTP_USERNAME="restling",
        RESTLING_SMTP_PASSWORD="example-test-password",
        RESTLING_SMTP_FROM_EMAIL="noreply@example.com",
    )

    assert settings.smtp_host == "smtp.example.com"
    assert settings.smtp_port == 587
    assert settings.smtp_security == "starttls"
    assert settings.smtp_username == "restling"
    assert settings.smtp_password is not None
    assert settings.smtp_password.get_secret_value() == "example-test-password"
    assert str(settings.smtp_from_email) == "noreply@example.com"


def test_smtp_without_authentication_is_accepted() -> None:
    """Support SMTP servers that don't require authentication."""
    settings = make_settings(
        "http://localhost:8000",
        RESTLING_SMTP_HOST="localhost",
        RESTLING_SMTP_SECURITY="none",
        RESTLING_SMTP_FROM_EMAIL="restling@example.com",
    )

    assert settings.smtp_host == "localhost"
    assert settings.smtp_username is None
    assert settings.smtp_password is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"RESTLING_SMTP_HOST": ""},
        {"RESTLING_SMTP_HOST": "smtp.example.com"},
        {"RESTLING_SMTP_USERNAME": "restling"},
        {"RESTLING_SMTP_PASSWORD": "secret"},
        {
            "RESTLING_SMTP_HOST": "smtp.example.com",
            "RESTLING_SMTP_FROM_EMAIL": "invalid-email",
        },
        {
            "RESTLING_SMTP_HOST": "smtp.example.com",
            "RESTLING_SMTP_FROM_EMAIL": "noreply@example.com",
            "RESTLING_SMTP_USERNAME": "restling",
        },
        {
            "RESTLING_SMTP_HOST": "smtp.example.com",
            "RESTLING_SMTP_FROM_EMAIL": "noreply@example.com",
            "RESTLING_SMTP_PASSWORD": "secret",
        },
        {
            "RESTLING_SMTP_HOST": "smtp.example.com",
            "RESTLING_SMTP_FROM_EMAIL": "noreply@example.com",
            "RESTLING_SMTP_PORT": 0,
        },
        {
            "RESTLING_SMTP_HOST": "smtp.example.com",
            "RESTLING_SMTP_FROM_EMAIL": "noreply@example.com",
            "RESTLING_SMTP_SECURITY": "invalid",
        },
    ],
)
def test_incomplete_smtp_configuration_is_rejected(
    overrides: dict[str, object],
) -> None:
    """Reject invalid or incomplete SMTP settings."""
    with pytest.raises(ValidationError):
        make_settings(
            "https://restling.example.com",
            **overrides,
        )


@pytest.mark.parametrize(
    "smtp_host",
    [
        "smtp.example.com",
        "192.168.1.100",
    ],
)
def test_unencrypted_remote_smtp_is_rejected(
    smtp_host: str,
) -> None:
    """Never permit unencrypted SMTP connections to remote hosts."""
    with pytest.raises(ValidationError):
        make_settings(
            "https://restling.example.com",
            RESTLING_SMTP_HOST=smtp_host,
            RESTLING_SMTP_SECURITY="none",
            RESTLING_SMTP_FROM_EMAIL="noreply@example.com",
        )


@pytest.mark.parametrize(
    "smtp_host",
    [
        "localhost",
        "127.0.0.1",
        "::1",
    ],
)
def test_unencrypted_local_smtp_is_accepted(
    smtp_host: str,
) -> None:
    """Permit local development mail servers without TLS."""
    settings = make_settings(
        "http://localhost:8000",
        RESTLING_SMTP_HOST=smtp_host,
        RESTLING_SMTP_SECURITY="none",
        RESTLING_SMTP_FROM_EMAIL="noreply@example.com",
    )

    assert settings.smtp_host == smtp_host
    assert settings.smtp_security == "none"


def test_unencrypted_smtp_with_credentials_is_rejected() -> None:
    """Never transmit SMTP authentication credentials without TLS."""
    with pytest.raises(ValidationError):
        make_settings(
            "http://localhost:8000",
            RESTLING_SMTP_HOST="localhost",
            RESTLING_SMTP_SECURITY="none",
            RESTLING_SMTP_FROM_EMAIL="noreply@example.com",
            RESTLING_SMTP_USERNAME="restling",
            RESTLING_SMTP_PASSWORD="test-password",
        )
