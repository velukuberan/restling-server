"""Unit tests for trusted account activation links."""

from urllib.parse import parse_qs, urlsplit

import pytest

from restling_server.core.config import Settings
from restling_server.users.activation_links import (
    ActivationURLNotConfiguredError,
    build_activation_url,
)


def make_settings(public_url: str | None = None) -> Settings:
    """Create settings with an explicitly configured public URL."""
    return Settings.model_validate(
        {
            "postgres_user": "test_user",
            "postgres_password": "test_password",
            "postgres_db": "test_db",
            "RESTLING_PUBLIC_URL": public_url,
        }
    )


@pytest.mark.parametrize(
    ("public_url", "expected_url"),
    [
        (
            "https://restling.example.com",
            "https://restling.example.com/activate?token=test-token",
        ),
        (
            "https://restling.example.com:8443",
            "https://restling.example.com:8443/activate?token=test-token",
        ),
        (
            "http://localhost:8000",
            "http://localhost:8000/activate?token=test-token",
        ),
    ],
)
def test_activation_link_uses_trusted_public_url(
    public_url: str,
    expected_url: str,
) -> None:
    """Build activation links using the configured application URL."""
    settings = make_settings(public_url)

    result = build_activation_url(settings, token="test-token")

    assert result == expected_url


def test_activation_link_encodes_token() -> None:
    """Encode reserved characters in the URL query string."""
    settings = make_settings("https://restling.example.com")
    token = "token+with/special=characters&more"

    result = build_activation_url(settings, token=token)
    parsed = urlsplit(result)

    assert parsed.path == "/activate"
    assert parse_qs(parsed.query) == {"token": [token]}


def test_activation_link_requires_public_url() -> None:
    """Reject link construction without a trusted public URL."""
    settings = make_settings()

    with pytest.raises(ActivationURLNotConfiguredError):
        build_activation_url(settings, token="test-token")
