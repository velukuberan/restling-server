"""Tests for trusted email-change verification URLs."""

import pytest
from pydantic import SecretStr

from restling_server.core.config import Settings
from restling_server.users.email_change_links import (
    EmailChangeURLNotConfiguredError,
    build_email_change_url,
)


def test_build_email_change_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Build a verification URL using the trusted public URL."""
    monkeypatch.setenv(
        "RESTLING_PUBLIC_URL",
        "https://restling.example.com",
    )

    settings = Settings(
        postgres_user="test",
        postgres_password=SecretStr("test"),
        postgres_db="test",
    )

    result = build_email_change_url(
        settings,
        token="sample-token",
    )

    assert (
        result == "https://restling.example.com/verify-email-change?token=sample-token"
    )


def test_email_change_url_requires_public_url() -> None:
    """Reject verification-link generation without a trusted public URL."""
    settings = Settings(
        postgres_user="test",
        postgres_password=SecretStr("test"),
        postgres_db="test",
    )

    settings.public_url = None

    with pytest.raises(
        EmailChangeURLNotConfiguredError,
        match="RESTLING_PUBLIC_URL must be configured",
    ):
        build_email_change_url(
            settings,
            token="sample-token",
        )
