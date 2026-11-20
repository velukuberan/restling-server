"""Construct trusted email-change verification links."""

from urllib.parse import urlencode

from restling_server.core.config import Settings


class EmailChangeURLNotConfiguredError(Exception):
    """The server has no trusted public URL configured."""


def build_email_change_url(
    settings: Settings,
    *,
    token: str,
) -> str:
    """Build an email-change verification link from the trusted public URL."""
    if settings.public_url is None:
        raise EmailChangeURLNotConfiguredError(
            "RESTLING_PUBLIC_URL must be configured."
        )

    base_url = str(settings.public_url).rstrip("/")
    query = urlencode({"token": token})

    return f"{base_url}/verify-email-change?{query}"
