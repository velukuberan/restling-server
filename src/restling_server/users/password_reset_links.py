"""Construct trusted password-reset links."""

from urllib.parse import urlencode

from restling_server.core.config import Settings


class PasswordResetURLNotConfiguredError(Exception):
    """The server has no trusted public URL configured."""


def build_password_reset_url(
    settings: Settings,
    *,
    token: str,
) -> str:
    """Build a password-reset link from the trusted public URL."""
    if settings.public_url is None:
        raise PasswordResetURLNotConfiguredError(
            "RESTLING_PUBLIC_URL must be configured."
        )

    base_url = str(settings.public_url).rstrip("/")
    query = urlencode({"token": token})

    return f"{base_url}/reset-password?{query}"
