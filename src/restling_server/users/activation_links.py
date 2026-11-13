"""Construct trusted account activation links."""

from urllib.parse import urlencode

from restling_server.core.config import Settings


class ActivationURLNotConfiguredError(Exception):
    """The server has no trusted public URL configured."""


def build_activation_url(settings: Settings, *, token: str) -> str:
    """Build an activation link from the configured public URL."""
    if settings.public_url is None:
        raise ActivationURLNotConfiguredError("RESTLING_PUBLIC_URL must be configured.")

    base_url = str(settings.public_url).rstrip("/")
    query = urlencode({"token": token})

    return f"{base_url}/activate?{query}"
