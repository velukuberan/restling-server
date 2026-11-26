"""Unit tests for HTTP client IP resolution."""

import pytest
from fastapi import Request

from restling_server.core.client_ip import (
    ClientIPResolutionError,
    resolve_client_ip,
)


def make_request(
    *,
    client_host: str | None,
    headers: list[tuple[bytes, bytes]] | None = None,
) -> Request:
    """Create a request with a controlled ASGI client address."""
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/auth/forgot-password",
            "headers": headers if headers is not None else [],
            "client": ((client_host, 12345) if client_host is not None else None),
        }
    )


@pytest.mark.parametrize(
    ("client_host", "expected_ip"),
    [
        ("192.0.2.10", "192.0.2.10"),
        ("127.0.0.1", "127.0.0.1"),
        ("::1", "::1"),
        ("2001:db8::1", "2001:db8::1"),
        ("2001:db8:0:0:0:0:0:1", "2001:db8::1"),
        ("2001:DB8::1", "2001:db8::1"),
        ("::ffff:192.0.2.10", "192.0.2.10"),
        ("::ffff:c000:20a", "192.0.2.10"),
    ],
)
def test_resolve_client_ip_normalizes_valid_addresses(
    client_host: str,
    expected_ip: str,
) -> None:
    """Return the canonical representation of valid IP addresses."""
    request = make_request(client_host=client_host)

    assert resolve_client_ip(request) == expected_ip


@pytest.mark.parametrize(
    "client_host",
    [
        "",
        "localhost",
        "unknown",
        "999.0.0.1",
        "192.0.2.10:8080",
        "192.0.2.10, 192.0.2.11",
        "[2001:db8::1]",
        "fe80::1%eth0",
        "fe80::1%3",
        "192.0.2.10/24",
        " 192.0.2.10 ",
    ],
)
def test_resolve_client_ip_rejects_invalid_addresses(
    client_host: str,
) -> None:
    """Reject malformed or unsupported client addresses."""
    request = make_request(client_host=client_host)

    with pytest.raises(
        ClientIPResolutionError,
        match="Invalid client IP address",
    ):
        resolve_client_ip(request)


def test_resolve_client_ip_rejects_missing_client() -> None:
    """Reject requests without an ASGI client address."""
    request = make_request(client_host=None)

    with pytest.raises(
        ClientIPResolutionError,
        match="Client address is unavailable",
    ):
        resolve_client_ip(request)


@pytest.mark.parametrize(
    "headers",
    [
        [(b"x-forwarded-for", b"198.51.100.50")],
        [(b"x-real-ip", b"198.51.100.50")],
        [(b"forwarded", b"for=198.51.100.50")],
        [
            (b"x-forwarded-for", b"198.51.100.50"),
            (b"x-real-ip", b"198.51.100.51"),
            (b"forwarded", b"for=198.51.100.52"),
        ],
    ],
)
def test_resolve_client_ip_ignores_forwarding_headers(
    headers: list[tuple[bytes, bytes]],
) -> None:
    """Use the ASGI client address rather than raw HTTP headers."""
    request = make_request(
        client_host="192.0.2.10",
        headers=headers,
    )

    assert resolve_client_ip(request) == "192.0.2.10"


def test_resolve_client_ip_does_not_fallback_to_forwarding_headers() -> None:
    """Forwarding headers cannot replace a missing client address."""
    request = make_request(
        client_host=None,
        headers=[
            (b"x-forwarded-for", b"198.51.100.50"),
        ],
    )

    with pytest.raises(
        ClientIPResolutionError,
        match="Client address is unavailable",
    ):
        resolve_client_ip(request)


def test_resolve_client_ip_does_not_expose_invalid_address() -> None:
    """Resolution errors must not expose untrusted address values."""
    request = make_request(
        client_host="untrusted-client-value",
    )

    with pytest.raises(ClientIPResolutionError) as exc_info:
        resolve_client_ip(request)

    assert str(exc_info.value) == "Invalid client IP address."
    assert "untrusted-client-value" not in str(exc_info.value)
    assert exc_info.value.__suppress_context__ is True
