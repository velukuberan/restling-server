"""Integration tests for trusted proxy client-IP resolution."""

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from restling_server.core.client_ip import resolve_client_ip


def create_test_app() -> FastAPI:
    """Create a minimal HTTP application for client-IP resolution."""
    app = FastAPI()

    @app.get("/client-ip")
    def client_ip(request: Request) -> dict[str, str]:
        return {"client_ip": resolve_client_ip(request)}

    return app


@pytest.mark.parametrize(
    ("peer_ip", "trusted_hosts", "forwarded_for", "expected_ip"),
    [
        # Untrusted peers cannot override their connection address.
        (
            "192.0.2.10",
            "127.0.0.1",
            "198.51.100.50",
            "192.0.2.10",
        ),
        # A trusted local proxy can forward the client address.
        (
            "127.0.0.1",
            "127.0.0.1",
            "192.0.2.10",
            "192.0.2.10",
        ),
        # Explicitly trusted remote proxy.
        (
            "10.0.0.10",
            "10.0.0.10",
            "192.0.2.10",
            "192.0.2.10",
        ),
        # Proxy within a trusted network.
        (
            "10.0.0.10",
            "10.0.0.0/24",
            "192.0.2.10",
            "192.0.2.10",
        ),
        # Proxy outside a trusted network.
        (
            "10.0.1.10",
            "10.0.0.0/24",
            "198.51.100.50",
            "10.0.1.10",
        ),
        # Multiple explicitly trusted proxies.
        (
            "10.0.0.10",
            "10.0.0.10,10.0.0.11",
            "192.0.2.10, 10.0.0.11",
            "192.0.2.10",
        ),
        # A forged leftmost address must not override
        # the rightmost untrusted client address.
        (
            "10.0.0.10",
            "10.0.0.10",
            "198.51.100.50, 192.0.2.10",
            "192.0.2.10",
        ),
        # Stop at the first untrusted intermediary.
        (
            "10.0.0.10",
            "10.0.0.10",
            "198.51.100.50, 10.0.1.10",
            "10.0.1.10",
        ),
        # Trusted IPv6 proxy.
        (
            "::1",
            "::1",
            "2001:db8::10",
            "2001:db8::10",
        ),
        # Canonicalize a forwarded IPv6 client address.
        (
            "127.0.0.1",
            "127.0.0.1",
            "2001:db8:0:0:0:0:0:10",
            "2001:db8::10",
        ),
        # Canonicalize a forwarded IPv4-mapped IPv6 address.
        (
            "127.0.0.1",
            "127.0.0.1",
            "::ffff:192.0.2.10",
            "192.0.2.10",
        ),
    ],
)
def test_proxy_headers_respect_trusted_hosts(
    peer_ip: str,
    trusted_hosts: str,
    forwarded_for: str,
    expected_ip: str,
) -> None:
    """Resolve forwarded addresses only through trusted proxies."""
    app = create_test_app()

    app.add_middleware(
        ProxyHeadersMiddleware,
        trusted_hosts=trusted_hosts,
    )

    with TestClient(
        app,
        client=(peer_ip, 12345),
    ) as client:
        response = client.get(
            "/client-ip",
            headers={
                "X-Forwarded-For": forwarded_for,
            },
        )

    assert response.status_code == 200
    assert response.json() == {
        "client_ip": expected_ip,
    }


def test_proxy_headers_disabled_ignores_forwarded_address() -> None:
    """Direct deployments must ignore forwarding headers."""
    app = create_test_app()

    with TestClient(
        app,
        client=("127.0.0.1", 12345),
    ) as client:
        response = client.get(
            "/client-ip",
            headers={
                "X-Forwarded-For": "198.51.100.50",
            },
        )

    assert response.status_code == 200
    assert response.json() == {
        "client_ip": "127.0.0.1",
    }


def test_trusted_proxy_without_forwarding_header() -> None:
    """Without a forwarded address, retain the connection address."""
    app = create_test_app()

    app.add_middleware(
        ProxyHeadersMiddleware,
        trusted_hosts="127.0.0.1",
    )

    with TestClient(
        app,
        client=("127.0.0.1", 12345),
    ) as client:
        response = client.get("/client-ip")

    assert response.status_code == 200
    assert response.json() == {
        "client_ip": "127.0.0.1",
    }


@pytest.mark.parametrize(
    "header_name",
    [
        "X-Real-IP",
        "Forwarded",
    ],
)
def test_proxy_headers_do_not_use_alternative_ip_headers(
    header_name: str,
) -> None:
    """Alternative forwarding headers must not override the peer."""
    app = create_test_app()

    app.add_middleware(
        ProxyHeadersMiddleware,
        trusted_hosts="127.0.0.1",
    )

    with TestClient(
        app,
        client=("127.0.0.1", 12345),
    ) as client:
        response = client.get(
            "/client-ip",
            headers={
                header_name: "198.51.100.50",
            },
        )

    assert response.status_code == 200
    assert response.json() == {
        "client_ip": "127.0.0.1",
    }
