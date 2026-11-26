"""Resolve client IP addresses at the HTTP boundary."""

from ipaddress import IPv6Address, ip_address

from fastapi import Request


class ClientIPResolutionError(Exception):
    """A valid client IP address could not be resolved."""


def resolve_client_ip(request: Request) -> str:
    """Return the validated client IP resolved by the ASGI server."""
    if request.client is None:
        raise ClientIPResolutionError("Client address is unavailable.")

    try:
        address = ip_address(request.client.host)

    except ValueError:
        raise ClientIPResolutionError("Invalid client IP address.") from None

    if isinstance(address, IPv6Address):
        if address.scope_id is not None:
            raise ClientIPResolutionError("Invalid client IP address.")

        if address.ipv4_mapped is not None:
            address = address.ipv4_mapped

    return str(address)
