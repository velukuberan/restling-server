"""Cryptographic helpers for one-time credentials."""

import hashlib
import secrets


def generate_token() -> str:
    """Generate a cryptographically secure one-time credential."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Return the SHA-256 hex digest of a one-time credential."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
