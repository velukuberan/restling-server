"""Unit tests for Argon2id password hashing."""

import subprocess
import sys
from importlib.resources import files

import pytest

from restling_server.users.passwords import (
    hash_password,
    validate_password,
    validate_password_length,
    verify_password,
)


def test_password_hash_uses_argon2id() -> None:
    password_hash = hash_password("a secure example passphrase")

    assert password_hash.startswith("$argon2id$")
    assert "a secure example passphrase" not in password_hash


def test_correct_password_is_accepted() -> None:
    password = "a secure example passphrase"
    password_hash = hash_password(password)

    assert verify_password(password, password_hash) is True


def test_incorrect_password_is_rejected() -> None:
    password_hash = hash_password("a secure example passphrase")

    assert verify_password("incorrect password", password_hash) is False


def test_invalid_password_hash_is_rejected() -> None:
    assert verify_password("some password", "invalid-hash") is False


def test_same_password_produces_different_hashes() -> None:
    password = "a secure example passphrase"

    first_hash = hash_password(password)
    second_hash = hash_password(password)

    assert first_hash != second_hash
    assert verify_password(password, first_hash)
    assert verify_password(password, second_hash)


@pytest.mark.parametrize(
    "password",
    [
        "a" * 15,
        "a" * 64,
        "a passphrase with spaces",
        "தமிழ் கடவுச்சொல் பாதுகாப்பு",
        "special!@#$%^&*()chars",
    ],
)
def test_valid_password_length_is_accepted(password: str) -> None:
    validate_password_length(password)


@pytest.mark.parametrize(
    "password",
    [
        "",
        "short",
        "a" * 14,
        "a" * 65,
    ],
)
def test_invalid_password_length_is_rejected(password: str) -> None:
    with pytest.raises(ValueError):
        validate_password_length(password)


def test_unicode_equivalent_passwords_verify() -> None:
    """Canonically equivalent Unicode passwords must verify."""
    password = "Caf\u00e9 secure passphrase"
    equivalent = "Cafe\u0301 secure passphrase"

    password_hash = hash_password(password)

    assert verify_password(equivalent, password_hash)


def test_unicode_equivalent_passwords_produce_same_hash_input() -> None:
    """Canonical equivalents must be normalized consistently."""
    from unicodedata import normalize

    password = "Caf\u00e9 secure passphrase"
    equivalent = "Cafe\u0301 secure passphrase"

    assert normalize("NFC", password) == normalize("NFC", equivalent)


def test_password_too_short_after_normalization_is_rejected() -> None:
    """Password length is checked after NFC normalization."""
    password = "e\u0301" * 14

    with pytest.raises(ValueError):
        validate_password_length(password)


def test_password_with_valid_normalized_length_is_accepted() -> None:
    """A password is accepted when its NFC length is valid."""
    password = "e\u0301" * 15

    validate_password_length(password)


def test_blocklisted_password_is_rejected() -> None:
    """A password in the packaged blocklist must be rejected."""
    resource = files("restling_server.users").joinpath("data", "blocked_passwords.txt")
    blocked_password = resource.read_text(encoding="utf-8").splitlines()[0]

    with pytest.raises(ValueError, match="too common"):
        validate_password(blocked_password)


def test_blocklist_matching_is_case_insensitive() -> None:
    """Case changes must not bypass the blocklist."""
    resource = files("restling_server.users").joinpath("data", "blocked_passwords.txt")
    blocked_password = resource.read_text(encoding="utf-8").splitlines()[0]

    with pytest.raises(ValueError, match="too common"):
        validate_password(blocked_password.upper())


def test_valid_passphrase_is_accepted() -> None:
    """An acceptable passphrase passes the password policy."""
    validate_password("A reasonably unique example phrase #8472")


def test_password_verification_is_case_sensitive() -> None:
    """Password authentication must preserve case sensitivity."""
    password = "My Unique Secure Passphrase #8472"
    password_hash = hash_password(password)

    assert verify_password(password, password_hash)
    assert not verify_password(password.lower(), password_hash)
    assert not verify_password(password.upper(), password_hash)


def test_missing_blocklist_prevents_password_validation() -> None:
    """An unavailable blocklist must prevent password validation."""
    script = """
from unittest.mock import patch

from restling_server.users.passwords import validate_password

with patch(
    "restling_server.users.passwords.files",
    side_effect=FileNotFoundError("Blocklist unavailable"),
):
    try:
        validate_password("A reasonably unique example phrase #8472")
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("Password validation did not fail securely")
"""

    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
