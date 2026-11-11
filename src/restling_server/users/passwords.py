"""Password hashing and verification using Argon2id."""

from functools import lru_cache
from importlib.resources import files
from unicodedata import normalize

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError

MIN_PASSWORD_LENGTH = 15
MAX_PASSWORD_LENGTH = 64


def hash_password(password: str) -> str:
    """Generate an Argon2id hash from an NFC-normalized password."""
    hasher = PasswordHasher(type=Type.ID)

    normalized_password = normalize("NFC", password)
    return hasher.hash(normalized_password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify an NFC-normalized password against its stored hash."""
    hasher = PasswordHasher(type=Type.ID)

    normalized_password = normalize("NFC", password)

    try:
        return hasher.verify(password_hash, normalized_password)
    except (VerificationError, InvalidHashError):
        return False


def validate_password_length(password: str) -> None:
    """Validate password length after Unicode NFC normalization."""
    normalized_password = normalize("NFC", password)

    if len(normalized_password) < MIN_PASSWORD_LENGTH:
        raise ValueError("Password must contain at least 15 characters.")

    if len(normalized_password) > MAX_PASSWORD_LENGTH:
        raise ValueError("Password must not exceed 64 characters.")


@lru_cache(maxsize=1)
def _load_blocked_passwords() -> frozenset[str]:
    """Load the packaged offline password blocklist."""
    resource = files("restling_server.users").joinpath("data", "blocked_passwords.txt")

    passwords = resource.read_text(encoding="utf-8").splitlines()

    if not passwords:
        raise RuntimeError("Password blocklist is empty.")

    return frozenset(passwords)


def validate_password(password: str) -> None:
    """Validate password length and offline blocklist membership."""
    normalized_password = normalize("NFC", password)

    validate_password_length(normalized_password)

    lookup_password = normalize("NFC", normalized_password.casefold())
    if lookup_password in _load_blocked_passwords():
        raise ValueError("Password is too common or easily guessed.")
