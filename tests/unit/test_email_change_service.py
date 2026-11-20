"""Unit tests for verified email-change business rules."""

import pytest

from restling_server.users.service import _normalize_email_change_target  # pyright: ignore[reportPrivateUsage]


def test_email_change_normalizes_email() -> None:
    original, normalized = _normalize_email_change_target("  John@Example.COM  ")

    assert original == "John@Example.COM"
    assert normalized == "john@example.com"


def test_email_change_normalization_detects_same_identity() -> None:
    _, normalized = _normalize_email_change_target("John@Example.COM")

    assert normalized == "john@example.com"


@pytest.mark.parametrize(
    "email",
    [
        "",
        "   ",
        "not-an-email",
        "user@",
        "@example.com",
    ],
)
def test_email_change_rejects_invalid_email(
    email: str,
) -> None:
    with pytest.raises(ValueError, match="Invalid email address"):
        _normalize_email_change_target(email)
