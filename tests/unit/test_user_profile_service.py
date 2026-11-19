"""Unit tests for profile update business invariants."""

import pytest

from restling_server.users.models import User
from restling_server.users.service import _apply_profile_changes  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize(
    "changes",
    [
        {"display_name": None},
        {"display_name": ""},
        {"display_name": "   "},
        {"display_name": "a" * 151},
        {"job_title": "a" * 101},
        {"email": "new@example.com"},
        {"system_role": "administrator"},
    ],
)
def test_invalid_profile_changes_are_rejected_atomically(
    changes: dict[str, str | None],
) -> None:
    """Invalid service inputs must not modify any profile field."""
    user = User(
        email="profile@example.com",
        normalized_email="profile@example.com",
        display_name="Original Name",
        job_title="Original Job",
        status="active",
        system_role="user",
    )

    with pytest.raises(ValueError):
        _apply_profile_changes(
            user,
            {
                "display_name": "Updated Name",
                **changes,
            },
        )

    assert user.display_name == "Original Name"
    assert user.job_title == "Original Job"
    assert user.email == "profile@example.com"
    assert user.system_role == "user"


def test_profile_service_normalizes_valid_changes() -> None:
    """The service normalizes values independently of HTTP validation."""
    user = User(
        display_name="Original Name",
        job_title="Original Job",
    )

    changed_fields = _apply_profile_changes(
        user,
        {
            "display_name": "  Updated Name  ",
            "job_title": "   ",
        },
    )

    assert changed_fields == ["display_name", "job_title"]
    assert user.display_name == "Updated Name"
    assert user.job_title is None


def test_identical_profile_changes_are_no_op() -> None:
    """Unchanged values produce no modifications."""
    user = User(
        display_name="Original Name",
        job_title=None,
    )

    changed_fields = _apply_profile_changes(
        user,
        {
            "display_name": " Original Name ",
            "job_title": None,
        },
    )

    assert changed_fields == []
