"""Unit tests for authenticated password-change request validation."""

import pytest
from pydantic import ValidationError

from restling_server.users.schemas import ChangePasswordRequest

CURRENT_PASSWORD = "A secure current password #8472"
NEW_PASSWORD = "A secure replacement password #9274"


def test_password_change_request_accepts_valid_input() -> None:
    """A valid request preserves both submitted passwords."""
    payload = ChangePasswordRequest(
        current_password=CURRENT_PASSWORD,
        new_password=NEW_PASSWORD,
    )

    assert payload.current_password == CURRENT_PASSWORD
    assert payload.new_password == NEW_PASSWORD


@pytest.mark.parametrize(
    "missing_field",
    ["current_password", "new_password"],
)
def test_password_change_request_rejects_missing_fields(
    missing_field: str,
) -> None:
    """Both password fields are required."""
    data = {
        "current_password": CURRENT_PASSWORD,
        "new_password": NEW_PASSWORD,
    }

    del data[missing_field]

    with pytest.raises(ValidationError):
        ChangePasswordRequest.model_validate(data)


def test_password_change_request_rejects_empty_current_password() -> None:
    """The current password cannot be empty."""
    with pytest.raises(ValidationError):
        ChangePasswordRequest(
            current_password="",
            new_password=NEW_PASSWORD,
        )


@pytest.mark.parametrize(
    "invalid_value",
    [None, 12345, True, [], {}],
)
@pytest.mark.parametrize(
    "field_name",
    ["current_password", "new_password"],
)
def test_password_change_request_rejects_invalid_field_types(
    field_name: str,
    invalid_value: object,
) -> None:
    """Both password fields must contain strings."""
    data: dict[str, object] = {
        "current_password": CURRENT_PASSWORD,
        "new_password": NEW_PASSWORD,
    }

    data[field_name] = invalid_value

    with pytest.raises(ValidationError):
        ChangePasswordRequest.model_validate(data)


@pytest.mark.parametrize(
    "unexpected_field",
    [
        "user_id",
        "confirm_password",
        "password_reset_required",
        "system_role",
    ],
)
def test_password_change_request_rejects_unexpected_fields(
    unexpected_field: str,
) -> None:
    """Unexpected fields cannot influence the password-change operation."""
    data = {
        "current_password": CURRENT_PASSWORD,
        "new_password": NEW_PASSWORD,
        unexpected_field: "unexpected-value",
    }

    with pytest.raises(ValidationError):
        ChangePasswordRequest.model_validate(data)


def test_password_change_request_hides_passwords_in_repr() -> None:
    """Model representations must not expose submitted passwords."""
    payload = ChangePasswordRequest(
        current_password=CURRENT_PASSWORD,
        new_password=NEW_PASSWORD,
    )

    representation = repr(payload)

    assert CURRENT_PASSWORD not in representation
    assert NEW_PASSWORD not in representation

    assert CURRENT_PASSWORD not in str(payload)
    assert NEW_PASSWORD not in str(payload)


def test_password_change_request_preserves_whitespace() -> None:
    """Password whitespace must not be silently removed."""
    current_password = "  A secure current password  "
    new_password = "  A secure replacement password  "

    payload = ChangePasswordRequest(
        current_password=current_password,
        new_password=new_password,
    )

    assert payload.current_password == current_password
    assert payload.new_password == new_password


@pytest.mark.parametrize(
    "new_password",
    [
        "",
        "short",
        "x" * 65,
        "passwordpassword",
        CURRENT_PASSWORD,
    ],
)
def test_password_change_request_defers_password_policy(
    new_password: str,
) -> None:
    """Password-policy enforcement belongs to the application service."""
    payload = ChangePasswordRequest(
        current_password=CURRENT_PASSWORD,
        new_password=new_password,
    )

    assert payload.new_password == new_password
