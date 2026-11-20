"""Unit tests for verified email-change request validation."""

import pytest
from pydantic import ValidationError

from restling_server.users.schemas import (
    AdminChangeUserEmailRequest,
    RequestEmailChangeRequest,
    VerifyEmailChangeRequest,
)


def test_email_change_request_accepts_valid_input() -> None:
    payload = RequestEmailChangeRequest(
        email="new@example.com",
        current_password="My secure password",
    )

    assert payload.email == "new@example.com"
    assert payload.current_password == "My secure password"


@pytest.mark.parametrize(
    ("email", "password"),
    [
        ("", "valid-password"),
        ("new@example.com", ""),
    ],
)
def test_email_change_request_rejects_empty_fields(
    email: str,
    password: str,
) -> None:
    with pytest.raises(ValidationError):
        RequestEmailChangeRequest(
            email=email,
            current_password=password,
        )


@pytest.mark.parametrize(
    "missing_field",
    ["email", "current_password"],
)
def test_email_change_request_rejects_missing_fields(
    missing_field: str,
) -> None:
    data = {
        "email": "new@example.com",
        "current_password": "valid-password",
    }

    del data[missing_field]

    with pytest.raises(ValidationError):
        RequestEmailChangeRequest.model_validate(data)


def test_email_change_request_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        RequestEmailChangeRequest.model_validate(
            {
                "email": "new@example.com",
                "current_password": "valid-password",
                "system_role": "administrator",
            }
        )


def test_email_change_request_hides_password_in_repr() -> None:
    payload = RequestEmailChangeRequest(
        email="new@example.com",
        current_password="secret-password",
    )

    assert "secret-password" not in repr(payload)


def test_verify_email_change_accepts_token() -> None:
    payload = VerifyEmailChangeRequest(token="verification-token")

    assert payload.token == "verification-token"
    assert "verification-token" not in repr(payload)


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"token": ""},
        {"token": "valid-token", "unexpected": "value"},
    ],
)
def test_verify_email_change_rejects_invalid_input(
    data: dict[str, str],
) -> None:
    with pytest.raises(ValidationError):
        VerifyEmailChangeRequest.model_validate(data)


def test_admin_email_change_accepts_valid_input() -> None:
    payload = AdminChangeUserEmailRequest(
        email="new@example.com",
        current_password="admin-password",
    )

    assert payload.email == "new@example.com"
    assert payload.current_password == "admin-password"
    assert "admin-password" not in repr(payload)


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"email": "new@example.com"},
        {"current_password": "admin-password"},
        {"email": "", "current_password": "admin-password"},
        {"email": "new@example.com", "current_password": ""},
        {
            "email": "new@example.com",
            "current_password": "admin-password",
            "system_role": "administrator",
        },
    ],
)
def test_admin_email_change_rejects_invalid_input(
    data: dict[str, str],
) -> None:
    with pytest.raises(ValidationError):
        AdminChangeUserEmailRequest.model_validate(data)
