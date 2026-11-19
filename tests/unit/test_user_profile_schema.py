"""Unit tests for user profile update validation."""

import pytest
from pydantic import ValidationError

from restling_server.users.schemas import UpdateUserProfileRequest


def test_profile_update_normalizes_fields() -> None:
    payload = UpdateUserProfileRequest(
        display_name="  John Smith  ",
        job_title="  Backend Engineer  ",
    )

    assert payload.display_name == "John Smith"
    assert payload.job_title == "Backend Engineer"


def test_profile_update_distinguishes_omitted_fields() -> None:
    payload = UpdateUserProfileRequest(job_title=None)

    assert payload.model_fields_set == {"job_title"}
    assert payload.job_title is None

    empty_payload = UpdateUserProfileRequest()

    assert empty_payload.model_fields_set == set()


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "   ",
        "a" * 151,
    ],
)
def test_profile_update_rejects_invalid_display_name(
    value: str | None,
) -> None:
    with pytest.raises(ValidationError):
        UpdateUserProfileRequest(display_name=value)


@pytest.mark.parametrize(
    "value",
    [
        "a" * 101,
    ],
)
def test_profile_update_rejects_oversized_job_title(
    value: str,
) -> None:
    with pytest.raises(ValidationError):
        UpdateUserProfileRequest(job_title=value)


@pytest.mark.parametrize(
    "field",
    [
        "email",
        "system_role",
        "status",
        "password_reset_required",
    ],
)
def test_profile_update_rejects_unknown_fields(
    field: str,
) -> None:
    with pytest.raises(ValidationError) as exc_info:
        UpdateUserProfileRequest.model_validate({field: "unexpected-value"})

    assert any(error["type"] == "extra_forbidden" for error in exc_info.value.errors())
