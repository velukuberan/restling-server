"""PostgreSQL tests for email-change uniqueness rules."""

import pytest
from psycopg.errors import UniqueViolation
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from restling_server.users.models import User
from restling_server.users.service import (
    EmailAlreadyExistsError,
    _check_email_change_target,  # pyright: ignore[reportPrivateUsage]
)


def test_duplicate_normalized_email_is_rejected(
    db_session: Session,
) -> None:
    first_user = User(
        email="john@example.com",
        normalized_email="john@example.com",
        display_name="John",
        status="pending",
        system_role="user",
    )

    db_session.add(first_user)
    db_session.flush()

    second_user = User(
        email="John@Example.COM",
        normalized_email="john@example.com",
        display_name="Another John",
        status="pending",
        system_role="user",
    )

    with pytest.raises(IntegrityError) as exc_info:
        with db_session.begin_nested():
            db_session.add(second_user)
            db_session.flush()

    assert isinstance(exc_info.value.orig, UniqueViolation)
    assert exc_info.value.orig.diag.constraint_name == "users_normalized_email_key"


def test_same_normalized_email_is_no_op(
    db_session: Session,
) -> None:
    user = User(
        email="john@example.com",
        normalized_email="john@example.com",
        display_name="John",
        status="pending",
        system_role="user",
    )

    db_session.add(user)
    db_session.flush()

    result = _check_email_change_target(
        db_session,
        user=user,
        email="  John@Example.COM  ",
    )

    assert result is False
    assert user.email == "john@example.com"


def test_available_email_can_proceed(
    db_session: Session,
) -> None:
    user = User(
        email="john@example.com",
        normalized_email="john@example.com",
        display_name="John",
        status="pending",
        system_role="user",
    )

    db_session.add(user)
    db_session.flush()

    result = _check_email_change_target(
        db_session,
        user=user,
        email="john.new@example.com",
    )

    assert result is True
    assert user.email == "john@example.com"


def test_email_owned_by_another_user_is_rejected(
    db_session: Session,
) -> None:
    first_user = User(
        email="john@example.com",
        normalized_email="john@example.com",
        display_name="John",
        status="pending",
        system_role="user",
    )

    second_user = User(
        email="alice@example.com",
        normalized_email="alice@example.com",
        display_name="Alice",
        status="pending",
        system_role="user",
    )

    db_session.add_all([first_user, second_user])
    db_session.flush()

    with pytest.raises(EmailAlreadyExistsError):
        _check_email_change_target(
            db_session,
            user=first_user,
            email="Alice@Example.COM",
        )

    assert first_user.email == "john@example.com"
    assert second_user.email == "alice@example.com"
