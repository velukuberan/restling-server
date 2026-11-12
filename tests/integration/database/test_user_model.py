"""PostgreSQL integration tests for the user model."""

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from restling_server.users.models import User


def test_pending_user_can_be_created(
    db_session: Session,
) -> None:
    """A pending account can be stored without a password."""
    user = User(
        email="Test@Example.com",
        normalized_email="test@example.com",
        display_name="Test User",
    )

    db_session.add(user)
    db_session.flush()

    assert user.id is not None
    assert user.id.version == 7
    assert user.status == "pending"
    assert user.system_role == "user"
    assert user.password_hash is None

    stored_user = db_session.scalar(select(User).where(User.id == user.id))

    assert stored_user is not None
    assert stored_user.email == "Test@Example.com"
    assert stored_user.normalized_email == "test@example.com"


def test_duplicate_normalized_email_is_rejected(
    db_session: Session,
) -> None:
    """PostgreSQL enforces unique normalized email addresses."""
    first_user = User(
        email="John@Example.com",
        normalized_email="john@example.com",
        display_name="John",
    )

    db_session.add(first_user)
    db_session.flush()

    duplicate_user = User(
        email="JOHN@example.com",
        normalized_email="john@example.com",
        display_name="Another John",
    )

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(duplicate_user)
            db_session.flush()


def test_invalid_account_status_is_rejected(
    db_session: Session,
) -> None:
    """PostgreSQL rejects unsupported account statuses."""
    user = User(
        email="invalid@example.com",
        normalized_email="invalid@example.com",
        display_name="Invalid User",
        status="unknown",
    )

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(user)
            db_session.flush()


@pytest.mark.parametrize("system_role", ["owner", "superadmin", ""])
def test_invalid_system_role_is_rejected(
    db_session: Session,
    system_role: str,
) -> None:
    """PostgreSQL accepts only approved system roles."""
    user = User(
        email="role@example.com",
        normalized_email="role@example.com",
        display_name="Role Test",
        system_role=system_role,
    )

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(user)
            db_session.flush()


@pytest.mark.parametrize(
    ("status", "password_hash"),
    [
        ("pending", "some-hash"),
        ("active", None),
        ("active", ""),
        ("active", "   "),
        ("suspended", None),
    ],
)
def test_invalid_password_state_is_rejected(
    db_session: Session,
    status: str,
    password_hash: str | None,
) -> None:
    """PostgreSQL enforces password presence by account state."""
    user = User(
        email="password@example.com",
        normalized_email="password@example.com",
        display_name="Password Test",
        status=status,
        password_hash=password_hash,
    )

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(user)
            db_session.flush()


@pytest.mark.parametrize("status", ["active", "suspended"])
def test_account_with_password_hash_is_accepted(
    db_session: Session,
    status: str,
) -> None:
    """Active and suspended accounts can have password hashes."""
    user = User(
        email=f"{status}@example.com",
        normalized_email=f"{status}@example.com",
        display_name="Account State Test",
        status=status,
        password_hash="example-hash-for-schema-test",
    )

    db_session.add(user)
    db_session.flush()

    assert user.id.version == 7
    assert user.status == status
    assert user.password_hash is not None


@pytest.mark.parametrize(
    "field_name",
    ["email", "normalized_email", "display_name"],
)
def test_required_user_fields_cannot_be_null(
    db_session: Session,
    field_name: str,
) -> None:
    """PostgreSQL rejects NULL values in required identity fields."""
    user = User(
        email="required@example.com",
        normalized_email="required@example.com",
        display_name="Required Fields Test",
    )

    setattr(user, field_name, None)

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(user)
            db_session.flush()
