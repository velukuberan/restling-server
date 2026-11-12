"""PostgreSQL integration tests for user creation."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from sqlalchemy import Engine, delete, select
from sqlalchemy.orm import Session
from uuid6 import uuid7

from restling_server.users.models import User
from restling_server.users.service import (
    UserAlreadyExistsError,
    UserCreationNotAllowedError,
    bootstrap_administrator,
    create_user,
)


def test_administrator_can_create_pending_user(
    test_engine: Engine,
) -> None:
    """An administrator can create a pending user account."""
    admin_email = "creation-admin@example.com"
    new_email = "newuser@example.com"

    try:
        with Session(test_engine) as session:
            administrator = bootstrap_administrator(
                session,
                email=admin_email,
                display_name="Administrator",
                password="A secure administrator passphrase #8472",
            )
            administrator_id = administrator.id

        with Session(test_engine) as session:
            create_user(
                session,
                actor_id=administrator_id,
                email=new_email,
                display_name="New User",
                job_title="Backend Engineer",
            )

        with Session(test_engine) as session:
            user = session.scalar(
                select(User).where(User.normalized_email == new_email)
            )

            assert user is not None
            assert user.id.version == 7
            assert user.email == new_email
            assert user.display_name == "New User"
            assert user.job_title == "Backend Engineer"
            assert user.status == "pending"
            assert user.system_role == "user"
            assert user.password_hash is None
            assert user.activated_at is None

    finally:
        with test_engine.begin() as connection:
            connection.execute(
                delete(User).where(User.normalized_email.in_([admin_email, new_email]))
            )


def test_ordinary_user_cannot_create_user(
    test_engine: Engine,
) -> None:
    """An ordinary user cannot create another account."""
    actor_email = "ordinary-actor@example.com"
    attempted_email = "unauthorized@example.com"

    try:
        with Session(test_engine) as session:
            actor = User(
                email=actor_email,
                normalized_email=actor_email,
                display_name="Ordinary User",
                status="active",
                system_role="user",
                password_hash="test-password-hash",
            )

            session.add(actor)
            session.commit()
            actor_id = actor.id

        with Session(test_engine) as session:
            with pytest.raises(UserCreationNotAllowedError):
                create_user(
                    session,
                    actor_id=actor_id,
                    email=attempted_email,
                    display_name="Unauthorized User",
                )

        with Session(test_engine) as session:
            attempted_user = session.scalar(
                select(User).where(User.normalized_email == attempted_email)
            )
            assert attempted_user is None

    finally:
        with test_engine.begin() as connection:
            connection.execute(
                delete(User).where(
                    User.normalized_email.in_([actor_email, attempted_email])
                )
            )


def test_suspended_administrator_cannot_create_user(
    test_engine: Engine,
) -> None:
    """A suspended administrator cannot create user accounts."""
    admin_email = "suspended-admin@example.com"
    attempted_email = "suspended-attempt@example.com"

    try:
        with Session(test_engine) as session:
            administrator = User(
                email=admin_email,
                normalized_email=admin_email,
                display_name="Suspended Administrator",
                status="suspended",
                system_role="administrator",
                password_hash="test-password-hash",
            )

            session.add(administrator)
            session.flush()
            administrator_id = administrator.id
            session.commit()

        with Session(test_engine) as session:
            with pytest.raises(UserCreationNotAllowedError):
                create_user(
                    session,
                    actor_id=administrator_id,
                    email=attempted_email,
                    display_name="Unauthorized User",
                )

        with Session(test_engine) as session:
            attempted_user = session.scalar(
                select(User).where(User.normalized_email == attempted_email)
            )

            assert attempted_user is None

    finally:
        with test_engine.begin() as connection:
            connection.execute(
                delete(User).where(
                    User.normalized_email.in_([admin_email, attempted_email])
                )
            )


def test_nonexistent_actor_cannot_create_user(
    test_engine: Engine,
) -> None:
    """A nonexistent actor cannot create a user account."""
    attempted_email = "nonexistent-actor-attempt@example.com"

    with Session(test_engine) as session:
        with pytest.raises(UserCreationNotAllowedError):
            create_user(
                session,
                actor_id=uuid7(),
                email=attempted_email,
                display_name="Unauthorized User",
            )

    with Session(test_engine) as session:
        user = session.scalar(
            select(User).where(User.normalized_email == attempted_email)
        )

        assert user is None


def test_duplicate_email_is_rejected(
    test_engine: Engine,
) -> None:
    """Email uniqueness must be enforced case-insensitively."""
    admin_email = "duplicate-admin@example.com"
    user_email = "developer@example.com"

    try:
        with Session(test_engine) as session:
            administrator = bootstrap_administrator(
                session,
                email=admin_email,
                display_name="Administrator",
                password="A secure administrator passphrase #8472",
            )
            administrator_id = administrator.id

        with Session(test_engine) as session:
            create_user(
                session,
                actor_id=administrator_id,
                email="Developer@Example.com",
                display_name="First Developer",
            )

        with Session(test_engine) as session:
            with pytest.raises(UserAlreadyExistsError):
                create_user(
                    session,
                    actor_id=administrator_id,
                    email=user_email,
                    display_name="Second Developer",
                )

        with Session(test_engine) as session:
            users = session.scalars(
                select(User).where(User.normalized_email == user_email)
            ).all()

            assert len(users) == 1
            assert users[0].display_name == "First Developer"

    finally:
        with test_engine.begin() as connection:
            connection.execute(
                delete(User).where(User.normalized_email.in_([admin_email, user_email]))
            )


@pytest.mark.parametrize(
    "email",
    [
        "",
        "   ",
        "invalid-email",
        "user@",
        "@example.com",
    ],
)
def test_create_user_rejects_invalid_email(
    test_engine: Engine,
    email: str,
) -> None:
    """Invalid email addresses must not create user accounts."""
    admin_email = "validation-admin@example.com"

    try:
        with Session(test_engine) as session:
            administrator = bootstrap_administrator(
                session,
                email=admin_email,
                display_name="Administrator",
                password="A secure administrator passphrase #8472",
            )
            administrator_id = administrator.id

        with Session(test_engine) as session:
            with pytest.raises(ValueError, match="Invalid user email"):
                create_user(
                    session,
                    actor_id=administrator_id,
                    email=email,
                    display_name="New User",
                )

        with Session(test_engine) as session:
            users = session.scalars(select(User)).all()
            assert len(users) == 1
            assert users[0].id == administrator_id

    finally:
        with test_engine.begin() as connection:
            connection.execute(delete(User).where(User.normalized_email == admin_email))


@pytest.mark.parametrize(
    "display_name",
    [
        "",
        "   ",
        "A" * 151,
    ],
)
def test_create_user_rejects_invalid_display_name(
    test_engine: Engine,
    display_name: str,
) -> None:
    """Invalid display names must not create user accounts."""
    admin_email = "display-validation-admin@example.com"
    new_email = "display-validation-user@example.com"

    try:
        with Session(test_engine) as session:
            administrator = bootstrap_administrator(
                session,
                email=admin_email,
                display_name="Administrator",
                password="A secure administrator passphrase #8472",
            )
            administrator_id = administrator.id

        with Session(test_engine) as session:
            with pytest.raises(ValueError):
                create_user(
                    session,
                    actor_id=administrator_id,
                    email=new_email,
                    display_name=display_name,
                )

        with Session(test_engine) as session:
            user = session.scalar(
                select(User).where(User.normalized_email == new_email)
            )

            assert user is None

    finally:
        with test_engine.begin() as connection:
            connection.execute(
                delete(User).where(User.normalized_email.in_([admin_email, new_email]))
            )


@pytest.mark.parametrize(
    ("job_title", "expected"),
    [
        (None, None),
        ("   ", None),
        ("  Backend Engineer  ", "Backend Engineer"),
    ],
)
def test_create_user_normalizes_job_title(
    test_engine: Engine,
    job_title: str | None,
    expected: str | None,
) -> None:
    """Optional job titles are normalized before persistence."""
    admin_email = "job-title-admin@example.com"
    user_email = "job-title-user@example.com"

    try:
        with Session(test_engine) as session:
            administrator = bootstrap_administrator(
                session,
                email=admin_email,
                display_name="Administrator",
                password="A secure administrator passphrase #8472",
            )
            administrator_id = administrator.id

        with Session(test_engine) as session:
            create_user(
                session,
                actor_id=administrator_id,
                email=user_email,
                display_name="New User",
                job_title=job_title,
            )

        with Session(test_engine) as session:
            user = session.scalar(
                select(User).where(User.normalized_email == user_email)
            )

            assert user is not None
            assert user.job_title == expected

    finally:
        with test_engine.begin() as connection:
            connection.execute(
                delete(User).where(User.normalized_email.in_([admin_email, user_email]))
            )


def test_create_user_rejects_long_job_title(
    test_engine: Engine,
) -> None:
    """Job titles longer than 100 characters are rejected."""
    admin_email = "long-title-admin@example.com"
    user_email = "long-title-user@example.com"

    try:
        with Session(test_engine) as session:
            administrator = bootstrap_administrator(
                session,
                email=admin_email,
                display_name="Administrator",
                password="A secure administrator passphrase #8472",
            )
            administrator_id = administrator.id

        with Session(test_engine) as session:
            with pytest.raises(ValueError, match="Job title"):
                create_user(
                    session,
                    actor_id=administrator_id,
                    email=user_email,
                    display_name="New User",
                    job_title="A" * 101,
                )

        with Session(test_engine) as session:
            user = session.scalar(
                select(User).where(User.normalized_email == user_email)
            )

            assert user is None

    finally:
        with test_engine.begin() as connection:
            connection.execute(
                delete(User).where(User.normalized_email.in_([admin_email, user_email]))
            )


def test_concurrent_duplicate_user_creation(
    test_engine: Engine,
) -> None:
    """Concurrent requests cannot create duplicate user accounts."""
    admin_email = "concurrent-admin@example.com"
    user_email = "concurrent-user@example.com"

    try:
        with Session(test_engine) as session:
            administrator = bootstrap_administrator(
                session,
                email=admin_email,
                display_name="Administrator",
                password="A secure administrator passphrase #8472",
            )
            administrator_id = administrator.id

        barrier = Barrier(2)

        def attempt_creation(email: str) -> str:
            barrier.wait(timeout=10)

            with Session(test_engine) as session:
                try:
                    create_user(
                        session,
                        actor_id=administrator_id,
                        email=email,
                        display_name="Concurrent User",
                    )
                except UserAlreadyExistsError:
                    return "duplicate"

            return "created"

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(
                    attempt_creation,
                    "Concurrent-User@Example.com",
                ),
                executor.submit(
                    attempt_creation,
                    user_email,
                ),
            ]

            results = [future.result(timeout=15) for future in futures]

        assert sorted(results) == ["created", "duplicate"]

        with Session(test_engine) as session:
            users = session.scalars(
                select(User).where(User.normalized_email == user_email)
            ).all()

            assert len(users) == 1
            assert users[0].status == "pending"

    finally:
        with test_engine.begin() as connection:
            connection.execute(
                delete(User).where(User.normalized_email.in_([admin_email, user_email]))
            )
