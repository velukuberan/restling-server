"""PostgreSQL integration tests for administrator bootstrap."""

from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from threading import Barrier
from time import monotonic, sleep

import pytest
from sqlalchemy import Engine, delete, func, select, text
from sqlalchemy.orm import Session

from restling_server.users.models import User
from restling_server.users.passwords import verify_password
from restling_server.users.service import (
    AdministratorAlreadyInitializedError,
    bootstrap_administrator,
)

# Must match the advisory-lock identifiers used by administrator bootstrap.
_TEST_BOOTSTRAP_LOCK_NAMESPACE = 723941
_TEST_BOOTSTRAP_LOCK_ID = 1


def test_initial_administrator_bootstrap(
    db_session: Session,
) -> None:
    """Bootstrap creates an active administrator with a secure password."""
    password = "A unique administrator passphrase #8472"

    administrator = bootstrap_administrator(
        db_session,
        email="Admin@Example.com",
        display_name="Initial Administrator",
        password=password,
    )

    assert administrator.id.version == 7
    assert administrator.email == "Admin@Example.com"
    assert administrator.normalized_email == "admin@example.com"
    assert administrator.display_name == "Initial Administrator"
    assert administrator.status == "active"
    assert administrator.system_role == "administrator"
    assert administrator.password_reset_required is False
    assert administrator.activated_at is not None

    assert administrator.password_hash is not None
    assert administrator.password_hash.startswith("$argon2id$")
    assert verify_password(password, administrator.password_hash)


def test_administrator_bootstrap_cannot_run_twice(
    db_session: Session,
) -> None:
    """Bootstrap must reject a second administrator."""
    bootstrap_administrator(
        db_session,
        email="first@example.com",
        display_name="First Administrator",
        password="First secure administrator passphrase #8472",
    )

    with pytest.raises(AdministratorAlreadyInitializedError):
        bootstrap_administrator(
            db_session,
            email="second@example.com",
            display_name="Second Administrator",
            password="Second secure administrator passphrase #8472",
        )


@pytest.mark.parametrize(
    "password",
    [
        "short",
        "a" * 14,
        "a" * 65,
    ],
)
def test_bootstrap_rejects_invalid_password(
    db_session: Session,
    password: str,
) -> None:
    """Invalid passwords must not create an administrator."""
    with pytest.raises(ValueError):
        bootstrap_administrator(
            db_session,
            email="admin@example.com",
            display_name="Administrator",
            password=password,
        )

    users = db_session.scalars(select(User)).all()

    assert users == []


@pytest.mark.parametrize(
    "email",
    [
        "",
        "   ",
        "not-an-email",
        "admin@",
        "@example.com",
    ],
)
def test_bootstrap_rejects_invalid_email(
    db_session: Session,
    email: str,
) -> None:
    """Bootstrap must reject invalid administrator email addresses."""
    with pytest.raises(ValueError):
        bootstrap_administrator(
            db_session,
            email=email,
            display_name="Administrator",
            password="A unique administrator passphrase #8472",
        )

    assert db_session.scalars(select(User)).all() == []


@pytest.mark.parametrize(
    "display_name",
    [
        "",
        "   ",
        "A" * 151,
    ],
)
def test_bootstrap_rejects_invalid_display_name(
    db_session: Session,
    display_name: str,
) -> None:
    """Bootstrap rejects empty or excessively long display names."""
    with pytest.raises(ValueError):
        bootstrap_administrator(
            db_session,
            email="admin@example.com",
            display_name=display_name,
            password="A unique administrator passphrase #8472",
        )

    assert db_session.scalars(select(User)).all() == []


def test_concurrent_administrator_bootstrap(
    test_engine: Engine,
) -> None:
    """Only one concurrent bootstrap attempt may succeed."""
    emails = (
        "bootstrap-a@example.com",
        "bootstrap-b@example.com",
    )

    # Bootstrap is only meaningful against an uninitialized database.
    with Session(test_engine) as session:
        user_count = session.scalar(select(func.count()).select_from(User))
        assert user_count == 0

    barrier = Barrier(2)

    def attempt_bootstrap(email: str) -> str:
        # Both workers begin their bootstrap attempts together.
        barrier.wait(timeout=10)

        with Session(test_engine) as session:
            try:
                bootstrap_administrator(
                    session,
                    email=email,
                    display_name="Initial Administrator",
                    password="A unique administrator passphrase #8472",
                )
            except AdministratorAlreadyInitializedError:
                return "rejected"

        return "created"

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(attempt_bootstrap, email) for email in emails]
            results = [future.result() for future in futures]

        assert sorted(results) == ["created", "rejected"]

        with Session(test_engine) as session:
            users = session.scalars(select(User)).all()

            assert len(users) == 1
            assert users[0].system_role == "administrator"
            assert users[0].status == "active"
            assert users[0].normalized_email in emails

    finally:
        # These sessions commit real transactions, so cleanup is explicit.
        # Delete only the records belonging to this test.
        with test_engine.begin() as connection:
            connection.execute(delete(User).where(User.normalized_email.in_(emails)))


def test_bootstrap_waits_for_advisory_lock(
    test_engine: Engine,
) -> None:
    """Bootstrap waits until another transaction releases its lock."""
    email = "lock-contention-admin@example.com"
    backend_pids: Queue[int] = Queue()

    def attempt_bootstrap() -> None:
        with Session(test_engine) as session:
            # Identify this connection in pg_stat_activity.
            pid = session.scalar(text("SELECT pg_backend_pid()"))
            assert isinstance(pid, int)

            # End the identification query's transaction so that
            # bootstrap_administrator() can own its transaction.
            session.rollback()
            backend_pids.put(pid)

            bootstrap_administrator(
                session,
                email=email,
                display_name="Lock Contention Administrator",
                password="A unique administrator passphrase #8472",
            )

    try:
        # This test requires an uninitialized test database.
        with Session(test_engine) as session:
            user_count = session.scalar(select(func.count()).select_from(User))
            assert user_count == 0

        with ThreadPoolExecutor(max_workers=1) as executor:
            with test_engine.connect() as lock_connection:
                with lock_connection.begin():
                    lock_connection.execute(
                        text("SELECT pg_advisory_xact_lock(:namespace, :lock_id)"),
                        {
                            "namespace": _TEST_BOOTSTRAP_LOCK_NAMESPACE,
                            "lock_id": _TEST_BOOTSTRAP_LOCK_ID,
                        },
                    )

                    # Connection A now holds the lock.
                    # Start bootstrap on connection B.
                    future = executor.submit(attempt_bootstrap)
                    worker_pid = backend_pids.get(timeout=10)

                    # Observe the worker actually waiting in PostgreSQL.
                    deadline = monotonic() + 10
                    lock_wait_observed = False

                    while monotonic() < deadline:
                        with test_engine.connect() as observer:
                            wait_event = observer.scalar(
                                text(
                                    "SELECT wait_event "
                                    "FROM pg_stat_activity "
                                    "WHERE pid = :pid "
                                    "AND wait_event_type = 'Lock'"
                                ),
                                {"pid": worker_pid},
                            )

                        if wait_event == "advisory":
                            lock_wait_observed = True
                            break

                        sleep(0.02)

                    assert lock_wait_observed, (
                        "Bootstrap did not wait for the advisory lock."
                    )

                # Connection A commits here, releasing the lock.

            # The bootstrap operation should now finish successfully.
            future.result(timeout=10)

        with Session(test_engine) as session:
            users = session.scalars(select(User)).all()
            assert len(users) == 1
            assert users[0].normalized_email == email
            assert users[0].system_role == "administrator"

    finally:
        # Clean up only the user created by this test.
        with test_engine.begin() as connection:
            connection.execute(delete(User).where(User.normalized_email == email))
