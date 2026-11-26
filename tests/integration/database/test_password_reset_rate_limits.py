"""PostgreSQL integration tests for password-recovery rate limits."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from threading import Barrier
from time import monotonic, sleep

import pytest
from sqlalchemy import Engine, delete, select, text
from sqlalchemy.orm import Session
from uuid6 import uuid7

from restling_server.users.models import PasswordResetAttempt
from restling_server.users.service import reserve_password_reset_attempt


def reserve_attempt(
    session: Session,
    *,
    email: str = "recovery@example.com",
    source_ip: str = "192.0.2.10",
    cooldown_seconds: int = 60,
    email_hourly_limit: int = 5,
    ip_hourly_limit: int = 20,
) -> bool:
    """Reserve an attempt using the default recovery limits."""
    return reserve_password_reset_attempt(
        session,
        email=email,
        source_ip=source_ip,
        cooldown_seconds=cooldown_seconds,
        email_hourly_limit=email_hourly_limit,
        ip_hourly_limit=ip_hourly_limit,
    )


def seed_attempt(
    session: Session,
    *,
    email: str,
    source_ip: str,
    created_at: datetime,
) -> None:
    """Persist a historical attempt for rate-limit verification."""
    with session.begin():
        session.add(
            PasswordResetAttempt(
                email_key=sha256(email.encode()).hexdigest(),
                source_ip=source_ip,
                created_at=created_at,
            )
        )


def test_password_reset_attempt_can_be_reserved(
    db_session: Session,
) -> None:
    """An unknown email address can reserve a recovery attempt."""
    assert reserve_attempt(db_session) is True

    attempts = db_session.scalars(select(PasswordResetAttempt)).all()

    assert len(attempts) == 1
    assert attempts[0].email_key == sha256(b"recovery@example.com").hexdigest()
    assert attempts[0].source_ip == "192.0.2.10"


def test_password_reset_cooldown_rejects_immediate_retry(
    db_session: Session,
) -> None:
    """An immediate retry must not create another reservation."""
    assert reserve_attempt(db_session) is True
    assert reserve_attempt(db_session) is False

    attempts = db_session.scalars(select(PasswordResetAttempt)).all()

    assert len(attempts) == 1


def test_password_reset_cooldown_cannot_be_bypassed_by_ip_change(
    db_session: Session,
) -> None:
    """Changing the source IP must not bypass the email cooldown."""
    assert (
        reserve_attempt(
            db_session,
            source_ip="192.0.2.10",
        )
        is True
    )

    assert (
        reserve_attempt(
            db_session,
            source_ip="192.0.2.11",
        )
        is False
    )


def test_password_reset_allows_retry_after_cooldown(
    db_session: Session,
) -> None:
    """Allow another reservation once the cooldown has elapsed."""
    seed_attempt(
        db_session,
        email="recovery@example.com",
        source_ip="192.0.2.10",
        created_at=datetime.now(UTC) - timedelta(seconds=61),
    )

    assert reserve_attempt(db_session) is True

    attempts = db_session.scalars(select(PasswordResetAttempt)).all()

    assert len(attempts) == 2


def test_password_reset_enforces_email_hourly_limit(
    db_session: Session,
) -> None:
    """The rolling email limit applies across different source IPs."""
    now = datetime.now(UTC)

    for index in range(5):
        seed_attempt(
            db_session,
            email="recovery@example.com",
            source_ip=f"192.0.2.{index + 10}",
            created_at=now - timedelta(minutes=index + 2),
        )

    assert (
        reserve_attempt(
            db_session,
            source_ip="192.0.2.100",
        )
        is False
    )

    attempts = db_session.scalars(select(PasswordResetAttempt)).all()

    assert len(attempts) == 5


def test_password_reset_enforces_ip_hourly_limit(
    db_session: Session,
) -> None:
    """Different emails cannot bypass the source-IP limit."""
    for index in range(20):
        assert (
            reserve_attempt(
                db_session,
                email=f"recovery-{index}@example.com",
            )
            is True
        )

    assert (
        reserve_attempt(
            db_session,
            email="another-user@example.com",
        )
        is False
    )

    attempts = db_session.scalars(select(PasswordResetAttempt)).all()

    assert len(attempts) == 20


def test_password_reset_rate_limits_are_independent(
    db_session: Session,
) -> None:
    """An exhausted IP limit must not affect unrelated clients."""
    assert (
        reserve_attempt(
            db_session,
            email="first@example.com",
            ip_hourly_limit=1,
        )
        is True
    )

    assert (
        reserve_attempt(
            db_session,
            email="second@example.com",
            ip_hourly_limit=1,
        )
        is False
    )

    assert (
        reserve_attempt(
            db_session,
            email="second@example.com",
            source_ip="192.0.2.11",
            ip_hourly_limit=1,
        )
        is True
    )


def test_password_reset_ignores_attempts_outside_hourly_window(
    db_session: Session,
) -> None:
    """Historical attempts outside the rolling window do not count."""
    seed_attempt(
        db_session,
        email="recovery@example.com",
        source_ip="192.0.2.10",
        created_at=datetime.now(UTC) - timedelta(minutes=61),
    )

    assert (
        reserve_attempt(
            db_session,
            email_hourly_limit=1,
            ip_hourly_limit=1,
        )
        is True
    )


def test_password_reset_normalizes_email_addresses(
    db_session: Session,
) -> None:
    """Equivalent email addresses share the same recovery limit."""
    assert (
        reserve_attempt(
            db_session,
            email="  Recovery@Example.COM  ",
        )
        is True
    )

    assert (
        reserve_attempt(
            db_session,
            email="recovery@example.com",
            source_ip="192.0.2.11",
        )
        is False
    )

    attempts = db_session.scalars(select(PasswordResetAttempt)).all()

    assert len(attempts) == 1
    assert attempts[0].email_key == sha256(b"recovery@example.com").hexdigest()


@pytest.mark.parametrize(
    ("first_ip", "second_ip", "expected_ip"),
    [
        (
            "2001:0db8:0000:0000:0000:0000:0000:0001",
            "2001:db8::1",
            "2001:db8::1",
        ),
        (
            "::ffff:192.0.2.10",
            "192.0.2.10",
            "192.0.2.10",
        ),
    ],
)
def test_password_reset_normalizes_source_ip(
    db_session: Session,
    first_ip: str,
    second_ip: str,
    expected_ip: str,
) -> None:
    """Equivalent IP representations share the same rate limit."""
    assert (
        reserve_attempt(
            db_session,
            email="first@example.com",
            source_ip=first_ip,
            ip_hourly_limit=1,
        )
        is True
    )

    assert (
        reserve_attempt(
            db_session,
            email="second@example.com",
            source_ip=second_ip,
            ip_hourly_limit=1,
        )
        is False
    )

    attempts = db_session.scalars(select(PasswordResetAttempt)).all()

    assert len(attempts) == 1
    assert attempts[0].source_ip == expected_ip


@pytest.mark.parametrize(
    "email",
    [
        "",
        "not-an-email",
        "user@",
    ],
)
def test_password_reset_rejects_invalid_email(
    db_session: Session,
    email: str,
) -> None:
    """Invalid email addresses must not create reservations."""
    with pytest.raises(ValueError):
        reserve_attempt(db_session, email=email)

    assert db_session.scalars(select(PasswordResetAttempt)).all() == []


@pytest.mark.parametrize(
    "source_ip",
    [
        "",
        "not-an-ip",
        "999.0.0.1",
        "fe80::1%eth0",
    ],
)
def test_password_reset_rejects_invalid_source_ip(
    db_session: Session,
    source_ip: str,
) -> None:
    """Invalid and scoped IP addresses must not create reservations."""
    with pytest.raises(ValueError):
        reserve_attempt(db_session, source_ip=source_ip)

    assert db_session.scalars(select(PasswordResetAttempt)).all() == []


@pytest.mark.parametrize(
    ("cooldown_seconds", "email_hourly_limit", "ip_hourly_limit"),
    [
        (0, 5, 20),
        (-1, 5, 20),
        (60, 0, 20),
        (60, -1, 20),
        (60, 5, 0),
        (60, 5, -1),
    ],
)
def test_password_reset_rejects_invalid_rate_limit_configuration(
    db_session: Session,
    cooldown_seconds: int,
    email_hourly_limit: int,
    ip_hourly_limit: int,
) -> None:
    """Application-level limits must remain positive."""
    with pytest.raises(ValueError):
        reserve_attempt(
            db_session,
            cooldown_seconds=cooldown_seconds,
            email_hourly_limit=email_hourly_limit,
            ip_hourly_limit=ip_hourly_limit,
        )

    assert db_session.scalars(select(PasswordResetAttempt)).all() == []


@pytest.mark.parametrize(
    "shared_dimension",
    [
        "email",
        "ip",
    ],
)
def test_concurrent_password_reset_attempts_respect_rate_limits(
    test_engine: Engine,
    shared_dimension: str,
) -> None:
    """Concurrent reservations cannot bypass a shared limit."""
    key = uuid7().hex

    first_email = f"first-{key}@example.com"
    second_email = (
        first_email if shared_dimension == "email" else f"second-{key}@example.com"
    )

    first_ip = "198.51.100.10"
    second_ip = first_ip if shared_dimension == "ip" else "198.51.100.11"

    email_keys = {
        sha256(first_email.encode()).hexdigest(),
        sha256(second_email.encode()).hexdigest(),
    }

    barrier = Barrier(2)

    def reserve_concurrently(
        email: str,
        source_ip: str,
    ) -> bool:
        with Session(test_engine) as session:
            barrier.wait(timeout=10)

            return reserve_attempt(
                session,
                email=email,
                source_ip=source_ip,
                email_hourly_limit=1,
                ip_hourly_limit=1,
            )

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(
                reserve_concurrently,
                first_email,
                first_ip,
            )

            second = executor.submit(
                reserve_concurrently,
                second_email,
                second_ip,
            )

            results = [
                first.result(timeout=10),
                second.result(timeout=10),
            ]

        assert sorted(results) == [False, True]

        with Session(test_engine) as session:
            attempts = session.scalars(
                select(PasswordResetAttempt).where(
                    PasswordResetAttempt.email_key.in_(email_keys)
                )
            ).all()

            assert len(attempts) == 1

    finally:
        # Concurrent reservations commit real transactions.
        # Remove only records created by this test.
        with test_engine.begin() as connection:
            connection.execute(
                delete(PasswordResetAttempt).where(
                    PasswordResetAttempt.email_key.in_(email_keys)
                )
            )


@pytest.mark.parametrize("shared_dimension", ["email", "ip"])
def test_password_reset_reservation_waits_for_advisory_lock(
    test_engine: Engine,
    shared_dimension: str,
) -> None:
    """Reservations must wait for competing transactions to commit."""
    key = uuid7().hex

    first_email = f"first-{key}@example.com"
    second_email = (
        first_email if shared_dimension == "email" else f"second-{key}@example.com"
    )

    first_ip = "203.0.113.10"
    second_ip = first_ip if shared_dimension == "ip" else "203.0.113.11"

    first_email_key = sha256(first_email.encode()).hexdigest()
    second_email_key = sha256(second_email.encode()).hexdigest()

    email_keys = {first_email_key, second_email_key}

    lock_value = first_email_key if shared_dimension == "email" else first_ip

    # Match the production advisory-lock identifier.
    digest = sha256(
        f"restling:password-reset:{shared_dimension}:{lock_value}".encode()
    ).digest()

    lock_key = int.from_bytes(
        digest[:8],
        byteorder="big",
        signed=True,
    )

    def competing_reservation() -> bool:
        with Session(test_engine) as session:
            return reserve_attempt(
                session,
                email=second_email,
                source_ip=second_ip,
                email_hourly_limit=1,
                ip_hourly_limit=1,
            )

    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            with Session(test_engine) as blocking_session:
                with blocking_session.begin():
                    blocking_session.execute(
                        text("SELECT pg_advisory_xact_lock(CAST(:lock_key AS BIGINT))"),
                        {"lock_key": lock_key},
                    )

                    blocker_pid = blocking_session.scalar(
                        text("SELECT pg_backend_pid()")
                    )

                    assert isinstance(blocker_pid, int)

                    future = executor.submit(competing_reservation)

                    deadline = monotonic() + 10
                    lock_wait_observed = False

                    while monotonic() < deadline:
                        with test_engine.connect() as observer:
                            blocked = observer.scalar(
                                text(
                                    "SELECT EXISTS ("
                                    "SELECT 1 "
                                    "FROM pg_stat_activity "
                                    "WHERE datname = current_database() "
                                    "AND wait_event_type = 'Lock' "
                                    "AND wait_event = 'advisory' "
                                    "AND :blocker_pid = ANY("
                                    "pg_blocking_pids(pid)"
                                    ")"
                                    ")"
                                ),
                                {"blocker_pid": blocker_pid},
                            )

                        if blocked is True:
                            lock_wait_observed = True
                            break

                        if future.done():
                            future.result(timeout=1)
                            break

                        sleep(0.02)

                    assert lock_wait_observed, (
                        "Recovery reservation did not wait "
                        "for the expected advisory lock."
                    )

                    # Consume the available reservation while
                    # the competing transaction is blocked.
                    blocking_session.add(
                        PasswordResetAttempt(
                            email_key=first_email_key,
                            source_ip=first_ip,
                            created_at=datetime.now(UTC),
                        )
                    )

                    blocking_session.flush()

                # Commit the reservation and release the lock.

            # The waiting request must see the committed attempt.
            assert future.result(timeout=10) is False

        with Session(test_engine) as session:
            attempts = session.scalars(
                select(PasswordResetAttempt).where(
                    PasswordResetAttempt.email_key.in_(email_keys)
                )
            ).all()

            assert len(attempts) == 1
            assert attempts[0].email_key == first_email_key
            assert attempts[0].source_ip == first_ip

    finally:
        with test_engine.begin() as connection:
            connection.execute(
                delete(PasswordResetAttempt).where(
                    PasswordResetAttempt.email_key.in_(email_keys)
                )
            )
