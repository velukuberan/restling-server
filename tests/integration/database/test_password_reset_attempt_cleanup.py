"""Integration tests for password-reset attempt cleanup."""

from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import UUID

import pytest
from sqlalchemy import Engine, event, select
from sqlalchemy.orm import Session

from restling_server.users.models import PasswordResetAttempt
from restling_server.users.service import cleanup_password_reset_attempts

NOW = datetime(2026, 11, 27, 0, 0, tzinfo=UTC)
EMAIL_KEY = sha256(b"recovery@example.com").hexdigest()
SOURCE_IP = "192.0.2.10"


def create_attempt(
    session: Session,
    *,
    created_at: datetime,
) -> UUID:
    """Persist a password-reset attempt with a known timestamp."""
    with session.begin():
        attempt = PasswordResetAttempt(
            email_key=EMAIL_KEY,
            source_ip=SOURCE_IP,
            created_at=created_at,
        )

        session.add(attempt)
        session.flush()

        attempt_id = attempt.id

    return attempt_id


@pytest.mark.parametrize(
    ("cooldown_seconds", "retention_seconds"),
    [
        (60, 3600),
        (1800, 3600),
        (3600, 3600),
        (7200, 7200),
        (86400, 86400),
    ],
)
def test_cleanup_respects_retention_boundary(
    db_session: Session,
    cooldown_seconds: int,
    retention_seconds: int,
) -> None:
    """Cleanup preserves attempts within every active rate-limit window."""
    cutoff = NOW - timedelta(seconds=retention_seconds)

    older_id = create_attempt(
        db_session,
        created_at=cutoff - timedelta(microseconds=1),
    )

    boundary_id = create_attempt(
        db_session,
        created_at=cutoff,
    )

    newer_id = create_attempt(
        db_session,
        created_at=cutoff + timedelta(microseconds=1),
    )

    recent_id = create_attempt(
        db_session,
        created_at=NOW,
    )

    deleted_count = cleanup_password_reset_attempts(
        db_session,
        now=NOW,
        cooldown_seconds=cooldown_seconds,
        batch_size=100,
    )

    assert deleted_count == 2

    with db_session.begin():
        remaining_ids = set(db_session.scalars(select(PasswordResetAttempt.id)).all())

        assert remaining_ids == {newer_id, recent_id}
        assert older_id not in remaining_ids
        assert boundary_id not in remaining_ids


def test_cleanup_respects_batch_size(
    db_session: Session,
) -> None:
    """Each cleanup invocation deletes only one bounded batch."""
    obsolete_ids = {
        create_attempt(
            db_session,
            created_at=NOW - timedelta(hours=2),
        )
        for _ in range(5)
    }

    recent_id = create_attempt(
        db_session,
        created_at=NOW - timedelta(minutes=10),
    )

    for expected_count in (2, 2, 1, 0):
        deleted_count = cleanup_password_reset_attempts(
            db_session,
            now=NOW,
            cooldown_seconds=60,
            batch_size=2,
        )

        assert deleted_count == expected_count

    with db_session.begin():
        remaining_ids = set(db_session.scalars(select(PasswordResetAttempt.id)).all())

        assert remaining_ids == {recent_id}
        assert remaining_ids.isdisjoint(obsolete_ids)


def test_cleanup_returns_zero_for_empty_table(
    db_session: Session,
) -> None:
    """An empty attempt table requires no cleanup."""
    deleted_count = cleanup_password_reset_attempts(
        db_session,
        now=NOW,
        cooldown_seconds=60,
        batch_size=100,
    )

    assert deleted_count == 0


@pytest.mark.parametrize(
    ("cooldown_seconds", "batch_size", "expected_message"),
    [
        (0, 100, "Password-reset cooldown must be positive."),
        (-1, 100, "Password-reset cooldown must be positive."),
        (60, 0, "Cleanup batch size must be positive."),
        (60, -1, "Cleanup batch size must be positive."),
    ],
)
def test_cleanup_rejects_invalid_arguments(
    db_session: Session,
    cooldown_seconds: int,
    batch_size: int,
    expected_message: str,
) -> None:
    """Invalid cleanup arguments cannot initiate a transaction."""
    with pytest.raises(
        ValueError,
        match=expected_message,
    ):
        cleanup_password_reset_attempts(
            db_session,
            now=NOW,
            cooldown_seconds=cooldown_seconds,
            batch_size=batch_size,
        )

    assert not db_session.in_transaction()


def test_cleanup_rejects_timezone_naive_timestamp(
    db_session: Session,
) -> None:
    """Cleanup requires an unambiguous timezone-aware timestamp."""
    with pytest.raises(
        ValueError,
        match="Cleanup time must be timezone-aware.",
    ):
        cleanup_password_reset_attempts(
            db_session,
            now=NOW.replace(tzinfo=None),
            cooldown_seconds=60,
            batch_size=100,
        )

    assert not db_session.in_transaction()


def test_cleanup_skips_locked_attempts(
    test_engine: Engine,
) -> None:
    """Cleanup skips records locked by another transaction."""
    with Session(test_engine) as session:
        locked_id = create_attempt(
            session,
            created_at=NOW - timedelta(hours=3),
        )

        unlocked_id = create_attempt(
            session,
            created_at=NOW - timedelta(hours=2),
        )

    with Session(test_engine) as locking_session:
        with locking_session.begin():
            locked_attempt = locking_session.scalar(
                select(PasswordResetAttempt)
                .where(
                    PasswordResetAttempt.id == locked_id,
                )
                .with_for_update()
            )

            assert locked_attempt is not None

            with Session(test_engine) as cleanup_session:
                deleted_count = cleanup_password_reset_attempts(
                    cleanup_session,
                    now=NOW,
                    cooldown_seconds=60,
                    batch_size=100,
                )

                assert deleted_count == 1

            with Session(test_engine) as verification_session:
                remaining_ids = set(
                    verification_session.scalars(select(PasswordResetAttempt.id)).all()
                )

                assert remaining_ids == {locked_id}
                assert unlocked_id not in remaining_ids

    # Once the lock is released, the remaining obsolete
    # record becomes eligible for the next cleanup batch.
    with Session(test_engine) as session:
        deleted_count = cleanup_password_reset_attempts(
            session,
            now=NOW,
            cooldown_seconds=60,
            batch_size=100,
        )

        assert deleted_count == 1

    with Session(test_engine) as session:
        assert session.scalars(select(PasswordResetAttempt)).all() == []


def test_cleanup_rolls_back_on_transaction_failure(
    test_engine: Engine,
) -> None:
    """A failed cleanup transaction preserves deleted records."""
    with Session(test_engine) as session:
        attempt_id = create_attempt(
            session,
            created_at=NOW - timedelta(hours=2),
        )

    def fail_before_commit(_session: Session) -> None:
        raise RuntimeError("Simulated cleanup transaction failure")

    with Session(test_engine) as session:
        event.listen(
            session,
            "before_commit",
            fail_before_commit,
        )

        with pytest.raises(
            RuntimeError,
            match="Simulated cleanup transaction failure",
        ):
            cleanup_password_reset_attempts(
                session,
                now=NOW,
                cooldown_seconds=60,
                batch_size=100,
            )

        assert not session.in_transaction()

    with Session(test_engine) as session:
        stored_attempt = session.get(
            PasswordResetAttempt,
            attempt_id,
        )

        assert stored_attempt is not None
        assert stored_attempt.email_key == EMAIL_KEY
        assert stored_attempt.source_ip == SOURCE_IP
        assert stored_attempt.created_at == (NOW - timedelta(hours=2))
