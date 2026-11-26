"""PostgreSQL integration tests for password-reset attempt records."""

from datetime import UTC, datetime
from hashlib import sha256

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from restling_server.users.models import PasswordResetAttempt


def test_password_reset_attempt_can_be_persisted(
    db_session: Session,
) -> None:
    """Recovery attempts persist without requiring an existing account."""
    email_key = sha256(b"unknown-user@example.com").hexdigest()
    created_at = datetime.now(UTC)

    attempt = PasswordResetAttempt(
        email_key=email_key,
        source_ip="192.0.2.10",
        created_at=created_at,
    )

    db_session.add(attempt)
    db_session.flush()

    attempt_id = attempt.id

    db_session.expire_all()

    stored_attempt = db_session.get(
        PasswordResetAttempt,
        attempt_id,
    )

    assert stored_attempt is not None
    assert stored_attempt.id.version == 7
    assert stored_attempt.email_key == email_key
    assert stored_attempt.source_ip == "192.0.2.10"
    assert stored_attempt.created_at == created_at


def test_password_reset_attempt_generates_creation_timestamp(
    db_session: Session,
) -> None:
    """An attempt receives a timezone-aware creation timestamp."""
    before = datetime.now(UTC)

    attempt = PasswordResetAttempt(
        email_key=sha256(b"user@example.com").hexdigest(),
        source_ip="192.0.2.10",
    )

    db_session.add(attempt)
    db_session.flush()

    after = datetime.now(UTC)

    assert attempt.created_at.tzinfo is not None
    assert attempt.created_at.utcoffset() is not None
    assert before <= attempt.created_at <= after


@pytest.mark.parametrize(
    "source_ip",
    [
        "192.0.2.10",
        "2001:db8::1",
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    ],
)
def test_password_reset_attempt_supports_ipv4_and_ipv6(
    db_session: Session,
    source_ip: str,
) -> None:
    """Recovery records can store IPv4 and IPv6 addresses."""
    attempt = PasswordResetAttempt(
        email_key=sha256(b"user@example.com").hexdigest(),
        source_ip=source_ip,
    )

    db_session.add(attempt)
    db_session.flush()

    attempt_id = attempt.id

    db_session.expire_all()

    stored_attempt = db_session.get(
        PasswordResetAttempt,
        attempt_id,
    )

    assert stored_attempt is not None
    assert stored_attempt.source_ip == source_ip


@pytest.mark.parametrize(
    "email_key",
    [
        "",
        "a" * 63,
    ],
)
def test_password_reset_attempt_rejects_invalid_email_key_length(
    db_session: Session,
    email_key: str,
) -> None:
    """The database requires a 64-character email key."""
    attempt = PasswordResetAttempt(
        email_key=email_key,
        source_ip="192.0.2.10",
    )

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(attempt)
            db_session.flush()


@pytest.mark.parametrize(
    "source_ip",
    [
        "",
        "   ",
    ],
)
def test_password_reset_attempt_rejects_empty_source_ip(
    db_session: Session,
    source_ip: str,
) -> None:
    """The database rejects empty or whitespace-only IP addresses."""
    attempt = PasswordResetAttempt(
        email_key=sha256(b"user@example.com").hexdigest(),
        source_ip=source_ip,
    )

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(attempt)
            db_session.flush()


def test_password_reset_attempt_allows_repeated_email_and_ip(
    db_session: Session,
) -> None:
    """Repeated attempts must remain independently countable."""
    email_key = sha256(b"user@example.com").hexdigest()
    source_ip = "192.0.2.10"

    first = PasswordResetAttempt(
        email_key=email_key,
        source_ip=source_ip,
    )

    second = PasswordResetAttempt(
        email_key=email_key,
        source_ip=source_ip,
    )

    db_session.add_all([first, second])
    db_session.flush()

    assert first.id != second.id

    attempts = db_session.scalars(
        select(PasswordResetAttempt).where(
            PasswordResetAttempt.email_key == email_key,
            PasswordResetAttempt.source_ip == source_ip,
        )
    ).all()

    assert len(attempts) == 2
