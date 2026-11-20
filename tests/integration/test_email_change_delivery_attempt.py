"""PostgreSQL integration tests for email-change delivery attempts."""

from datetime import UTC, datetime

from sqlalchemy import Engine, inspect
from sqlalchemy.orm import Session
from uuid6 import uuid7

from restling_server.users.models import EmailChangeDeliveryAttempt, User
from restling_server.users.passwords import hash_password


def test_email_change_delivery_attempt_persists(
    test_engine: Engine,
) -> None:
    """An email-change delivery attempt persists in PostgreSQL."""
    inspector = inspect(test_engine)

    assert inspector.has_table("email_change_delivery_attempts")

    email = f"delivery-attempt-{uuid7().hex}@example.com"

    with Session(test_engine) as session:
        user = User(
            email=email,
            normalized_email=email,
            display_name="Delivery Attempt Test User",
            status="active",
            system_role="user",
            password_hash=hash_password("A secure delivery attempt test passphrase"),
        )

        session.add(user)
        session.flush()

        user_id = user.id

        attempt = EmailChangeDeliveryAttempt(
            user_id=user_id,
            created_at=datetime.now(UTC),
        )

        session.add(attempt)
        session.commit()

        attempt_id = attempt.id

    with Session(test_engine) as session:
        stored_attempt = session.get(
            EmailChangeDeliveryAttempt,
            attempt_id,
        )

        assert stored_attempt is not None
        assert stored_attempt.user_id == user_id
