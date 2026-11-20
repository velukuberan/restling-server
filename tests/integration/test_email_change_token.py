"""PostgreSQL persistence tests for email-change tokens."""

from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from restling_server.users.models import OneTimeToken, User
from restling_server.users.tokens import generate_token, hash_token


def test_email_change_token_is_stored_as_hash(
    db_session: Session,
) -> None:
    """Persist a one-time email-change token without its raw credential."""
    user = User(
        email="current@example.com",
        normalized_email="current@example.com",
        display_name="Token Test User",
        status="pending",
        system_role="user",
    )

    db_session.add(user)
    db_session.flush()

    raw_token = generate_token()
    now = datetime.now(UTC)

    token = OneTimeToken(
        user_id=user.id,
        purpose="email_change",
        token_hash=hash_token(raw_token),
        pending_email="new@example.com",
        created_at=now,
        expires_at=now + timedelta(minutes=30),
    )

    db_session.add(token)
    db_session.flush()

    db_session.expire_all()

    stored_token = db_session.get(OneTimeToken, token.id)

    assert stored_token is not None
    assert stored_token.purpose == "email_change"
    assert stored_token.pending_email == "new@example.com"
    assert stored_token.token_hash == hash_token(raw_token)
    assert stored_token.token_hash != raw_token
    assert stored_token.expires_at > stored_token.created_at
    assert stored_token.consumed_at is None
    assert stored_token.revoked_at is None
