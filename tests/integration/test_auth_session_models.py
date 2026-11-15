"""PostgreSQL integration tests for authentication session models."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from restling_server.users.models import (
    AccessToken,
    LoginSession,
    RefreshTokenHistory,
    User,
)


def create_test_session(db_session: Session) -> LoginSession:
    """Create a pending user and an associated login session."""
    user = User(
        email="session-test@example.com",
        normalized_email="session-test@example.com",
        display_name="Session Test",
        status="pending",
        system_role="user",
        password_hash=None,
    )
    db_session.add(user)
    db_session.flush()

    now = datetime.now(UTC)

    login_session = LoginSession(
        user_id=user.id,
        refresh_token_hash="a" * 64,
        created_at=now,
        expires_at=now + timedelta(days=7),
    )
    db_session.add(login_session)
    db_session.flush()

    return login_session


def test_session_persists_with_valid_user(
    db_session: Session,
) -> None:
    login_session = create_test_session(db_session)

    stored = db_session.get(LoginSession, login_session.id)

    assert stored is not None
    assert stored.user_id == login_session.user_id
    assert stored.revoked_at is None


def test_session_rejects_invalid_expiration(
    db_session: Session,
) -> None:
    login_session = create_test_session(db_session)

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            login_session.expires_at = login_session.created_at
            db_session.flush()

    db_session.refresh(login_session)


def test_session_rejects_revocation_with_refresh_hash(
    db_session: Session,
) -> None:
    login_session = create_test_session(db_session)

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            login_session.revoked_at = datetime.now(UTC)
            login_session.revocation_reason = "logout"
            db_session.flush()

    db_session.refresh(login_session)


def test_access_token_rejects_empty_hash(
    db_session: Session,
) -> None:
    login_session = create_test_session(db_session)
    now = datetime.now(UTC)

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(
                AccessToken(
                    session_id=login_session.id,
                    token_hash="",
                    created_at=now,
                    expires_at=now + timedelta(minutes=15),
                )
            )
            db_session.flush()


def test_access_token_hash_must_be_unique(
    db_session: Session,
) -> None:
    login_session = create_test_session(db_session)
    now = datetime.now(UTC)

    first_token = AccessToken(
        session_id=login_session.id,
        token_hash="b" * 64,
        created_at=now,
        expires_at=now + timedelta(minutes=15),
    )
    db_session.add(first_token)
    db_session.flush()

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(
                AccessToken(
                    session_id=login_session.id,
                    token_hash="b" * 64,
                    created_at=now,
                    expires_at=now + timedelta(minutes=15),
                )
            )
            db_session.flush()


def test_deleting_session_cascades_to_child_tokens(
    db_session: Session,
) -> None:
    login_session = create_test_session(db_session)
    now = datetime.now(UTC)

    access_token = AccessToken(
        session_id=login_session.id,
        token_hash="c" * 64,
        created_at=now,
        expires_at=now + timedelta(minutes=15),
    )

    refresh_history = RefreshTokenHistory(
        session_id=login_session.id,
        token_hash="d" * 64,
        used_at=now,
    )

    db_session.add_all([access_token, refresh_history])
    db_session.flush()

    access_token_id = access_token.id
    history_id = refresh_history.id
    user_id = login_session.user_id

    db_session.execute(delete(LoginSession).where(LoginSession.id == login_session.id))
    db_session.flush()

    # Database-level cascades do not synchronize all objects
    # already held in SQLAlchemy's identity map.
    db_session.expire_all()

    assert db_session.get(AccessToken, access_token_id) is None
    assert db_session.get(RefreshTokenHistory, history_id) is None
    assert db_session.get(User, user_id) is not None


def test_user_cannot_be_deleted_while_session_exists(
    db_session: Session,
) -> None:
    login_session = create_test_session(db_session)

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.execute(delete(User).where(User.id == login_session.user_id))
            db_session.flush()

    assert db_session.get(LoginSession, login_session.id) is not None


def test_refresh_history_rejects_empty_hash(
    db_session: Session,
) -> None:
    login_session = create_test_session(db_session)

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(
                RefreshTokenHistory(
                    session_id=login_session.id,
                    token_hash=" ",
                    used_at=datetime.now(UTC),
                )
            )
            db_session.flush()


def test_refresh_hash_cannot_be_blank(
    db_session: Session,
) -> None:
    login_session = create_test_session(db_session)

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            login_session.refresh_token_hash = " "
            db_session.flush()

    db_session.refresh(login_session)


def test_refresh_token_hash_must_be_unique(
    db_session: Session,
) -> None:
    first_session = create_test_session(db_session)

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(
                LoginSession(
                    user_id=first_session.user_id,
                    refresh_token_hash=first_session.refresh_token_hash,
                    expires_at=datetime.now(UTC) + timedelta(days=7),
                )
            )
            db_session.flush()


def test_refresh_history_hash_must_be_unique(
    db_session: Session,
) -> None:
    login_session = create_test_session(db_session)

    first_entry = RefreshTokenHistory(
        session_id=login_session.id,
        token_hash="e" * 64,
    )
    db_session.add(first_entry)
    db_session.flush()

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(
                RefreshTokenHistory(
                    session_id=login_session.id,
                    token_hash="e" * 64,
                )
            )
            db_session.flush()


def test_session_can_be_revoked(
    db_session: Session,
) -> None:
    login_session = create_test_session(db_session)

    login_session.refresh_token_hash = None
    login_session.revoked_at = datetime.now(UTC)
    login_session.revocation_reason = "logout"

    db_session.flush()
    db_session.refresh(login_session)

    assert login_session.refresh_token_hash is None
    assert login_session.revoked_at is not None
    assert login_session.revocation_reason == "logout"
