"""PostgreSQL integration tests for refresh-token rotation."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

import pytest
from sqlalchemy import Connection, Engine, delete, event, select
from sqlalchemy.orm import Mapper, Session
from uuid6 import uuid7

from restling_server.users.models import (
    AccessToken,
    LoginSession,
    RefreshTokenHistory,
    User,
)
from restling_server.users.passwords import hash_password
from restling_server.users.service import (
    InvalidCredentialsError,
    login_user,
    refresh_session,
)
from restling_server.users.tokens import hash_token


def test_refresh_rotates_credentials(
    test_engine: Engine,
) -> None:
    """Refreshing rotates credentials without extending the session."""
    email = f"refresh-user-{uuid7().hex}@example.com"
    password = "A secure refresh passphrase #8472"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Refresh Test User",
                status="active",
                system_role="user",
                password_hash=hash_password(password),
            )

            session.add(user)
            session.commit()

        with Session(test_engine) as session:
            original = login_user(
                session,
                email=email,
                password=password,
                access_token_expiry_minutes=15,
                refresh_session_expiry_days=7,
                max_active_sessions=2,
            )

        with Session(test_engine) as session:
            refreshed = refresh_session(
                session,
                refresh_token=original.refresh_token,
                access_token_expiry_minutes=15,
            )

        assert refreshed.session_id == original.session_id
        assert refreshed.access_token != original.access_token
        assert refreshed.refresh_token != original.refresh_token
        assert refreshed.session_expires_at == original.session_expires_at
        assert refreshed.access_token_expires_at <= original.session_expires_at

        with Session(test_engine) as session:
            stored_session = session.get(
                LoginSession,
                original.session_id,
            )

            assert stored_session is not None
            assert stored_session.revoked_at is None
            assert stored_session.refresh_token_hash == hash_token(
                refreshed.refresh_token
            )
            assert stored_session.expires_at == original.session_expires_at
            assert stored_session.last_used_at is not None

            previous_token = session.scalar(
                select(RefreshTokenHistory).where(
                    RefreshTokenHistory.session_id == original.session_id
                )
            )

            assert previous_token is not None
            assert previous_token.token_hash == hash_token(original.refresh_token)

            new_access_token = session.scalar(
                select(AccessToken).where(
                    AccessToken.token_hash == hash_token(refreshed.access_token)
                )
            )

            assert new_access_token is not None
            assert new_access_token.session_id == original.session_id
            assert new_access_token.expires_at == (refreshed.access_token_expires_at)

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(User.normalized_email == email)

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )
            connection.execute(delete(User).where(User.normalized_email == email))


def test_refresh_replay_revokes_session(
    test_engine: Engine,
) -> None:
    """Reusing a consumed refresh token revokes its session."""
    email = f"refresh-replay-{uuid7().hex}@example.com"
    password = "A secure replay test passphrase #8472"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Refresh Replay User",
                status="active",
                system_role="user",
                password_hash=hash_password(password),
            )
            session.add(user)
            session.commit()

        with Session(test_engine) as session:
            original = login_user(
                session,
                email=email,
                password=password,
                access_token_expiry_minutes=15,
                refresh_session_expiry_days=7,
                max_active_sessions=2,
            )

        with Session(test_engine) as session:
            rotated = refresh_session(
                session,
                refresh_token=original.refresh_token,
                access_token_expiry_minutes=15,
            )

        # The original refresh token has already been consumed.
        with Session(test_engine) as session:
            with pytest.raises(InvalidCredentialsError):
                refresh_session(
                    session,
                    refresh_token=original.refresh_token,
                    access_token_expiry_minutes=15,
                )

        # Rejecting the replay must not roll back the revocation.
        with Session(test_engine) as session:
            stored = session.get(LoginSession, original.session_id)

            assert stored is not None
            assert stored.revoked_at is not None
            assert stored.revocation_reason == "refresh_token_replay"
            assert stored.refresh_token_hash is None

        # The replacement refresh token must also be unusable.
        with Session(test_engine) as session:
            with pytest.raises(InvalidCredentialsError):
                refresh_session(
                    session,
                    refresh_token=rotated.refresh_token,
                    access_token_expiry_minutes=15,
                )

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(User.normalized_email == email)

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )
            connection.execute(delete(User).where(User.normalized_email == email))


def test_concurrent_refresh_detects_replay(
    test_engine: Engine,
) -> None:
    """Concurrent reuse of one refresh credential revokes the session."""
    email = f"concurrent-refresh-{uuid7().hex}@example.com"
    password = "A secure concurrent refresh passphrase #8472"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Concurrent Refresh User",
                status="active",
                system_role="user",
                password_hash=hash_password(password),
            )
            session.add(user)
            session.commit()

        with Session(test_engine) as session:
            original = login_user(
                session,
                email=email,
                password=password,
                access_token_expiry_minutes=15,
                refresh_session_expiry_days=7,
                max_active_sessions=2,
            )

        barrier = Barrier(3)

        def attempt_refresh() -> bool:
            with Session(test_engine) as session:
                barrier.wait(timeout=10)

                try:
                    refresh_session(
                        session,
                        refresh_token=original.refresh_token,
                        access_token_expiry_minutes=15,
                    )
                except InvalidCredentialsError:
                    return False

                return True

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(attempt_refresh) for _ in range(2)]

            barrier.wait(timeout=10)
            results = [future.result(timeout=15) for future in futures]

        assert results.count(True) == 1
        assert results.count(False) == 1

        with Session(test_engine) as session:
            stored = session.get(LoginSession, original.session_id)

            assert stored is not None
            assert stored.revoked_at is not None
            assert stored.revocation_reason == "refresh_token_replay"
            assert stored.refresh_token_hash is None

            history = session.scalars(
                select(RefreshTokenHistory).where(
                    RefreshTokenHistory.session_id == original.session_id
                )
            ).all()

            assert len(history) == 1
            assert history[0].token_hash == hash_token(original.refresh_token)

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(User.normalized_email == email)

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )
            connection.execute(delete(User).where(User.normalized_email == email))


@pytest.mark.parametrize("session_state", ["expired", "revoked"])
def test_refresh_rejects_inactive_session(
    test_engine: Engine,
    session_state: str,
) -> None:
    """Expired or revoked sessions cannot refresh credentials."""
    email = f"inactive-refresh-{uuid7().hex}@example.com"
    password = "A secure inactive refresh passphrase #8472"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Inactive Refresh User",
                status="active",
                system_role="user",
                password_hash=hash_password(password),
            )
            session.add(user)
            session.commit()

        with Session(test_engine) as session:
            original = login_user(
                session,
                email=email,
                password=password,
                access_token_expiry_minutes=15,
                refresh_session_expiry_days=7,
                max_active_sessions=2,
            )

        with Session(test_engine) as session:
            stored = session.get(LoginSession, original.session_id)
            assert stored is not None

            now = datetime.now(UTC)

            if session_state == "expired":
                stored.created_at = now - timedelta(days=8)
                stored.expires_at = now - timedelta(days=1)
            else:
                stored.refresh_token_hash = None
                stored.revoked_at = now
                stored.revocation_reason = "logout"

            session.commit()

        with Session(test_engine) as session:
            with pytest.raises(InvalidCredentialsError):
                refresh_session(
                    session,
                    refresh_token=original.refresh_token,
                    access_token_expiry_minutes=15,
                )

        with Session(test_engine) as session:
            history = session.scalars(
                select(RefreshTokenHistory).where(
                    RefreshTokenHistory.session_id == original.session_id
                )
            ).all()

            assert history == []

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(User.normalized_email == email)

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )
            connection.execute(delete(User).where(User.normalized_email == email))


@pytest.mark.parametrize(
    "refresh_token",
    [
        "",
        "   ",
        "invalid-token",
        "A" * 43,
    ],
)
def test_refresh_rejects_invalid_credentials(
    db_session: Session,
    refresh_token: str,
) -> None:
    """Unknown refresh credentials must be rejected."""
    with pytest.raises(
        InvalidCredentialsError,
        match="Invalid refresh credential",
    ):
        refresh_session(
            db_session,
            refresh_token=refresh_token,
            access_token_expiry_minutes=15,
        )

    assert db_session.scalars(select(LoginSession)).all() == []
    assert db_session.scalars(select(AccessToken)).all() == []
    assert db_session.scalars(select(RefreshTokenHistory)).all() == []


def test_refresh_rolls_back_when_access_token_insert_fails(
    test_engine: Engine,
) -> None:
    """Failed token persistence leaves the original credentials intact."""
    email = f"refresh-rollback-{uuid7().hex}@example.com"
    password = "A secure refresh rollback passphrase #8472"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Refresh Rollback User",
                status="active",
                system_role="user",
                password_hash=hash_password(password),
            )
            session.add(user)
            session.commit()

        with Session(test_engine) as session:
            original = login_user(
                session,
                email=email,
                password=password,
                access_token_expiry_minutes=15,
                refresh_session_expiry_days=7,
                max_active_sessions=2,
            )

        def reject_access_token_insert(
            _mapper: Mapper[AccessToken],
            _connection: Connection,
            _target: AccessToken,
        ) -> None:
            raise RuntimeError("Simulated refresh persistence failure")

        event.listen(
            AccessToken,
            "before_insert",
            reject_access_token_insert,
        )

        try:
            with Session(test_engine) as session:
                with pytest.raises(
                    RuntimeError,
                    match="Simulated refresh persistence failure",
                ):
                    refresh_session(
                        session,
                        refresh_token=original.refresh_token,
                        access_token_expiry_minutes=15,
                    )
        finally:
            event.remove(
                AccessToken,
                "before_insert",
                reject_access_token_insert,
            )

        with Session(test_engine) as session:
            stored = session.get(LoginSession, original.session_id)

            assert stored is not None
            assert stored.revoked_at is None
            assert stored.refresh_token_hash == hash_token(original.refresh_token)
            assert stored.last_used_at is None

            history = session.scalars(
                select(RefreshTokenHistory).where(
                    RefreshTokenHistory.session_id == original.session_id
                )
            ).all()

            assert history == []

            access_tokens = session.scalars(
                select(AccessToken).where(AccessToken.session_id == original.session_id)
            ).all()

            assert len(access_tokens) == 1
            assert access_tokens[0].token_hash == hash_token(original.access_token)

        # The original refresh token must still work after rollback.
        with Session(test_engine) as session:
            refreshed = refresh_session(
                session,
                refresh_token=original.refresh_token,
                access_token_expiry_minutes=15,
            )

        assert refreshed.session_id == original.session_id
        assert refreshed.refresh_token != original.refresh_token

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(User.normalized_email == email)

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )
            connection.execute(delete(User).where(User.normalized_email == email))


@pytest.mark.parametrize(
    ("status", "password_reset_required"),
    [
        ("suspended", False),
        ("active", True),
    ],
)
def test_refresh_rejects_ineligible_account(
    test_engine: Engine,
    status: str,
    password_reset_required: bool,
) -> None:
    """Ineligible accounts cannot obtain replacement credentials."""
    email = f"ineligible-refresh-{uuid7().hex}@example.com"
    password = "A secure refresh eligibility passphrase #8472"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Refresh Eligibility User",
                status="active",
                system_role="user",
                password_hash=hash_password(password),
            )
            session.add(user)
            session.commit()
            user_id = user.id

        with Session(test_engine) as session:
            original = login_user(
                session,
                email=email,
                password=password,
                access_token_expiry_minutes=15,
                refresh_session_expiry_days=7,
                max_active_sessions=2,
            )

        # Change account eligibility after the original login.
        with Session(test_engine) as session:
            user = session.get(User, user_id)
            assert user is not None

            user.status = status
            user.password_reset_required = password_reset_required
            session.commit()

        with Session(test_engine) as session:
            with pytest.raises(InvalidCredentialsError):
                refresh_session(
                    session,
                    refresh_token=original.refresh_token,
                    access_token_expiry_minutes=15,
                )

        with Session(test_engine) as session:
            stored = session.get(LoginSession, original.session_id)
            assert stored is not None

            assert stored.refresh_token_hash == hash_token(original.refresh_token)
            assert stored.last_used_at is None

            history = session.scalars(
                select(RefreshTokenHistory).where(
                    RefreshTokenHistory.session_id == original.session_id
                )
            ).all()

            assert history == []

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(User.normalized_email == email)

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )
            connection.execute(delete(User).where(User.normalized_email == email))
