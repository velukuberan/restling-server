"""PostgreSQL integration tests for self-service session management."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

import pytest
from sqlalchemy import Connection, Engine, delete, event, select
from sqlalchemy.orm import Mapper, Session
from uuid6 import uuid7

from restling_server.users.models import LoginSession, User
from restling_server.users.passwords import hash_password
from restling_server.users.service import (
    InvalidCredentialsError,
    SessionNotFoundError,
    authenticate_access_token,
    list_user_session_history,
    list_user_sessions,
    login_user,
    refresh_session,
    revoke_all_user_sessions,
    revoke_other_sessions,
    revoke_user_session,
)
from restling_server.users.tokens import hash_token


def test_list_user_sessions_returns_own_active_sessions(
    test_engine: Engine,
) -> None:
    """A user can list their active sessions and identify the current one."""
    email = f"session-list-{uuid7().hex}@example.com"
    password = "A secure session listing passphrase #8472"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Session List User",
                status="active",
                system_role="user",
                password_hash=hash_password(password),
            )

            session.add(user)
            session.commit()

        with Session(test_engine) as session:
            first = login_user(
                session,
                email=email,
                password=password,
                access_token_expiry_minutes=15,
                refresh_session_expiry_days=7,
                max_active_sessions=2,
            )

        with Session(test_engine) as session:
            second = login_user(
                session,
                email=email,
                password=password,
                access_token_expiry_minutes=15,
                refresh_session_expiry_days=7,
                max_active_sessions=2,
            )

        with Session(test_engine) as session:
            results = list_user_sessions(
                session,
                access_token=first.access_token,
            )

            assert len(results) == 2

            by_id = {item.session_id: item for item in results}

            assert set(by_id) == {
                first.session_id,
                second.session_id,
            }

            assert by_id[first.session_id].is_current is True
            assert by_id[second.session_id].is_current is False

            for item in results:
                assert item.expires_at > item.created_at
                assert not hasattr(item, "refresh_token_hash")
                assert not hasattr(item, "token_hash")

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(User.normalized_email == email)

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )
            connection.execute(delete(User).where(User.normalized_email == email))


def test_list_user_sessions_excludes_other_users(
    test_engine: Engine,
) -> None:
    """Session listing never exposes another user's sessions."""
    email_a = f"session-owner-a-{uuid7().hex}@example.com"
    email_b = f"session-owner-b-{uuid7().hex}@example.com"
    password = "A secure session isolation passphrase #8472"

    try:
        with Session(test_engine) as session:
            for email in (email_a, email_b):
                session.add(
                    User(
                        email=email,
                        normalized_email=email,
                        display_name="Session Isolation User",
                        status="active",
                        system_role="user",
                        password_hash=hash_password(password),
                    )
                )
            session.commit()

        def create_login(email: str):
            with Session(test_engine) as session:
                return login_user(
                    session,
                    email=email,
                    password=password,
                    access_token_expiry_minutes=15,
                    refresh_session_expiry_days=7,
                    max_active_sessions=2,
                )

        first_a = create_login(email_a)
        second_a = create_login(email_a)
        first_b = create_login(email_b)

        with Session(test_engine) as session:
            sessions_a = list_user_sessions(
                session,
                access_token=first_a.access_token,
            )

        assert {item.session_id for item in sessions_a} == {
            first_a.session_id,
            second_a.session_id,
        }
        assert all(item.session_id != first_b.session_id for item in sessions_a)

        with Session(test_engine) as session:
            sessions_b = list_user_sessions(
                session,
                access_token=first_b.access_token,
            )

        assert len(sessions_b) == 1
        assert sessions_b[0].session_id == first_b.session_id
        assert sessions_b[0].is_current is True

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(
                User.normalized_email.in_([email_a, email_b])
            )
            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )
            connection.execute(
                delete(User).where(User.normalized_email.in_([email_a, email_b]))
            )


def test_list_user_sessions_excludes_inactive_sessions(
    test_engine: Engine,
) -> None:
    """Session listing excludes revoked and expired sessions."""
    email = f"inactive-session-list-{uuid7().hex}@example.com"
    password = "A secure inactive session passphrase #8472"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Inactive Session List User",
                status="active",
                system_role="user",
                password_hash=hash_password(password),
            )
            session.add(user)
            session.commit()

        def create_login():
            with Session(test_engine) as session:
                return login_user(
                    session,
                    email=email,
                    password=password,
                    access_token_expiry_minutes=15,
                    refresh_session_expiry_days=7,
                    max_active_sessions=3,
                )

        active = create_login()
        revoked = create_login()
        expired = create_login()

        with Session(test_engine) as session:
            revoked_session = session.get(LoginSession, revoked.session_id)
            expired_session = session.get(LoginSession, expired.session_id)

            assert revoked_session is not None
            assert expired_session is not None

            now = datetime.now(UTC)

            revoked_session.refresh_token_hash = None
            revoked_session.revoked_at = now
            revoked_session.revocation_reason = "logout"

            expired_session.created_at = now - timedelta(days=8)
            expired_session.expires_at = now - timedelta(days=1)

            session.commit()

        with Session(test_engine) as session:
            results = list_user_sessions(
                session,
                access_token=active.access_token,
            )

        assert len(results) == 1
        assert results[0].session_id == active.session_id
        assert results[0].is_current is True

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(User.normalized_email == email)

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )
            connection.execute(delete(User).where(User.normalized_email == email))


@pytest.mark.parametrize(
    "access_token",
    [
        "",
        "   ",
        "invalid-token",
        "A" * 43,
    ],
)
def test_list_user_sessions_rejects_invalid_credentials(
    db_session: Session,
    access_token: str,
) -> None:
    """Invalid access credentials cannot retrieve session information."""
    with pytest.raises(
        InvalidCredentialsError,
        match="Invalid access credential",
    ):
        list_user_sessions(
            db_session,
            access_token=access_token,
        )


def test_revoke_user_session_revokes_owned_session(
    test_engine: Engine,
) -> None:
    """A user can revoke another session without losing the current one."""
    email = f"session-revoke-{uuid7().hex}@example.com"
    password = "A secure session revocation passphrase #8472"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Session Revocation User",
                status="active",
                system_role="user",
                password_hash=hash_password(password),
            )
            session.add(user)
            session.commit()

        with Session(test_engine) as session:
            current = login_user(
                session,
                email=email,
                password=password,
                access_token_expiry_minutes=15,
                refresh_session_expiry_days=7,
                max_active_sessions=2,
            )

        with Session(test_engine) as session:
            other = login_user(
                session,
                email=email,
                password=password,
                access_token_expiry_minutes=15,
                refresh_session_expiry_days=7,
                max_active_sessions=2,
            )

        with Session(test_engine) as session:
            revoke_user_session(
                session,
                access_token=current.access_token,
                target_session_id=other.session_id,
            )

        with Session(test_engine) as session:
            revoked = session.get(LoginSession, other.session_id)
            remaining = session.get(LoginSession, current.session_id)

            assert revoked is not None
            assert revoked.revoked_at is not None
            assert revoked.revocation_reason == "user_revoked"
            assert revoked.refresh_token_hash is None

            assert remaining is not None
            assert remaining.revoked_at is None

        with Session(test_engine) as session:
            results = list_user_sessions(
                session,
                access_token=current.access_token,
            )

            assert len(results) == 1
            assert results[0].session_id == current.session_id
            assert results[0].is_current is True

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(User.normalized_email == email)

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )
            connection.execute(delete(User).where(User.normalized_email == email))


def test_revoke_user_session_rejects_other_users_session(
    test_engine: Engine,
) -> None:
    """A user cannot revoke a session owned by another account."""
    email_a = f"revoke-owner-a-{uuid7().hex}@example.com"
    email_b = f"revoke-owner-b-{uuid7().hex}@example.com"
    password = "A secure cross-user revocation passphrase #8472"

    try:
        with Session(test_engine) as session:
            for email in (email_a, email_b):
                session.add(
                    User(
                        email=email,
                        normalized_email=email,
                        display_name="Cross User Revocation Test",
                        status="active",
                        system_role="user",
                        password_hash=hash_password(password),
                    )
                )
            session.commit()

        with Session(test_engine) as session:
            login_a = login_user(
                session,
                email=email_a,
                password=password,
                access_token_expiry_minutes=15,
                refresh_session_expiry_days=7,
                max_active_sessions=2,
            )

        with Session(test_engine) as session:
            login_b = login_user(
                session,
                email=email_b,
                password=password,
                access_token_expiry_minutes=15,
                refresh_session_expiry_days=7,
                max_active_sessions=2,
            )

        # User A attempts to revoke User B's session.
        with Session(test_engine) as session:
            with pytest.raises(
                SessionNotFoundError,
                match=r"Session not found\.",
            ):
                revoke_user_session(
                    session,
                    access_token=login_a.access_token,
                    target_session_id=login_b.session_id,
                )

        # User B's session must remain completely usable.
        with Session(test_engine) as session:
            stored = session.get(LoginSession, login_b.session_id)

            assert stored is not None
            assert stored.revoked_at is None

        with Session(test_engine) as session:
            authenticated = authenticate_access_token(
                session,
                access_token=login_b.access_token,
            )
            assert authenticated.email == email_b

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(
                User.normalized_email.in_([email_a, email_b])
            )

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )
            connection.execute(
                delete(User).where(User.normalized_email.in_([email_a, email_b]))
            )


def test_revoke_user_session_rejects_unknown_target(
    test_engine: Engine,
) -> None:
    """An unknown session ID cannot revoke the current session."""
    email = f"unknown-session-{uuid7().hex}@example.com"
    password = "A secure unknown session passphrase #8472"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Unknown Session Test User",
                status="active",
                system_role="user",
                password_hash=hash_password(password),
            )
            session.add(user)
            session.commit()

        with Session(test_engine) as session:
            current = login_user(
                session,
                email=email,
                password=password,
                access_token_expiry_minutes=15,
                refresh_session_expiry_days=7,
                max_active_sessions=2,
            )

        unknown_session_id = uuid7()
        assert unknown_session_id != current.session_id

        with Session(test_engine) as session:
            with pytest.raises(
                SessionNotFoundError,
                match=r"Session not found\.",
            ):
                revoke_user_session(
                    session,
                    access_token=current.access_token,
                    target_session_id=unknown_session_id,
                )

        # The legitimate session must remain usable.
        with Session(test_engine) as session:
            authenticated = authenticate_access_token(
                session,
                access_token=current.access_token,
            )
            assert authenticated.email == email

            stored = session.get(LoginSession, current.session_id)
            assert stored is not None
            assert stored.revoked_at is None

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(User.normalized_email == email)

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )
            connection.execute(delete(User).where(User.normalized_email == email))


@pytest.mark.parametrize("target_state", ["revoked", "expired"])
def test_revoke_user_session_accepts_inactive_target(
    test_engine: Engine,
    target_state: str,
) -> None:
    """Already-revoked or expired sessions cannot be revoked again."""
    email = f"inactive-revoke-{uuid7().hex}@example.com"
    password = "A secure inactive revocation passphrase #8472"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Inactive Target User",
                status="active",
                system_role="user",
                password_hash=hash_password(password),
            )
            session.add(user)
            session.commit()

        with Session(test_engine) as session:
            current = login_user(
                session,
                email=email,
                password=password,
                access_token_expiry_minutes=15,
                refresh_session_expiry_days=7,
                max_active_sessions=2,
            )

        with Session(test_engine) as session:
            target_login = login_user(
                session,
                email=email,
                password=password,
                access_token_expiry_minutes=15,
                refresh_session_expiry_days=7,
                max_active_sessions=2,
            )

        with Session(test_engine) as session:
            target = session.get(LoginSession, target_login.session_id)
            assert target is not None

            now = datetime.now(UTC)

            if target_state == "revoked":
                target.refresh_token_hash = None
                target.revoked_at = now
                target.revocation_reason = "logout"
            else:
                target.created_at = now - timedelta(days=8)
                target.expires_at = now - timedelta(days=1)

            session.commit()

        with Session(test_engine) as session:
            revoke_user_session(
                session,
                access_token=current.access_token,
                target_session_id=target_login.session_id,
            )

        with Session(test_engine) as session:
            target = session.get(LoginSession, target_login.session_id)
            current_session = session.get(LoginSession, current.session_id)

            assert target is not None
            assert current_session is not None
            assert current_session.revoked_at is None

            if target_state == "revoked":
                assert target.revoked_at is not None
                assert target.revocation_reason == "logout"
            else:
                assert target.revoked_at is None
                assert target.expires_at <= datetime.now(UTC)

        # The requesting session must still authenticate.
        with Session(test_engine) as session:
            authenticated = authenticate_access_token(
                session,
                access_token=current.access_token,
            )
            assert authenticated.email == email

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(User.normalized_email == email)

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )
            connection.execute(delete(User).where(User.normalized_email == email))


def test_revoke_other_sessions_preserves_current_session(
    test_engine: Engine,
) -> None:
    """Revoke all other active sessions without revoking the current one."""
    email = f"revoke-others-{uuid7().hex}@example.com"
    password = "A secure bulk revocation passphrase #8472"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Bulk Revocation User",
                status="active",
                system_role="user",
                password_hash=hash_password(password),
            )
            session.add(user)
            session.commit()

        def create_login():
            with Session(test_engine) as session:
                return login_user(
                    session,
                    email=email,
                    password=password,
                    access_token_expiry_minutes=15,
                    refresh_session_expiry_days=7,
                    max_active_sessions=3,
                )

        current = create_login()
        second = create_login()
        third = create_login()

        with Session(test_engine) as session:
            revoked_count = revoke_other_sessions(
                session,
                access_token=current.access_token,
            )

        assert revoked_count == 2

        # Repeating the operation must not revoke the current session.
        with Session(test_engine) as session:
            repeated_count = revoke_other_sessions(
                session,
                access_token=current.access_token,
            )

        assert repeated_count == 0

        with Session(test_engine) as session:
            current_session = session.get(LoginSession, current.session_id)

            assert current_session is not None
            assert current_session.revoked_at is None

            for session_id in (second.session_id, third.session_id):
                stored = session.get(LoginSession, session_id)

                assert stored is not None
                assert stored.revoked_at is not None
                assert stored.revocation_reason == "user_revoked"
                assert stored.refresh_token_hash is None

        with Session(test_engine) as session:
            authenticated = authenticate_access_token(
                session,
                access_token=current.access_token,
            )
            assert authenticated.email == email

            results = list_user_sessions(
                session,
                access_token=current.access_token,
            )
            assert len(results) == 1
            assert results[0].session_id == current.session_id

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(User.normalized_email == email)

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )
            connection.execute(delete(User).where(User.normalized_email == email))


def test_revoke_other_sessions_does_not_affect_other_users(
    test_engine: Engine,
) -> None:
    """Bulk revocation affects only the authenticated user's sessions."""
    email_a = f"bulk-owner-a-{uuid7().hex}@example.com"
    email_b = f"bulk-owner-b-{uuid7().hex}@example.com"
    password = "A secure bulk isolation passphrase #8472"

    try:
        with Session(test_engine) as session:
            for email in (email_a, email_b):
                session.add(
                    User(
                        email=email,
                        normalized_email=email,
                        display_name="Bulk Isolation User",
                        status="active",
                        system_role="user",
                        password_hash=hash_password(password),
                    )
                )
            session.commit()

        def create_login(email: str):
            with Session(test_engine) as session:
                return login_user(
                    session,
                    email=email,
                    password=password,
                    access_token_expiry_minutes=15,
                    refresh_session_expiry_days=7,
                    max_active_sessions=2,
                )

        current_a = create_login(email_a)
        other_a = create_login(email_a)
        current_b = create_login(email_b)

        with Session(test_engine) as session:
            revoked_count = revoke_other_sessions(
                session,
                access_token=current_a.access_token,
            )

        assert revoked_count == 1

        with Session(test_engine) as session:
            stored_a = session.get(LoginSession, other_a.session_id)
            stored_b = session.get(LoginSession, current_b.session_id)

            assert stored_a is not None
            assert stored_a.revoked_at is not None

            assert stored_b is not None
            assert stored_b.revoked_at is None
            assert stored_b.refresh_token_hash == hash_token(current_b.refresh_token)

        # User B must still be able to authenticate and refresh.
        with Session(test_engine) as session:
            authenticated = authenticate_access_token(
                session,
                access_token=current_b.access_token,
            )
            assert authenticated.email == email_b

        with Session(test_engine) as session:
            refreshed = refresh_session(
                session,
                refresh_token=current_b.refresh_token,
                access_token_expiry_minutes=15,
            )

        assert refreshed.session_id == current_b.session_id

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(
                User.normalized_email.in_([email_a, email_b])
            )

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )
            connection.execute(
                delete(User).where(User.normalized_email.in_([email_a, email_b]))
            )


def test_revoke_other_sessions_rolls_back_on_failure(
    test_engine: Engine,
) -> None:
    """Failure during bulk revocation rolls back all session updates."""
    email = f"bulk-rollback-{uuid7().hex}@example.com"
    password = "A secure bulk rollback passphrase #8472"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Bulk Rollback User",
                status="active",
                system_role="user",
                password_hash=hash_password(password),
            )
            session.add(user)
            session.commit()

        def create_login():
            with Session(test_engine) as session:
                return login_user(
                    session,
                    email=email,
                    password=password,
                    access_token_expiry_minutes=15,
                    refresh_session_expiry_days=7,
                    max_active_sessions=3,
                )

        current = create_login()
        second = create_login()
        third = create_login()

        updates_seen = 0

        def reject_second_update(
            _mapper: Mapper[LoginSession],
            _connection: Connection,
            _target: LoginSession,
        ) -> None:
            nonlocal updates_seen
            updates_seen += 1

            if updates_seen == 2:
                raise RuntimeError("Simulated bulk revocation failure")

        event.listen(LoginSession, "before_update", reject_second_update)

        try:
            with Session(test_engine) as session:
                with pytest.raises(
                    RuntimeError,
                    match="Simulated bulk revocation failure",
                ):
                    revoke_other_sessions(
                        session,
                        access_token=current.access_token,
                    )
        finally:
            event.remove(
                LoginSession,
                "before_update",
                reject_second_update,
            )

        assert updates_seen == 2

        # Neither session should have been revoked.
        with Session(test_engine) as session:
            for login in (current, second, third):
                stored = session.get(LoginSession, login.session_id)

                assert stored is not None
                assert stored.revoked_at is None
                assert stored.revocation_reason is None
                assert stored.refresh_token_hash == hash_token(login.refresh_token)

        # Retrying the operation should revoke both other sessions.
        with Session(test_engine) as session:
            revoked_count = revoke_other_sessions(
                session,
                access_token=current.access_token,
            )

        assert revoked_count == 2

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(User.normalized_email == email)

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )
            connection.execute(delete(User).where(User.normalized_email == email))


def test_concurrent_session_revocation_and_refresh(
    test_engine: Engine,
) -> None:
    """Concurrent refresh cannot restore a revoked target session."""
    email = f"concurrent-revoke-{uuid7().hex}@example.com"
    password = "A secure concurrent revocation passphrase #8472"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Concurrent Revocation User",
                status="active",
                system_role="user",
                password_hash=hash_password(password),
            )
            session.add(user)
            session.commit()

        with Session(test_engine) as session:
            current = login_user(
                session,
                email=email,
                password=password,
                access_token_expiry_minutes=15,
                refresh_session_expiry_days=7,
                max_active_sessions=2,
            )

        with Session(test_engine) as session:
            target = login_user(
                session,
                email=email,
                password=password,
                access_token_expiry_minutes=15,
                refresh_session_expiry_days=7,
                max_active_sessions=2,
            )

        barrier = Barrier(3)

        def attempt_revocation() -> None:
            with Session(test_engine) as session:
                barrier.wait(timeout=10)
                revoke_user_session(
                    session,
                    access_token=current.access_token,
                    target_session_id=target.session_id,
                )

        def attempt_refresh() -> str | None:
            with Session(test_engine) as session:
                barrier.wait(timeout=10)

                try:
                    refreshed = refresh_session(
                        session,
                        refresh_token=target.refresh_token,
                        access_token_expiry_minutes=15,
                    )
                except InvalidCredentialsError:
                    return None

                return refreshed.access_token

        with ThreadPoolExecutor(max_workers=2) as executor:
            revoke_future = executor.submit(attempt_revocation)
            refresh_future = executor.submit(attempt_refresh)

            barrier.wait(timeout=10)

            revoke_future.result(timeout=15)
            refreshed_access_token = refresh_future.result(timeout=15)

        with Session(test_engine) as session:
            stored = session.get(LoginSession, target.session_id)

            assert stored is not None
            assert stored.revoked_at is not None
            assert stored.revocation_reason == "user_revoked"
            assert stored.refresh_token_hash is None

        # Session A must remain authenticated.
        with Session(test_engine) as session:
            authenticated = authenticate_access_token(
                session,
                access_token=current.access_token,
            )
            assert authenticated.email == email

        # Session B's original credential must be invalid.
        with Session(test_engine) as session:
            with pytest.raises(InvalidCredentialsError):
                authenticate_access_token(
                    session,
                    access_token=target.access_token,
                )

        # Any credential issued during the race must also be invalid.
        if refreshed_access_token is not None:
            with Session(test_engine) as session:
                with pytest.raises(InvalidCredentialsError):
                    authenticate_access_token(
                        session,
                        access_token=refreshed_access_token,
                    )

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(User.normalized_email == email)

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )
            connection.execute(delete(User).where(User.normalized_email == email))


def test_revoke_user_session_can_revoke_current_session(
    test_engine: Engine,
) -> None:
    """A user can explicitly revoke their own current session."""
    email = f"self-revoke-{uuid7().hex}@example.com"
    password = "A secure self-revocation passphrase #8472"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Self Revocation User",
                status="active",
                system_role="user",
                password_hash=hash_password(password),
            )
            session.add(user)
            session.commit()

        with Session(test_engine) as session:
            current = login_user(
                session,
                email=email,
                password=password,
                access_token_expiry_minutes=15,
                refresh_session_expiry_days=7,
                max_active_sessions=2,
            )

        with Session(test_engine) as session:
            revoke_user_session(
                session,
                access_token=current.access_token,
                target_session_id=current.session_id,
            )

        with Session(test_engine) as session:
            stored = session.get(LoginSession, current.session_id)

            assert stored is not None
            assert stored.revoked_at is not None
            assert stored.revocation_reason == "user_revoked"
            assert stored.refresh_token_hash is None

        with Session(test_engine) as session:
            with pytest.raises(InvalidCredentialsError):
                authenticate_access_token(
                    session,
                    access_token=current.access_token,
                )

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(User.normalized_email == email)

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )
            connection.execute(delete(User).where(User.normalized_email == email))


def test_session_history_retention_ordering_and_isolation(
    test_engine: Engine,
) -> None:
    """Retain recent history and paginate sessions deterministically."""
    email = f"history-owner-{uuid7().hex}@example.com"
    other_email = f"history-other-{uuid7().hex}@example.com"
    password = "A secure session history passphrase #8472"

    try:
        with Session(test_engine) as session:
            for address in (email, other_email):
                session.add(
                    User(
                        email=address,
                        normalized_email=address,
                        display_name="Session History User",
                        status="active",
                        system_role="user",
                        password_hash=hash_password(password),
                    )
                )
            session.commit()

        def create_login(address: str):
            with Session(test_engine) as session:
                return login_user(
                    session,
                    email=address,
                    password=password,
                    access_token_expiry_minutes=15,
                    refresh_session_expiry_days=7,
                    max_active_sessions=10,
                )

        current = create_login(email)
        other_active = create_login(email)
        recent_revoked = create_login(email)
        old_revoked = create_login(email)
        recent_expired = create_login(email)
        old_expired = create_login(email)
        foreign = create_login(other_email)

        now = datetime.now(UTC)
        tied_created_at = now - timedelta(minutes=1)

        with Session(test_engine) as session:
            current_record = session.get(LoginSession, current.session_id)
            other_active_record = session.get(LoginSession, other_active.session_id)

            assert current_record is not None
            assert other_active_record is not None

            # Deliberately give the active sessions identical timestamps.
            # UUID is the stable secondary sorting key.
            current_record.created_at = tied_created_at
            other_active_record.created_at = tied_created_at

            for result, revoked_days in (
                (recent_revoked, 2),
                (old_revoked, 31),
            ):
                record = session.get(LoginSession, result.session_id)
                assert record is not None

                record.refresh_token_hash = None
                record.revoked_at = now - timedelta(days=revoked_days)
                record.revocation_reason = "logout"

            for result, expired_days in (
                (recent_expired, 2),
                (old_expired, 31),
            ):
                record = session.get(LoginSession, result.session_id)
                assert record is not None

                record.created_at = now - timedelta(days=expired_days + 7)
                record.expires_at = now - timedelta(days=expired_days)

            session.commit()

        with Session(test_engine) as session:
            page = list_user_session_history(
                session,
                access_token=current.access_token,
                retention_days=30,
            )

            # Two active + one recently revoked + one recently expired.
            assert page.total == 4
            assert len(page.items) == 4

            assert [item.status for item in page.items] == [
                "active",
                "active",
                "revoked",
                "expired",
            ]

            active_ids = sorted(
                [current.session_id, other_active.session_id],
                reverse=True,
            )

            assert [item.session_id for item in page.items[:2]] == active_ids

            assert {item.session_id for item in page.items} == {
                current.session_id,
                other_active.session_id,
                recent_revoked.session_id,
                recent_expired.session_id,
            }

            assert all(item.session_id != foreign.session_id for item in page.items)

            assert sum(item.is_current for item in page.items) == 1
            assert (
                next(item for item in page.items if item.is_current).session_id
                == current.session_id
            )

            revoked_page = list_user_session_history(
                session,
                access_token=current.access_token,
                status="revoked",
                retention_days=30,
            )

            assert revoked_page.total == 1
            assert revoked_page.items[0].session_id == (recent_revoked.session_id)
            assert revoked_page.items[0].revoked_at is not None

            expired_page = list_user_session_history(
                session,
                access_token=current.access_token,
                status="expired",
                retention_days=30,
            )

            assert expired_page.total == 1
            assert expired_page.items[0].session_id == (recent_expired.session_id)

            first_page = list_user_session_history(
                session,
                access_token=current.access_token,
                limit=2,
                offset=0,
                retention_days=30,
            )

            second_page = list_user_session_history(
                session,
                access_token=current.access_token,
                limit=2,
                offset=2,
                retention_days=30,
            )

            assert first_page.total == 4
            assert second_page.total == 4

            assert [
                item.session_id for item in (first_page.items + second_page.items)
            ] == [item.session_id for item in page.items]

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(
                User.normalized_email.in_([email, other_email])
            )

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )

            connection.execute(
                delete(User).where(User.normalized_email.in_([email, other_email]))
            )


def test_revoke_all_sessions_does_not_affect_other_users(
    test_engine: Engine,
) -> None:
    """Bulk revocation affects only the authenticated user's sessions."""
    email_a = f"bulk-owner-a-{uuid7().hex}@example.com"
    email_b = f"bulk-owner-b-{uuid7().hex}@example.com"
    password = "A secure bulk isolation passphrase #8472"

    try:
        with Session(test_engine) as session:
            for email in (email_a, email_b):
                session.add(
                    User(
                        email=email,
                        normalized_email=email,
                        display_name="Bulk Isolation User",
                        status="active",
                        system_role="user",
                        password_hash=hash_password(password),
                    )
                )
            session.commit()

        def create_login(email: str):
            with Session(test_engine) as session:
                return login_user(
                    session,
                    email=email,
                    password=password,
                    access_token_expiry_minutes=15,
                    refresh_session_expiry_days=7,
                    max_active_sessions=2,
                )

        current_a = create_login(email_a)
        other_a = create_login(email_a)
        current_b = create_login(email_b)

        with Session(test_engine) as session:
            revoke_all_user_sessions(
                session,
                access_token=current_a.access_token,
            )

        with Session(test_engine) as session:
            stored_current_a = session.get(LoginSession, current_a.session_id)
            stored_other_a = session.get(LoginSession, other_a.session_id)
            stored_b = session.get(LoginSession, current_b.session_id)

            # Both User A sessions must be revoked.
            assert stored_current_a is not None
            assert stored_current_a.revoked_at is not None

            assert stored_other_a is not None
            assert stored_other_a.revoked_at is not None

            # User B must remain unaffected.
            assert stored_b is not None
            assert stored_b.revoked_at is None
            assert stored_b.refresh_token_hash == hash_token(current_b.refresh_token)

        # User B must still be able to authenticate and refresh.
        with Session(test_engine) as session:
            authenticated = authenticate_access_token(
                session,
                access_token=current_b.access_token,
            )
            assert authenticated.email == email_b

        with Session(test_engine) as session:
            refreshed = refresh_session(
                session,
                refresh_token=current_b.refresh_token,
                access_token_expiry_minutes=15,
            )

        assert refreshed.session_id == current_b.session_id

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(
                User.normalized_email.in_([email_a, email_b])
            )

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )
            connection.execute(
                delete(User).where(User.normalized_email.in_([email_a, email_b]))
            )


def test_revoke_all_sessions_rolls_back_on_failure(
    test_engine: Engine,
) -> None:
    """Failure during bulk revocation rolls back all session updates."""
    email = f"bulk-rollback-{uuid7().hex}@example.com"
    password = "A secure bulk rollback passphrase #8472"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Bulk Rollback User",
                status="active",
                system_role="user",
                password_hash=hash_password(password),
            )
            session.add(user)
            session.commit()

        def create_login():
            with Session(test_engine) as session:
                return login_user(
                    session,
                    email=email,
                    password=password,
                    access_token_expiry_minutes=15,
                    refresh_session_expiry_days=7,
                    max_active_sessions=3,
                )

        current = create_login()
        second = create_login()
        third = create_login()

        updates_seen = 0

        def reject_second_update(
            _mapper: Mapper[LoginSession],
            _connection: Connection,
            _target: LoginSession,
        ) -> None:
            nonlocal updates_seen
            updates_seen += 1

            if updates_seen == 2:
                raise RuntimeError("Simulated bulk revocation failure")

        event.listen(LoginSession, "before_update", reject_second_update)

        try:
            with Session(test_engine) as session:
                with pytest.raises(
                    RuntimeError,
                    match="Simulated bulk revocation failure",
                ):
                    revoke_other_sessions(
                        session,
                        access_token=current.access_token,
                    )
        finally:
            event.remove(
                LoginSession,
                "before_update",
                reject_second_update,
            )

        assert updates_seen == 2

        # Neither session should have been revoked.
        with Session(test_engine) as session:
            for login in (current, second, third):
                stored = session.get(LoginSession, login.session_id)

                assert stored is not None
                assert stored.revoked_at is None
                assert stored.revocation_reason is None
                assert stored.refresh_token_hash == hash_token(login.refresh_token)

        # Retrying the operation should revoke both other sessions.
        with Session(test_engine) as session:
            revoked_count = revoke_other_sessions(
                session,
                access_token=current.access_token,
            )

        assert revoked_count == 2

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(User.normalized_email == email)

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )
            connection.execute(delete(User).where(User.normalized_email == email))
