"""PostgreSQL integration tests for session logout."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from sqlalchemy import Connection, Engine, delete, event, select
from sqlalchemy.orm import Mapper, Session
from uuid6 import uuid7

from restling_server.users.models import LoginSession, User
from restling_server.users.passwords import hash_password
from restling_server.users.service import (
    InvalidCredentialsError,
    authenticate_access_token,
    login_user,
    logout_session,
    refresh_session,
)
from restling_server.users.tokens import hash_token


def test_logout_revokes_current_session(
    test_engine: Engine,
) -> None:
    """Logging out revokes the session and its refresh credential."""
    email = f"logout-{uuid7().hex}@example.com"
    password = "A secure logout test passphrase #8472"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Logout Test User",
                status="active",
                system_role="user",
                password_hash=hash_password(password),
            )

            session.add(user)
            session.commit()

        with Session(test_engine) as session:
            login_result = login_user(
                session,
                email=email,
                password=password,
                access_token_expiry_minutes=15,
                refresh_session_expiry_days=7,
                max_active_sessions=2,
            )

        with Session(test_engine) as session:
            logout_session(
                session,
                access_token=login_result.access_token,
            )

        with Session(test_engine) as session:
            stored = session.get(
                LoginSession,
                login_result.session_id,
            )

            assert stored is not None
            assert stored.revoked_at is not None
            assert stored.revocation_reason == "logout"
            assert stored.refresh_token_hash is None

        # Logout must invalidate the original access token.
        with Session(test_engine) as session:
            with pytest.raises(
                InvalidCredentialsError,
                match="Invalid access credential",
            ):
                authenticate_access_token(
                    session,
                    access_token=login_result.access_token,
                )

        # Logout must also invalidate the refresh token.
        with Session(test_engine) as session:
            with pytest.raises(
                InvalidCredentialsError,
                match="Invalid refresh credential",
            ):
                refresh_session(
                    session,
                    refresh_token=login_result.refresh_token,
                    access_token_expiry_minutes=15,
                )

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
def test_logout_rejects_invalid_credentials(
    db_session: Session,
    access_token: str,
) -> None:
    """Unknown access credentials cannot authorize logout."""
    with pytest.raises(
        InvalidCredentialsError,
        match="Invalid access credential",
    ):
        logout_session(
            db_session,
            access_token=access_token,
        )


def test_repeated_logout_preserves_revocation(
    test_engine: Engine,
) -> None:
    """Repeated logout cannot alter an already revoked session."""
    email = f"repeated-logout-{uuid7().hex}@example.com"
    password = "A secure repeated logout passphrase #8472"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Repeated Logout User",
                status="active",
                system_role="user",
                password_hash=hash_password(password),
            )
            session.add(user)
            session.commit()

        with Session(test_engine) as session:
            login_result = login_user(
                session,
                email=email,
                password=password,
                access_token_expiry_minutes=15,
                refresh_session_expiry_days=7,
                max_active_sessions=2,
            )

        with Session(test_engine) as session:
            logout_session(
                session,
                access_token=login_result.access_token,
            )

        with Session(test_engine) as session:
            stored = session.get(LoginSession, login_result.session_id)
            assert stored is not None

            original_revoked_at = stored.revoked_at
            assert original_revoked_at is not None

        with Session(test_engine) as session:
            with pytest.raises(
                InvalidCredentialsError,
                match="Invalid access credential",
            ):
                logout_session(
                    session,
                    access_token=login_result.access_token,
                )

        with Session(test_engine) as session:
            stored = session.get(LoginSession, login_result.session_id)
            assert stored is not None

            assert stored.revoked_at == original_revoked_at
            assert stored.revocation_reason == "logout"
            assert stored.refresh_token_hash is None

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(User.normalized_email == email)

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )
            connection.execute(delete(User).where(User.normalized_email == email))


def test_concurrent_logout_and_refresh_revokes_session(
    test_engine: Engine,
) -> None:
    """A concurrent refresh cannot keep a logged-out session active."""
    email = f"concurrent-logout-{uuid7().hex}@example.com"
    password = "A secure concurrent logout passphrase #8472"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Concurrent Logout User",
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

        def attempt_logout() -> None:
            with Session(test_engine) as session:
                barrier.wait(timeout=10)
                logout_session(
                    session,
                    access_token=original.access_token,
                )

        def attempt_refresh() -> str | None:
            with Session(test_engine) as session:
                barrier.wait(timeout=10)

                try:
                    refreshed = refresh_session(
                        session,
                        refresh_token=original.refresh_token,
                        access_token_expiry_minutes=15,
                    )
                except InvalidCredentialsError:
                    return None

                return refreshed.access_token

        with ThreadPoolExecutor(max_workers=2) as executor:
            logout_future = executor.submit(attempt_logout)
            refresh_future = executor.submit(attempt_refresh)

            barrier.wait(timeout=10)

            logout_future.result(timeout=15)
            refreshed_access_token = refresh_future.result(timeout=15)

        with Session(test_engine) as session:
            stored = session.get(LoginSession, original.session_id)

            assert stored is not None
            assert stored.revoked_at is not None
            assert stored.revocation_reason == "logout"
            assert stored.refresh_token_hash is None

        # The original access token must be invalid after logout.
        with Session(test_engine) as session:
            with pytest.raises(InvalidCredentialsError):
                authenticate_access_token(
                    session,
                    access_token=original.access_token,
                )

        # If refresh succeeded before logout, its access token
        # must also have become invalid.
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


def test_logout_rolls_back_when_session_update_fails(
    test_engine: Engine,
) -> None:
    """Failed revocation persistence leaves the session usable."""
    email = f"logout-rollback-{uuid7().hex}@example.com"
    password = "A secure logout rollback passphrase #8472"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Logout Rollback User",
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

        def reject_session_update(
            _mapper: Mapper[LoginSession],
            _connection: Connection,
            _target: LoginSession,
        ) -> None:
            raise RuntimeError("Simulated logout persistence failure")

        event.listen(
            LoginSession,
            "before_update",
            reject_session_update,
        )

        try:
            with Session(test_engine) as session:
                with pytest.raises(
                    RuntimeError,
                    match="Simulated logout persistence failure",
                ):
                    logout_session(
                        session,
                        access_token=original.access_token,
                    )
        finally:
            event.remove(
                LoginSession,
                "before_update",
                reject_session_update,
            )

        # Verify that the failed transaction did not persist revocation.
        with Session(test_engine) as session:
            stored = session.get(LoginSession, original.session_id)

            assert stored is not None
            assert stored.revoked_at is None
            assert stored.revocation_reason is None
            assert stored.refresh_token_hash == hash_token(original.refresh_token)

        # The original access token must still authenticate.
        with Session(test_engine) as session:
            authenticated_user = authenticate_access_token(
                session,
                access_token=original.access_token,
            )

            assert authenticated_user.email == email

        # A subsequent logout must succeed.
        with Session(test_engine) as session:
            logout_session(
                session,
                access_token=original.access_token,
            )

        with Session(test_engine) as session:
            stored = session.get(LoginSession, original.session_id)

            assert stored is not None
            assert stored.revoked_at is not None
            assert stored.revocation_reason == "logout"
            assert stored.refresh_token_hash is None

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(User.normalized_email == email)

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )
            connection.execute(delete(User).where(User.normalized_email == email))


def test_logout_does_not_revoke_other_sessions(
    test_engine: Engine,
) -> None:
    """Logging out of one session leaves another session active."""
    email = f"isolated-logout-{uuid7().hex}@example.com"
    password = "A secure session isolation passphrase #8472"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Session Isolation User",
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

        assert first.session_id != second.session_id

        with Session(test_engine) as session:
            logout_session(
                session,
                access_token=first.access_token,
            )

        # Session A is revoked, but Session B remains usable.
        with Session(test_engine) as session:
            with pytest.raises(InvalidCredentialsError):
                authenticate_access_token(
                    session,
                    access_token=first.access_token,
                )

        with Session(test_engine) as session:
            authenticated_user = authenticate_access_token(
                session,
                access_token=second.access_token,
            )
            assert authenticated_user.email == email

        with Session(test_engine) as session:
            refreshed = refresh_session(
                session,
                refresh_token=second.refresh_token,
                access_token_expiry_minutes=15,
            )

        assert refreshed.session_id == second.session_id

        with Session(test_engine) as session:
            first_stored = session.get(LoginSession, first.session_id)
            second_stored = session.get(LoginSession, second.session_id)

            assert first_stored is not None
            assert first_stored.revoked_at is not None

            assert second_stored is not None
            assert second_stored.revoked_at is None

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(User.normalized_email == email)

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )
            connection.execute(delete(User).where(User.normalized_email == email))
