"""PostgreSQL integration tests for user login."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier
from uuid import UUID

import pytest
from sqlalchemy import Connection, Engine, delete, event, select
from sqlalchemy.orm import Mapper, Session
from uuid6 import uuid7

from restling_server.users.models import AccessToken, LoginSession, User
from restling_server.users.passwords import hash_password
from restling_server.users.service import (
    InvalidCredentialsError,
    SessionLimitReachedError,
    login_user,
)
from restling_server.users.tokens import hash_token


def test_login_rejects_unknown_user(
    db_session: Session,
) -> None:
    """Unknown credentials must not establish a session."""
    with pytest.raises(InvalidCredentialsError):
        login_user(
            db_session,
            email="unknown-login@example.com",
            password="A secure test passphrase #8472",
            access_token_expiry_minutes=15,
            refresh_session_expiry_days=7,
            max_active_sessions=2,
        )


def test_login_rejects_incorrect_password(
    test_engine: Engine,
) -> None:
    """An existing account must reject incorrect credentials."""
    email = f"login-user-{uuid7().hex}@example.com"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Login Test User",
                status="active",
                system_role="user",
                password_hash=hash_password("My correct secure passphrase #8472"),
            )

            session.add(user)
            session.commit()

        with Session(test_engine) as session:
            with pytest.raises(InvalidCredentialsError):
                login_user(
                    session,
                    email=email,
                    password="An incorrect passphrase #9382",
                    access_token_expiry_minutes=15,
                    refresh_session_expiry_days=7,
                    max_active_sessions=2,
                )

    finally:
        with test_engine.begin() as connection:
            connection.execute(delete(User).where(User.normalized_email == email))


@pytest.mark.parametrize(
    ("status", "password_reset_required"),
    [
        ("suspended", False),
        ("active", True),
    ],
)
def test_login_rejects_ineligible_account(
    test_engine: Engine,
    status: str,
    password_reset_required: bool,
) -> None:
    """Ineligible accounts cannot log in with valid credentials."""
    email = f"ineligible-login-{uuid7().hex}@example.com"
    password = "My secure login passphrase #8472"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Ineligible Login User",
                status=status,
                system_role="user",
                password_hash=hash_password(password),
                password_reset_required=password_reset_required,
            )

            session.add(user)
            session.commit()

        with Session(test_engine) as session:
            with pytest.raises(InvalidCredentialsError):
                login_user(
                    session,
                    email=email,
                    password=password,
                    access_token_expiry_minutes=15,
                    refresh_session_expiry_days=7,
                    max_active_sessions=2,
                )

    finally:
        with test_engine.begin() as connection:
            connection.execute(delete(User).where(User.normalized_email == email))


def test_login_rejects_pending_account(
    test_engine: Engine,
) -> None:
    """Pending accounts cannot log in before activation."""
    email = f"pending-login-{uuid7().hex}@example.com"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Pending Login User",
                status="pending",
                system_role="user",
                password_hash=None,
            )

            session.add(user)
            session.commit()

        with Session(test_engine) as session:
            with pytest.raises(InvalidCredentialsError):
                login_user(
                    session,
                    email=email,
                    password="A secure test passphrase #8472",
                    access_token_expiry_minutes=15,
                    refresh_session_expiry_days=7,
                    max_active_sessions=2,
                )

    finally:
        with test_engine.begin() as connection:
            connection.execute(delete(User).where(User.normalized_email == email))


def test_valid_credentials_create_session_and_tokens(
    test_engine: Engine,
) -> None:
    """Successful login persists hashes and returns raw credentials."""
    email = f"successful-login-{uuid7().hex}@example.com"
    password = "A secure login passphrase #8472"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Successful Login User",
                status="active",
                system_role="user",
                password_hash=hash_password(password),
            )
            session.add(user)
            session.commit()
            user_id = user.id

        with Session(test_engine) as session:
            result = login_user(
                session,
                email=email,
                password=password,
                access_token_expiry_minutes=15,
                refresh_session_expiry_days=7,
                max_active_sessions=2,
            )

        assert result.access_token != result.refresh_token

        with Session(test_engine) as session:
            login_session = session.get(LoginSession, result.session_id)

            assert login_session is not None
            assert login_session.user_id == user_id
            assert login_session.revoked_at is None
            assert login_session.refresh_token_hash == hash_token(result.refresh_token)
            assert login_session.expires_at == result.session_expires_at

            access_token = session.scalar(
                select(AccessToken).where(AccessToken.session_id == result.session_id)
            )

            assert access_token is not None
            assert access_token.token_hash == hash_token(result.access_token)
            assert access_token.expires_at == (result.access_token_expires_at)

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(User.normalized_email == email)
            session_ids = select(LoginSession.id).where(
                LoginSession.user_id.in_(user_ids)
            )

            connection.execute(
                delete(AccessToken).where(AccessToken.session_id.in_(session_ids))
            )
            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )
            connection.execute(delete(User).where(User.normalized_email == email))


def test_login_rejects_when_session_limit_reached(
    test_engine: Engine,
) -> None:
    """A third login cannot replace two existing active sessions."""
    email = f"session-limit-{uuid7().hex}@example.com"
    password = "My secure session passphrase #8472"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Session Limit User",
                status="active",
                system_role="user",
                password_hash=hash_password(password),
            )
            session.add(user)
            session.commit()
            user_id = user.id

        session_ids: list[UUID] = []

        for _ in range(2):
            with Session(test_engine) as session:
                result = login_user(
                    session,
                    email=email,
                    password=password,
                    access_token_expiry_minutes=15,
                    refresh_session_expiry_days=7,
                    max_active_sessions=2,
                )
                session_ids.append(result.session_id)

        assert session_ids[0] != session_ids[1]

        with Session(test_engine) as session:
            with pytest.raises(SessionLimitReachedError):
                login_user(
                    session,
                    email=email,
                    password=password,
                    access_token_expiry_minutes=15,
                    refresh_session_expiry_days=7,
                    max_active_sessions=2,
                )

        with Session(test_engine) as session:
            stored_sessions = session.scalars(
                select(LoginSession).where(LoginSession.user_id == user_id)
            ).all()

            assert len(stored_sessions) == 2
            assert {item.id for item in stored_sessions} == set(session_ids)
            assert all(item.revoked_at is None for item in stored_sessions)

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(User.normalized_email == email)

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )
            connection.execute(delete(User).where(User.normalized_email == email))


@pytest.mark.parametrize("session_state", ["expired", "revoked"])
def test_login_ignores_inactive_sessions(
    test_engine: Engine,
    session_state: str,
) -> None:
    """Expired and revoked sessions do not count toward the limit."""
    email = f"inactive-session-{uuid7().hex}@example.com"
    password = "A secure session passphrase #8472"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Inactive Session User",
                status="active",
                system_role="user",
                password_hash=hash_password(password),
            )
            session.add(user)
            session.commit()
            user_id = user.id

        with Session(test_engine) as session:
            first = login_user(
                session,
                email=email,
                password=password,
                access_token_expiry_minutes=15,
                refresh_session_expiry_days=7,
                max_active_sessions=1,
            )

        with Session(test_engine) as session:
            stored = session.get(LoginSession, first.session_id)
            assert stored is not None

            now = datetime.now(UTC)

            if session_state == "expired":
                # Simulate a session created in the past
                # whose valid expiration has already passed.
                stored.created_at = now - timedelta(days=8)
                stored.expires_at = now - timedelta(days=1)
            else:
                stored.refresh_token_hash = None
                stored.revoked_at = now
                stored.revocation_reason = "logout"

            session.commit()

        with Session(test_engine) as session:
            second = login_user(
                session,
                email=email,
                password=password,
                access_token_expiry_minutes=15,
                refresh_session_expiry_days=7,
                max_active_sessions=1,
            )

        assert second.session_id != first.session_id

        with Session(test_engine) as session:
            sessions = session.scalars(
                select(LoginSession).where(LoginSession.user_id == user_id)
            ).all()

            assert len(sessions) == 2

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(User.normalized_email == email)

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )
            connection.execute(delete(User).where(User.normalized_email == email))


def test_concurrent_logins_respect_session_limit(
    test_engine: Engine,
) -> None:
    """Concurrent logins cannot exceed the active-session limit."""
    email = f"concurrent-login-{uuid7().hex}@example.com"
    password = "My secure concurrent passphrase #8472"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Concurrent Login User",
                status="active",
                system_role="user",
                password_hash=hash_password(password),
            )
            session.add(user)
            session.commit()
            user_id = user.id

        barrier = Barrier(3)

        def attempt_login() -> bool:
            # Each thread owns its own SQLAlchemy session.
            with Session(test_engine) as session:
                barrier.wait(timeout=10)

                try:
                    login_user(
                        session,
                        email=email,
                        password=password,
                        access_token_expiry_minutes=15,
                        refresh_session_expiry_days=7,
                        max_active_sessions=1,
                    )
                except SessionLimitReachedError:
                    return False

                return True

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(attempt_login) for _ in range(2)]

            # Release both workers at approximately the same time.
            barrier.wait(timeout=10)

            results = [future.result() for future in futures]

        assert results.count(True) == 1
        assert results.count(False) == 1

        with Session(test_engine) as session:
            stored_sessions = session.scalars(
                select(LoginSession).where(LoginSession.user_id == user_id)
            ).all()

            assert len(stored_sessions) == 1
            assert stored_sessions[0].revoked_at is None

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(User.normalized_email == email)

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )
            connection.execute(delete(User).where(User.normalized_email == email))


def test_login_rolls_back_when_access_token_insert_fails(
    test_engine: Engine,
) -> None:
    """Failed token persistence rolls back the login session."""
    email = f"rollback-login-{uuid7().hex}@example.com"
    password = "A secure rollback passphrase #8472"

    with Session(test_engine) as session:
        user = User(
            email=email,
            normalized_email=email,
            display_name="Rollback Login User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )
        session.add(user)
        session.commit()
        user_id = user.id

    def reject_access_token_insert(
        _mapper: Mapper[AccessToken],
        _connection: Connection,
        _target: AccessToken,
    ) -> None:
        raise RuntimeError("Simulated access-token persistence failure")

    try:
        event.listen(
            AccessToken,
            "before_insert",
            reject_access_token_insert,
        )

        try:
            with Session(test_engine) as session:
                with pytest.raises(
                    RuntimeError,
                    match="Simulated access-token persistence failure",
                ):
                    login_user(
                        session,
                        email=email,
                        password=password,
                        access_token_expiry_minutes=15,
                        refresh_session_expiry_days=7,
                        max_active_sessions=2,
                    )
        finally:
            event.remove(
                AccessToken,
                "before_insert",
                reject_access_token_insert,
            )

        with Session(test_engine) as session:
            stored_sessions = session.scalars(
                select(LoginSession).where(LoginSession.user_id == user_id)
            ).all()

            assert stored_sessions == []

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(User.normalized_email == email)

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )
            connection.execute(delete(User).where(User.normalized_email == email))


def test_login_normalizes_internationalized_email(
    test_engine: Engine,
) -> None:
    """Equivalent internationalized domains identify the same account."""
    username = f"idn-login-{uuid7().hex}"
    email = f"{username}@bücher.de"
    login_email = f"{username}@xn--bcher-kva.de"
    password = "A secure internationalized passphrase #8472"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Internationalized Login User",
                status="active",
                system_role="user",
                password_hash=hash_password(password),
            )
            session.add(user)
            session.commit()

        with Session(test_engine) as session:
            result = login_user(
                session,
                email=login_email,
                password=password,
                access_token_expiry_minutes=15,
                refresh_session_expiry_days=7,
                max_active_sessions=2,
            )

        assert result.session_id is not None

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(User.normalized_email == email)

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )
            connection.execute(delete(User).where(User.normalized_email == email))


@pytest.mark.parametrize(
    "email",
    [
        "",
        "   ",
        "not-an-email",
        "user@",
        "@example.com",
    ],
)
def test_login_rejects_malformed_email(
    db_session: Session,
    email: str,
) -> None:
    """Malformed email addresses produce a generic login error."""
    with pytest.raises(
        InvalidCredentialsError,
        match="Invalid email address or password",
    ):
        login_user(
            db_session,
            email=email,
            password="A secure test passphrase #8472",
            access_token_expiry_minutes=15,
            refresh_session_expiry_days=7,
            max_active_sessions=2,
        )
