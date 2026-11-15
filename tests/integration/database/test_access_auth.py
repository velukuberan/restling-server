"""PostgreSQL integration tests for access-token authentication."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import Engine, delete, select
from sqlalchemy.orm import Session
from uuid6 import uuid7

from restling_server.users.models import AccessToken, LoginSession, User
from restling_server.users.passwords import hash_password
from restling_server.users.service import (
    InvalidCredentialsError,
    authenticate_access_token,
    login_user,
    refresh_session,
)
from restling_server.users.tokens import hash_token


def test_valid_access_token_authenticates_user(
    test_engine: Engine,
) -> None:
    """A valid access token resolves its associated user."""
    email = f"access-auth-{uuid7().hex}@example.com"
    password = "A secure access authentication passphrase #8472"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Access Authentication User",
                status="active",
                system_role="user",
                password_hash=hash_password(password),
            )

            session.add(user)
            session.commit()
            user_id = user.id

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
            authenticated_user = authenticate_access_token(
                session,
                access_token=login_result.access_token,
            )

            assert authenticated_user.id == user_id
            assert authenticated_user.email == email
            assert authenticated_user.status == "active"

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
def test_invalid_access_token_is_rejected(
    db_session: Session,
    access_token: str,
) -> None:
    """Unknown access credentials must not authenticate."""
    with pytest.raises(
        InvalidCredentialsError,
        match="Invalid access credential",
    ):
        authenticate_access_token(
            db_session,
            access_token=access_token,
        )


def test_expired_access_token_is_rejected(
    test_engine: Engine,
) -> None:
    """An expired access token cannot authenticate an active session."""
    email = f"expired-access-{uuid7().hex}@example.com"
    password = "A secure expired access passphrase #8472"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Expired Access User",
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

        # Expire only the access token, not its parent session.
        with Session(test_engine) as session:
            access_token = session.scalar(
                select(AccessToken).where(
                    AccessToken.token_hash == hash_token(login_result.access_token)
                )
            )

            assert access_token is not None

            now = datetime.now(UTC)
            access_token.created_at = now - timedelta(hours=2)
            access_token.expires_at = now - timedelta(hours=1)

            session.commit()

        with Session(test_engine) as session:
            with pytest.raises(
                InvalidCredentialsError,
                match="Invalid access credential",
            ):
                authenticate_access_token(
                    session,
                    access_token=login_result.access_token,
                )

        # The parent session should still be active.
        with Session(test_engine) as session:
            stored = session.get(LoginSession, login_result.session_id)

            assert stored is not None
            assert stored.revoked_at is None
            assert stored.expires_at > datetime.now(UTC)

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(User.normalized_email == email)

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )
            connection.execute(delete(User).where(User.normalized_email == email))


@pytest.mark.parametrize("session_state", ["expired", "revoked"])
def test_access_token_rejects_inactive_session(
    test_engine: Engine,
    session_state: str,
) -> None:
    """An inactive parent session invalidates its access tokens."""
    email = f"inactive-access-{uuid7().hex}@example.com"
    password = "A secure inactive access passphrase #8472"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Inactive Access User",
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
            stored = session.get(LoginSession, login_result.session_id)
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
            with pytest.raises(
                InvalidCredentialsError,
                match="Invalid access credential",
            ):
                authenticate_access_token(
                    session,
                    access_token=login_result.access_token,
                )

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
def test_access_token_rejects_ineligible_account(
    test_engine: Engine,
    status: str,
    password_reset_required: bool,
) -> None:
    """An ineligible account cannot authenticate with an existing token."""
    email = f"ineligible-access-{uuid7().hex}@example.com"
    password = "A secure access eligibility passphrase #8472"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Access Eligibility User",
                status="active",
                system_role="user",
                password_hash=hash_password(password),
            )
            session.add(user)
            session.commit()
            user_id = user.id

        with Session(test_engine) as session:
            login_result = login_user(
                session,
                email=email,
                password=password,
                access_token_expiry_minutes=15,
                refresh_session_expiry_days=7,
                max_active_sessions=2,
            )

        # Change account eligibility after issuing the access token.
        with Session(test_engine) as session:
            user = session.get(User, user_id)
            assert user is not None

            user.status = status
            user.password_reset_required = password_reset_required
            session.commit()

        with Session(test_engine) as session:
            with pytest.raises(
                InvalidCredentialsError,
                match="Invalid access credential",
            ):
                authenticate_access_token(
                    session,
                    access_token=login_result.access_token,
                )

        # The account change must not require changing the token itself.
        with Session(test_engine) as session:
            stored = session.get(LoginSession, login_result.session_id)

            assert stored is not None
            assert stored.revoked_at is None
            assert stored.expires_at > datetime.now(UTC)

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(User.normalized_email == email)

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )
            connection.execute(delete(User).where(User.normalized_email == email))


def test_refresh_replay_invalidates_all_session_access_tokens(
    test_engine: Engine,
) -> None:
    """Refresh-token replay invalidates all access tokens in the session."""
    email = f"replay-access-{uuid7().hex}@example.com"
    password = "A secure replay access passphrase #8472"

    try:
        with Session(test_engine) as session:
            user = User(
                email=email,
                normalized_email=email,
                display_name="Replay Access User",
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

        # Both access tokens are valid before replay detection.
        for token in (original.access_token, rotated.access_token):
            with Session(test_engine) as session:
                authenticated_user = authenticate_access_token(
                    session,
                    access_token=token,
                )
                assert authenticated_user.email == email

        # Reusing the consumed refresh credential revokes the session.
        with Session(test_engine) as session:
            with pytest.raises(InvalidCredentialsError):
                refresh_session(
                    session,
                    refresh_token=original.refresh_token,
                    access_token_expiry_minutes=15,
                )

        # Neither access token may authenticate after session revocation.
        for token in (original.access_token, rotated.access_token):
            with Session(test_engine) as session:
                with pytest.raises(
                    InvalidCredentialsError,
                    match="Invalid access credential",
                ):
                    authenticate_access_token(
                        session,
                        access_token=token,
                    )

        with Session(test_engine) as session:
            stored = session.get(LoginSession, original.session_id)

            assert stored is not None
            assert stored.revoked_at is not None
            assert stored.revocation_reason == "refresh_token_replay"

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(User.normalized_email == email)

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )
            connection.execute(delete(User).where(User.normalized_email == email))
