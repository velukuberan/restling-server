"""PostgreSQL integration tests for user activation."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

import pytest
from sqlalchemy import Engine, delete, select
from sqlalchemy.orm import Session
from uuid6 import uuid7

from restling_server.users.models import OneTimeToken, User
from restling_server.users.passwords import verify_password
from restling_server.users.service import (
    InvalidActivationTokenError,
    activate_user,
    issue_activation_token,
)
from restling_server.users.tokens import generate_token, hash_token


def test_valid_token_activates_pending_user(
    test_engine: Engine,
) -> None:
    """Activation updates the user and consumes the token atomically."""

    test_id = uuid7().hex
    admin_email = f"activation-admin-{test_id}@example.com"
    user_email = f"activation-user-{test_id}@example.com"
    password = "My secure activation passphrase #8472"

    try:
        with Session(test_engine) as session:
            administrator = User(
                email=admin_email,
                normalized_email=admin_email,
                display_name="Administrator",
                status="active",
                system_role="administrator",
                password_hash="test-password-hash",
            )

            pending_user = User(
                email=user_email,
                normalized_email=user_email,
                display_name="Pending User",
                status="pending",
                system_role="user",
                password_hash=None,
            )

            session.add_all([administrator, pending_user])
            session.commit()

            administrator_id = administrator.id
            user_id = pending_user.id

        with Session(test_engine) as session:
            raw_token, _ = issue_activation_token(
                session,
                actor_id=administrator_id,
                user_id=user_id,
                expiry_hours=24,
            )

        before_activation = datetime.now(UTC)

        with Session(test_engine) as session:
            activate_user(
                session,
                token=raw_token,
                password=password,
            )

        after_activation = datetime.now(UTC)

        with Session(test_engine) as session:
            user = session.get(User, user_id)

            assert user is not None
            assert user.status == "active"
            assert user.password_hash is not None
            assert verify_password(password, user.password_hash)
            assert user.password_reset_required is False
            assert user.activated_at is not None
            assert before_activation <= user.activated_at <= after_activation

            stored_token = session.scalar(
                select(OneTimeToken).where(
                    OneTimeToken.token_hash == hash_token(raw_token)
                )
            )

            assert stored_token is not None
            assert stored_token.consumed_at is not None
            assert stored_token.revoked_at is None

            # A consumed activation credential must never be reusable.
            with Session(test_engine) as session:
                with pytest.raises(InvalidActivationTokenError):
                    activate_user(
                        session,
                        token=raw_token,
                        password="Another secure passphrase #9382",
                    )

            # A failed replay must not change the activated account.
            with Session(test_engine) as session:
                user = session.get(User, user_id)

                assert user is not None
                assert user.status == "active"
                assert user.password_hash is not None
                assert verify_password(password, user.password_hash)

                stored_token = session.scalar(
                    select(OneTimeToken).where(
                        OneTimeToken.token_hash == hash_token(raw_token)
                    )
                )

                assert stored_token is not None
                assert stored_token.consumed_at is not None

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(
                User.normalized_email.in_([admin_email, user_email])
            )

            connection.execute(
                delete(OneTimeToken).where(OneTimeToken.user_id.in_(user_ids))
            )

            connection.execute(
                delete(User).where(User.normalized_email.in_([admin_email, user_email]))
            )


@pytest.mark.parametrize(
    "token",
    [
        "",
        "invalid-token",
        "A" * 43,
    ],
)
def test_invalid_activation_token_is_rejected(
    test_engine: Engine,
    token: str,
) -> None:
    """Unknown activation credentials cannot activate accounts."""
    password = "A secure activation passphrase #8472"

    with Session(test_engine) as session:
        with pytest.raises(InvalidActivationTokenError):
            activate_user(
                session,
                token=token,
                password=password,
            )


@pytest.mark.parametrize(
    "token_state",
    ["expired", "revoked", "wrong_purpose"],
)
def test_unusable_activation_token_is_rejected(
    test_engine: Engine,
    token_state: str,
) -> None:
    """Reject existing credentials that are not valid for activation."""
    test_id = uuid7().hex
    user_email = f"invalid-activation-{test_id}@example.com"

    raw_token = generate_token()
    now = datetime.now(UTC)

    created_at = now - timedelta(hours=2)
    expires_at = now + timedelta(hours=1)

    if token_state == "expired":
        expires_at = now - timedelta(hours=1)

    purpose = (
        "password_reset" if token_state == "wrong_purpose" else "account_activation"
    )

    try:
        with Session(test_engine) as session:
            user = User(
                email=user_email,
                normalized_email=user_email,
                display_name="Pending Activation User",
                status="pending",
                system_role="user",
                password_hash=None,
            )

            session.add(user)
            session.flush()

            user_id = user.id

            stored_token = OneTimeToken(
                user_id=user_id,
                purpose=purpose,
                token_hash=hash_token(raw_token),
                pending_email=None,
                created_at=created_at,
                expires_at=expires_at,
                revoked_at=now if token_state == "revoked" else None,
            )

            session.add(stored_token)
            session.commit()

        with Session(test_engine) as session:
            with pytest.raises(InvalidActivationTokenError):
                activate_user(
                    session,
                    token=raw_token,
                    password="A secure activation passphrase #8472",
                )

        # Rejection must not modify the account or consume the token.
        with Session(test_engine) as session:
            user = session.get(User, user_id)

            assert user is not None
            assert user.status == "pending"
            assert user.password_hash is None
            assert user.activated_at is None

            stored_token = session.scalar(
                select(OneTimeToken).where(
                    OneTimeToken.token_hash == hash_token(raw_token)
                )
            )

            assert stored_token is not None
            assert stored_token.consumed_at is None

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(User.normalized_email == user_email)

            connection.execute(
                delete(OneTimeToken).where(OneTimeToken.user_id.in_(user_ids))
            )

            connection.execute(delete(User).where(User.normalized_email == user_email))


def test_invalid_password_does_not_consume_activation_token(
    test_engine: Engine,
) -> None:
    """A rejected password must leave the invitation usable."""
    test_id = uuid7().hex
    admin_email = f"password-admin-{test_id}@example.com"
    user_email = f"password-user-{test_id}@example.com"

    valid_password = "A secure activation passphrase #8472"

    try:
        with Session(test_engine) as session:
            administrator = User(
                email=admin_email,
                normalized_email=admin_email,
                display_name="Administrator",
                status="active",
                system_role="administrator",
                password_hash="test-password-hash",
            )

            pending_user = User(
                email=user_email,
                normalized_email=user_email,
                display_name="Pending User",
                status="pending",
                system_role="user",
                password_hash=None,
            )

            session.add_all([administrator, pending_user])
            session.commit()

            administrator_id = administrator.id
            user_id = pending_user.id

        with Session(test_engine) as session:
            raw_token, _ = issue_activation_token(
                session,
                actor_id=administrator_id,
                user_id=user_id,
                expiry_hours=24,
            )

        # The invitation is valid, but the password is too short.
        with Session(test_engine) as session:
            with pytest.raises(ValueError, match="at least 15 characters"):
                activate_user(
                    session,
                    token=raw_token,
                    password="short",
                )

        # The account and token must remain unchanged.
        with Session(test_engine) as session:
            user = session.get(User, user_id)

            assert user is not None
            assert user.status == "pending"
            assert user.password_hash is None
            assert user.activated_at is None

            stored_token = session.scalar(
                select(OneTimeToken).where(
                    OneTimeToken.token_hash == hash_token(raw_token)
                )
            )

            assert stored_token is not None
            assert stored_token.consumed_at is None
            assert stored_token.revoked_at is None

        # The same invitation must still work with a valid password.
        with Session(test_engine) as session:
            activate_user(
                session,
                token=raw_token,
                password=valid_password,
            )

        with Session(test_engine) as session:
            user = session.get(User, user_id)

            assert user is not None
            assert user.status == "active"
            assert user.password_hash is not None
            assert verify_password(valid_password, user.password_hash)

            stored_token = session.scalar(
                select(OneTimeToken).where(
                    OneTimeToken.token_hash == hash_token(raw_token)
                )
            )

            assert stored_token is not None
            assert stored_token.consumed_at is not None

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(
                User.normalized_email.in_([admin_email, user_email])
            )

            connection.execute(
                delete(OneTimeToken).where(OneTimeToken.user_id.in_(user_ids))
            )

            connection.execute(
                delete(User).where(User.normalized_email.in_([admin_email, user_email]))
            )


def test_concurrent_activation_allows_only_one_success(
    test_engine: Engine,
) -> None:
    """The same activation token cannot activate twice concurrently."""
    test_id = uuid7().hex
    admin_email = f"concurrent-activation-admin-{test_id}@example.com"
    user_email = f"concurrent-activation-user-{test_id}@example.com"
    password = "A secure concurrent activation passphrase #8472"

    try:
        with Session(test_engine) as session:
            administrator = User(
                email=admin_email,
                normalized_email=admin_email,
                display_name="Administrator",
                status="active",
                system_role="administrator",
                password_hash="test-password-hash",
            )

            pending_user = User(
                email=user_email,
                normalized_email=user_email,
                display_name="Pending User",
                status="pending",
                system_role="user",
                password_hash=None,
            )

            session.add_all([administrator, pending_user])
            session.commit()

            administrator_id = administrator.id
            user_id = pending_user.id

        with Session(test_engine) as session:
            raw_token, _ = issue_activation_token(
                session,
                actor_id=administrator_id,
                user_id=user_id,
                expiry_hours=24,
            )

        barrier = Barrier(2, timeout=10)

        def attempt_activation() -> str:
            with Session(test_engine) as session:
                barrier.wait()

                try:
                    activate_user(
                        session,
                        token=raw_token,
                        password=password,
                    )
                except InvalidActivationTokenError:
                    return "rejected"

                return "activated"

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(attempt_activation) for _ in range(2)]

            results = [future.result(timeout=20) for future in futures]

        assert sorted(results) == ["activated", "rejected"]

        # Inspect the final committed state using a fresh session.
        with Session(test_engine) as session:
            user = session.get(User, user_id)

            assert user is not None
            assert user.status == "active"
            assert user.activated_at is not None
            assert user.password_hash is not None
            assert verify_password(password, user.password_hash)

            stored_tokens = session.scalars(
                select(OneTimeToken).where(
                    OneTimeToken.user_id == user_id,
                    OneTimeToken.purpose == "account_activation",
                )
            ).all()

            assert len(stored_tokens) == 1

            stored_token = stored_tokens[0]

            assert stored_token.token_hash == hash_token(raw_token)
            assert stored_token.consumed_at is not None
            assert stored_token.revoked_at is None

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(
                User.normalized_email.in_([admin_email, user_email])
            )

            connection.execute(
                delete(OneTimeToken).where(OneTimeToken.user_id.in_(user_ids))
            )

            connection.execute(
                delete(User).where(User.normalized_email.in_([admin_email, user_email]))
            )


def test_invalid_token_takes_precedence_over_invalid_password(
    test_engine: Engine,
) -> None:
    """Invalid credentials are rejected before password-policy errors."""
    with Session(test_engine) as session:
        with pytest.raises(InvalidActivationTokenError):
            activate_user(
                session,
                token="invalid-activation-token",
                password="short",
            )
