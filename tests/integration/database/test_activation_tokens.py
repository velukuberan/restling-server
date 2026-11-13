"""PostgreSQL integration tests for activation token issuance."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

import pytest
from sqlalchemy import Engine, delete, select
from sqlalchemy.orm import Session
from uuid6 import uuid7

from restling_server.users.models import OneTimeToken, User
from restling_server.users.service import (
    InvitationNotAllowedError,
    issue_activation_token,
)
from restling_server.users.tokens import hash_token


def test_activation_token_issuance_and_replacement(
    test_engine: Engine,
) -> None:
    """Issuance stores a hash and replacement revokes the old token."""
    test_id = uuid7().hex

    admin_email = f"token-admin-{test_id}@example.com"
    user_email = f"token-user-{test_id}@example.com"

    try:
        # Create an administrator and a pending user.
        with Session(test_engine) as session:
            administrator = User(
                email=admin_email,
                normalized_email=admin_email,
                display_name="Token Administrator",
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

        before_issuance = datetime.now(UTC)

        # First invitation.
        with Session(test_engine) as session:
            first_token, first_expiry = issue_activation_token(
                session,
                actor_id=administrator_id,
                user_id=user_id,
                expiry_hours=24,
            )

        after_issuance = datetime.now(UTC)

        assert before_issuance + timedelta(hours=24) <= first_expiry
        assert first_expiry <= after_issuance + timedelta(hours=24)

        with Session(test_engine) as session:
            tokens = session.scalars(
                select(OneTimeToken).where(OneTimeToken.user_id == user_id)
            ).all()

            assert len(tokens) == 1

            stored_token = tokens[0]

            assert stored_token.id.version == 7
            assert stored_token.purpose == "account_activation"
            assert stored_token.token_hash == hash_token(first_token)
            assert stored_token.token_hash != first_token
            assert stored_token.pending_email is None
            assert stored_token.consumed_at is None
            assert stored_token.revoked_at is None

        # Reissue invitation.
        with Session(test_engine) as session:
            second_token, second_expiry = issue_activation_token(
                session,
                actor_id=administrator_id,
                user_id=user_id,
                expiry_hours=24,
            )

        assert second_token != first_token
        assert second_expiry >= first_expiry

        with Session(test_engine) as session:
            tokens = session.scalars(
                select(OneTimeToken)
                .where(OneTimeToken.user_id == user_id)
                .order_by(OneTimeToken.created_at)
            ).all()

            assert len(tokens) == 2

            first_stored = next(
                token for token in tokens if token.token_hash == hash_token(first_token)
            )

            second_stored = next(
                token
                for token in tokens
                if token.token_hash == hash_token(second_token)
            )

            assert first_stored.revoked_at is not None
            assert second_stored.revoked_at is None
            assert second_stored.consumed_at is None

    finally:
        # Remove child records before their parent users.
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
    (
        "actor_role",
        "actor_status",
        "target_status",
        "password_reset_required",
    ),
    [
        ("user", "active", "pending", False),
        ("administrator", "suspended", "pending", False),
        ("administrator", "active", "active", False),
        ("administrator", "active", "suspended", False),
        ("administrator", "active", "pending", True),
    ],
)
def test_activation_token_requires_authorized_pending_account(
    test_engine: Engine,
    actor_role: str,
    actor_status: str,
    target_status: str,
    password_reset_required: bool,
) -> None:
    """Reject unauthorized actors and ineligible target accounts."""
    test_id = uuid7().hex
    actor_email = f"actor-{test_id}@example.com"
    target_email = f"target-{test_id}@example.com"

    try:
        with Session(test_engine) as session:
            actor = User(
                email=actor_email,
                normalized_email=actor_email,
                display_name="Test Actor",
                system_role=actor_role,
                status=actor_status,
                password_hash="test-password-hash",
                password_reset_required=password_reset_required,
            )

            target = User(
                email=target_email,
                normalized_email=target_email,
                display_name="Test Target",
                system_role="user",
                status=target_status,
                password_hash=(
                    None if target_status == "pending" else "test-password-hash"
                ),
            )

            session.add_all([actor, target])
            session.commit()

            actor_id = actor.id
            target_id = target.id

        with Session(test_engine) as session:
            with pytest.raises(InvitationNotAllowedError):
                issue_activation_token(
                    session,
                    actor_id=actor_id,
                    user_id=target_id,
                    expiry_hours=24,
                )

        with Session(test_engine) as session:
            tokens = session.scalars(
                select(OneTimeToken).where(OneTimeToken.user_id == target_id)
            ).all()

            assert tokens == []

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(
                User.normalized_email.in_([actor_email, target_email])
            )

            connection.execute(
                delete(OneTimeToken).where(OneTimeToken.user_id.in_(user_ids))
            )

            connection.execute(
                delete(User).where(
                    User.normalized_email.in_([actor_email, target_email])
                )
            )


@pytest.mark.parametrize("expiry_hours", [0, -1, -24])
def test_activation_token_rejects_invalid_expiry(
    test_engine: Engine,
    expiry_hours: int,
) -> None:
    """Reject invalid expiration without writing to PostgreSQL."""
    with Session(test_engine) as session:
        with pytest.raises(
            ValueError,
            match="Invitation expiry must be at least one hour",
        ):
            issue_activation_token(
                session,
                actor_id=uuid7(),
                user_id=uuid7(),
                expiry_hours=expiry_hours,
            )


def test_concurrent_activation_token_issuance(
    test_engine: Engine,
) -> None:
    """Concurrent issuance leaves exactly one usable activation token."""
    test_id = uuid7().hex
    admin_email = f"concurrent-token-admin-{test_id}@example.com"
    user_email = f"concurrent-token-user-{test_id}@example.com"

    try:
        with Session(test_engine) as session:
            administrator = User(
                email=admin_email,
                normalized_email=admin_email,
                display_name="Concurrent Test Administrator",
                status="active",
                system_role="administrator",
                password_hash="test-password-hash",
            )

            pending_user = User(
                email=user_email,
                normalized_email=user_email,
                display_name="Concurrent Test User",
                status="pending",
                system_role="user",
                password_hash=None,
            )

            session.add_all([administrator, pending_user])
            session.commit()

            administrator_id = administrator.id
            user_id = pending_user.id

        barrier = Barrier(2, timeout=10)

        def issue_invitation() -> str:
            # Both workers reach the operation at approximately
            # the same time, using independent database sessions.
            with Session(test_engine) as session:
                barrier.wait()

                raw_token, _ = issue_activation_token(
                    session,
                    actor_id=administrator_id,
                    user_id=user_id,
                    expiry_hours=24,
                )

                return raw_token

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(issue_invitation) for _ in range(2)]

            raw_tokens = [future.result(timeout=15) for future in futures]

        assert raw_tokens[0] != raw_tokens[1]

        with Session(test_engine) as session:
            stored_tokens = session.scalars(
                select(OneTimeToken).where(
                    OneTimeToken.user_id == user_id,
                    OneTimeToken.purpose == "account_activation",
                )
            ).all()

            assert len(stored_tokens) == 2

            stored_hashes = {token.token_hash for token in stored_tokens}

            assert stored_hashes == {hash_token(raw_token) for raw_token in raw_tokens}

            usable_tokens = [
                token
                for token in stored_tokens
                if token.consumed_at is None
                and token.revoked_at is None
                and token.expires_at > datetime.now(UTC)
            ]

            assert len(usable_tokens) == 1

            revoked_tokens = [
                token for token in stored_tokens if token.revoked_at is not None
            ]

            assert len(revoked_tokens) == 1

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
