"""PostgreSQL integration tests for password-reset issuance."""

from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier
from uuid import UUID

import pytest
from sqlalchemy import Engine, delete, event, select
from sqlalchemy.orm import Session
from uuid6 import uuid7

from restling_server.users.models import (
    AccessToken,
    AuditLog,
    LoginSession,
    OneTimeToken,
    User,
)
from restling_server.users.passwords import verify_password
from restling_server.users.service import (
    InvalidCredentialsError,
    InvalidPasswordResetTokenError,
    PasswordResetNotAllowedError,
    authenticate_access_token,
    issue_password_reset_token,
    refresh_session,
    reset_user_password,
)
from restling_server.users.tokens import generate_token, hash_token


@pytest.fixture
def reset_accounts(
    test_engine: Engine,
) -> Iterator[tuple[UUID, UUID]]:
    """Create isolated accounts for password-reset tests."""
    identifier = uuid7().hex
    admin_email = f"reset-admin-{identifier}@example.com"
    user_email = f"reset-user-{identifier}@example.com"

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

            user = User(
                email=user_email,
                normalized_email=user_email,
                display_name="Test User",
                status="active",
                system_role="user",
                password_hash="test-password-hash",
            )

            session.add_all([administrator, user])
            session.commit()

            yield administrator.id, user.id

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(
                User.normalized_email.in_([admin_email, user_email])
            )

            connection.execute(
                delete(OneTimeToken).where(OneTimeToken.user_id.in_(user_ids))
            )

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )

            connection.execute(
                delete(User).where(User.normalized_email.in_([admin_email, user_email]))
            )


def test_administrator_can_issue_password_reset_token(
    test_engine: Engine,
    reset_accounts: tuple[UUID, UUID],
) -> None:
    """An administrator can issue a hashed, expiring reset token."""
    administrator_id, user_id = reset_accounts

    before = datetime.now(UTC)

    with Session(test_engine) as session:
        raw_token, expires_at = issue_password_reset_token(
            session,
            actor_id=administrator_id,
            user_id=user_id,
            expiry_minutes=30,
        )

    after = datetime.now(UTC)

    assert raw_token
    assert before + timedelta(minutes=30) <= expires_at
    assert expires_at <= after + timedelta(minutes=30)

    with Session(test_engine) as session:
        stored_token = session.scalar(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "password_reset",
            )
        )

        assert stored_token is not None
        assert stored_token.token_hash == hash_token(raw_token)
        assert stored_token.token_hash != raw_token
        assert stored_token.expires_at == expires_at
        assert stored_token.consumed_at is None
        assert stored_token.revoked_at is None

        audit_events = session.scalars(
            select(AuditLog).where(AuditLog.target_user_id == user_id)
        ).all()
        assert len(audit_events) == 1
        audit_event = audit_events[0]
        assert audit_event.action == "user.password_reset_issued"
        assert audit_event.actor_user_id == administrator_id
        assert before <= audit_event.created_at <= after
        assert audit_event.event_metadata == {}
        assert raw_token not in str(audit_event.event_metadata)
        assert stored_token.token_hash not in str(audit_event.event_metadata)


def test_reissuing_reset_token_revokes_previous_token(
    test_engine: Engine,
    reset_accounts: tuple[UUID, UUID],
) -> None:
    """Reissuing a reset credential invalidates the previous one."""
    administrator_id, user_id = reset_accounts

    with Session(test_engine) as session:
        first_token, _ = issue_password_reset_token(
            session,
            actor_id=administrator_id,
            user_id=user_id,
            expiry_minutes=30,
        )

    with Session(test_engine) as session:
        second_token, _ = issue_password_reset_token(
            session,
            actor_id=administrator_id,
            user_id=user_id,
            expiry_minutes=30,
        )

    assert first_token != second_token

    with Session(test_engine) as session:
        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "password_reset",
            )
        ).all()

        assert len(tokens) == 2

        first = next(
            item for item in tokens if item.token_hash == hash_token(first_token)
        )

        second = next(
            item for item in tokens if item.token_hash == hash_token(second_token)
        )

        assert first.revoked_at is not None
        assert first.consumed_at is None

        assert second.revoked_at is None
        assert second.consumed_at is None
        assert second.expires_at > datetime.now(UTC)


def test_ordinary_user_cannot_issue_reset_token(
    test_engine: Engine,
    reset_accounts: tuple[UUID, UUID],
) -> None:
    """Ordinary users cannot issue administrative reset tokens."""
    _, user_id = reset_accounts

    with Session(test_engine) as session:
        with pytest.raises(PasswordResetNotAllowedError):
            issue_password_reset_token(
                session,
                actor_id=user_id,
                user_id=user_id,
                expiry_minutes=30,
            )

    with Session(test_engine) as session:
        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "password_reset",
            )
        ).all()

        assert tokens == []
        assert session.scalars(select(AuditLog)).all() == []


@pytest.mark.parametrize("status", ["active", "suspended"])
def test_active_and_suspended_accounts_can_receive_reset(
    test_engine: Engine,
    reset_accounts: tuple[UUID, UUID],
    status: str,
) -> None:
    """Both active and suspended accounts support recovery issuance."""
    administrator_id, user_id = reset_accounts

    with Session(test_engine) as session:
        with session.begin():
            user = session.get(User, user_id)

            assert user is not None
            user.status = status

    with Session(test_engine) as session:
        raw_token, _ = issue_password_reset_token(
            session,
            actor_id=administrator_id,
            user_id=user_id,
            expiry_minutes=30,
        )

    assert raw_token


def test_suspended_administrator_cannot_issue_reset_token(
    test_engine: Engine,
    reset_accounts: tuple[UUID, UUID],
) -> None:
    """A suspended administrator cannot issue reset credentials."""
    administrator_id, user_id = reset_accounts

    with Session(test_engine) as session:
        with session.begin():
            administrator = session.get(User, administrator_id)

            assert administrator is not None
            administrator.status = "suspended"

    with Session(test_engine) as session:
        with pytest.raises(PasswordResetNotAllowedError):
            issue_password_reset_token(
                session,
                actor_id=administrator_id,
                user_id=user_id,
                expiry_minutes=30,
            )

    with Session(test_engine) as session:
        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "password_reset",
            )
        ).all()

        assert tokens == []


def test_pending_account_cannot_receive_reset_token(
    test_engine: Engine,
    reset_accounts: tuple[UUID, UUID],
) -> None:
    """Pending accounts must use activation instead of recovery."""
    administrator_id, user_id = reset_accounts

    with Session(test_engine) as session:
        with session.begin():
            user = session.get(User, user_id)

            assert user is not None

            user.status = "pending"
            user.password_hash = None

    with Session(test_engine) as session:
        with pytest.raises(PasswordResetNotAllowedError):
            issue_password_reset_token(
                session,
                actor_id=administrator_id,
                user_id=user_id,
                expiry_minutes=30,
            )


def test_concurrent_reset_issuance_leaves_one_usable_token(
    test_engine: Engine,
    reset_accounts: tuple[UUID, UUID],
) -> None:
    """Concurrent reset issuance leaves only one usable credential."""
    administrator_id, user_id = reset_accounts
    barrier = Barrier(2, timeout=10)

    def issue_token() -> str:
        with Session(test_engine) as session:
            barrier.wait()

            raw_token, _ = issue_password_reset_token(
                session,
                actor_id=administrator_id,
                user_id=user_id,
                expiry_minutes=30,
            )

            return raw_token

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(issue_token) for _ in range(2)]

        raw_tokens = [future.result(timeout=20) for future in futures]

    assert raw_tokens[0] != raw_tokens[1]

    with Session(test_engine) as session:
        stored_tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "password_reset",
            )
        ).all()

        assert len(stored_tokens) == 2

        usable_tokens = [
            token
            for token in stored_tokens
            if token.consumed_at is None
            and token.revoked_at is None
            and token.expires_at > datetime.now(UTC)
        ]

        revoked_tokens = [
            token for token in stored_tokens if token.revoked_at is not None
        ]

        assert len(usable_tokens) == 1
        assert len(revoked_tokens) == 1

        stored_hashes = {token.token_hash for token in stored_tokens}

        assert stored_hashes == {hash_token(raw_token) for raw_token in raw_tokens}


def test_valid_password_reset_token_changes_password(
    test_engine: Engine,
    reset_accounts: tuple[UUID, UUID],
) -> None:
    """A valid reset token updates the password and is consumed."""
    administrator_id, user_id = reset_accounts
    new_password = "A secure replacement passphrase #8472"

    with Session(test_engine) as session:
        raw_token, _ = issue_password_reset_token(
            session,
            actor_id=administrator_id,
            user_id=user_id,
            expiry_minutes=30,
        )

    with Session(test_engine) as session:
        reset_user_password(
            session,
            token=raw_token,
            new_password=new_password,
        )

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.password_hash is not None
        assert verify_password(new_password, user.password_hash)
        assert user.password_reset_required is False
        assert user.status == "active"

        stored_token = session.scalar(
            select(OneTimeToken).where(OneTimeToken.token_hash == hash_token(raw_token))
        )

        assert stored_token is not None
        assert stored_token.consumed_at is not None
        assert stored_token.revoked_at is None

        events = session.scalars(
            select(AuditLog)
            .where(AuditLog.target_user_id == user_id)
            .order_by(AuditLog.created_at, AuditLog.id)
        ).all()
        assert len(events) == 2
        assert {event.action for event in events} == {
            "user.password_reset_issued",
            "user.password_reset_completed",
        }
        completion = next(
            event for event in events if event.action == "user.password_reset_completed"
        )
        assert completion.actor_user_id is None
        assert completion.target_user_id == user_id
        assert completion.event_metadata == {}
        assert raw_token not in str(completion.event_metadata)
        assert hash_token(raw_token) not in str(completion.event_metadata)
        assert new_password not in str(completion.event_metadata)

    # A consumed token must never be accepted again.
    with Session(test_engine) as session:
        with pytest.raises(InvalidPasswordResetTokenError):
            reset_user_password(
                session,
                token=raw_token,
                new_password="Another secure replacement passphrase #9382",
            )

    with Session(test_engine) as session:
        completion_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_reset_completed",
            )
        ).all()
        assert len(completion_events) == 1


def test_invalid_new_password_preserves_reset_token(
    test_engine: Engine,
    reset_accounts: tuple[UUID, UUID],
) -> None:
    """Password validation failure must not consume the reset token."""
    administrator_id, user_id = reset_accounts

    with Session(test_engine) as session:
        raw_token, _ = issue_password_reset_token(
            session,
            actor_id=administrator_id,
            user_id=user_id,
            expiry_minutes=30,
        )

    with Session(test_engine) as session:
        with pytest.raises(ValueError):
            reset_user_password(
                session,
                token=raw_token,
                new_password="short",
            )

    with Session(test_engine) as session:
        stored_token = session.scalar(
            select(OneTimeToken).where(OneTimeToken.token_hash == hash_token(raw_token))
        )

        assert stored_token is not None
        assert stored_token.consumed_at is None
        assert stored_token.revoked_at is None

    # The original token should remain usable.
    with Session(test_engine) as session:
        reset_user_password(
            session,
            token=raw_token,
            new_password="A valid replacement passphrase #8472",
        )

    with Session(test_engine) as session:
        stored_token = session.scalar(
            select(OneTimeToken).where(OneTimeToken.token_hash == hash_token(raw_token))
        )

        assert stored_token is not None
        assert stored_token.consumed_at is not None


def test_unknown_password_reset_token_is_rejected(
    test_engine: Engine,
) -> None:
    """An unknown credential must not reset any password."""
    with Session(test_engine) as session:
        with pytest.raises(InvalidPasswordResetTokenError):
            reset_user_password(
                session,
                token="invalid-password-reset-token",
                new_password="A secure replacement passphrase #8472",
            )


def test_password_reset_revokes_all_existing_sessions(
    test_engine: Engine,
    reset_accounts: tuple[UUID, UUID],
) -> None:
    """Resetting a password invalidates every existing login session."""
    administrator_id, user_id = reset_accounts

    access_tokens: list[str] = []
    refresh_tokens: list[str] = []
    session_ids: list[UUID] = []

    now = datetime.now(UTC)

    # Create two independent login sessions.
    with Session(test_engine) as session:
        with session.begin():
            for _ in range(2):
                raw_access_token = generate_token()
                raw_refresh_token = generate_token()

                login_session = LoginSession(
                    user_id=user_id,
                    refresh_token_hash=hash_token(raw_refresh_token),
                    created_at=now,
                    expires_at=now + timedelta(days=7),
                )

                session.add(login_session)
                session.flush()

                access_token = AccessToken(
                    session_id=login_session.id,
                    token_hash=hash_token(raw_access_token),
                    created_at=now,
                    expires_at=now + timedelta(minutes=15),
                )

                session.add(access_token)

                session_ids.append(login_session.id)
                access_tokens.append(raw_access_token)
                refresh_tokens.append(raw_refresh_token)

    # Both access credentials must work before the reset.
    for raw_access_token in access_tokens:
        with Session(test_engine) as session:
            user = authenticate_access_token(
                session,
                access_token=raw_access_token,
            )

            assert user.id == user_id

    # Issue a one-time password-reset credential.
    with Session(test_engine) as session:
        reset_token, _ = issue_password_reset_token(
            session,
            actor_id=administrator_id,
            user_id=user_id,
            expiry_minutes=30,
        )

    # Completing the reset must revoke both sessions.
    with Session(test_engine) as session:
        reset_user_password(
            session,
            token=reset_token,
            new_password="A new secure password after recovery #8472",
        )

    # Verify the committed session state.
    with Session(test_engine) as session:
        stored_sessions = session.scalars(
            select(LoginSession).where(LoginSession.id.in_(session_ids))
        ).all()

        assert len(stored_sessions) == 2

        for login_session in stored_sessions:
            assert login_session.revoked_at is not None
            assert login_session.revocation_reason == "password_reset"
            assert login_session.refresh_token_hash is None

    # Previously valid access credentials must now fail.
    for raw_access_token in access_tokens:
        with Session(test_engine) as session:
            with pytest.raises(InvalidCredentialsError):
                authenticate_access_token(
                    session,
                    access_token=raw_access_token,
                )

    # Previously valid refresh credentials must also fail.
    for raw_refresh_token in refresh_tokens:
        with Session(test_engine) as session:
            with pytest.raises(InvalidCredentialsError):
                refresh_session(
                    session,
                    refresh_token=raw_refresh_token,
                    access_token_expiry_minutes=15,
                )


def test_expired_password_reset_token_is_rejected(
    test_engine: Engine,
    reset_accounts: tuple[UUID, UUID],
) -> None:
    """An expired reset credential cannot change a password."""
    administrator_id, user_id = reset_accounts

    with Session(test_engine) as session:
        raw_token, _ = issue_password_reset_token(
            session,
            actor_id=administrator_id,
            user_id=user_id,
            expiry_minutes=30,
        )

    # Simulate expiration in PostgreSQL.
    with Session(test_engine) as session:
        with session.begin():
            stored_token = session.scalar(
                select(OneTimeToken).where(
                    OneTimeToken.token_hash == hash_token(raw_token)
                )
            )

            assert stored_token is not None

            now = datetime.now(UTC)
            stored_token.created_at = now - timedelta(minutes=31)
            stored_token.expires_at = now - timedelta(minutes=1)

    with Session(test_engine) as session:
        with pytest.raises(InvalidPasswordResetTokenError):
            reset_user_password(
                session,
                token=raw_token,
                new_password="A secure replacement passphrase #8472",
            )

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.password_hash == "test-password-hash"

        stored_token = session.scalar(
            select(OneTimeToken).where(OneTimeToken.token_hash == hash_token(raw_token))
        )

        assert stored_token is not None
        assert stored_token.consumed_at is None


def test_revoked_password_reset_token_is_rejected(
    test_engine: Engine,
    reset_accounts: tuple[UUID, UUID],
) -> None:
    """A revoked reset credential cannot change a password."""
    administrator_id, user_id = reset_accounts

    with Session(test_engine) as session:
        raw_token, _ = issue_password_reset_token(
            session,
            actor_id=administrator_id,
            user_id=user_id,
            expiry_minutes=30,
        )

    with Session(test_engine) as session:
        with session.begin():
            stored_token = session.scalar(
                select(OneTimeToken).where(
                    OneTimeToken.token_hash == hash_token(raw_token)
                )
            )

            assert stored_token is not None
            stored_token.revoked_at = datetime.now(UTC)

    with Session(test_engine) as session:
        with pytest.raises(InvalidPasswordResetTokenError):
            reset_user_password(
                session,
                token=raw_token,
                new_password="A secure replacement passphrase #8472",
            )

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.password_hash == "test-password-hash"

        stored_token = session.scalar(
            select(OneTimeToken).where(OneTimeToken.token_hash == hash_token(raw_token))
        )

        assert stored_token is not None
        assert stored_token.revoked_at is not None
        assert stored_token.consumed_at is None


def test_password_reset_clears_required_flag(
    test_engine: Engine,
    reset_accounts: tuple[UUID, UUID],
) -> None:
    """Successful recovery clears the forced password-reset flag."""
    administrator_id, user_id = reset_accounts
    new_password = "A secure replacement passphrase #8472"

    # Simulate an account requiring a password reset.
    with Session(test_engine) as session:
        with session.begin():
            user = session.get(User, user_id)

            assert user is not None
            user.password_reset_required = True

    # Administrator issues a password-reset credential.
    with Session(test_engine) as session:
        raw_token, _ = issue_password_reset_token(
            session,
            actor_id=administrator_id,
            user_id=user_id,
            expiry_minutes=30,
        )

    # The flag must remain set until reset completion.
    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.password_reset_required is True

    # User completes recovery.
    with Session(test_engine) as session:
        reset_user_password(
            session,
            token=raw_token,
            new_password=new_password,
        )

    # Verify the committed account state.
    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.password_reset_required is False
        assert user.status == "active"
        assert user.password_hash is not None
        assert verify_password(new_password, user.password_hash)


def test_password_reset_preserves_suspended_status(
    test_engine: Engine,
    reset_accounts: tuple[UUID, UUID],
) -> None:
    """Password recovery must not reactivate a suspended account."""
    administrator_id, user_id = reset_accounts
    new_password = "A secure suspended-account passphrase #8472"

    with Session(test_engine) as session:
        with session.begin():
            user = session.get(User, user_id)

            assert user is not None
            user.status = "suspended"
            user.password_reset_required = True

    with Session(test_engine) as session:
        raw_token, _ = issue_password_reset_token(
            session,
            actor_id=administrator_id,
            user_id=user_id,
            expiry_minutes=30,
        )

    with Session(test_engine) as session:
        reset_user_password(
            session,
            token=raw_token,
            new_password=new_password,
        )

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.status == "suspended"
        assert user.password_reset_required is False
        assert user.password_hash is not None
        assert verify_password(new_password, user.password_hash)

        stored_token = session.scalar(
            select(OneTimeToken).where(OneTimeToken.token_hash == hash_token(raw_token))
        )

        assert stored_token is not None
        assert stored_token.consumed_at is not None
        assert stored_token.revoked_at is None


def test_concurrent_password_reset_allows_only_one_success(
    test_engine: Engine,
    reset_accounts: tuple[UUID, UUID],
) -> None:
    """The same reset credential cannot be consumed concurrently."""
    administrator_id, user_id = reset_accounts

    first_password = "First secure replacement passphrase #8472"
    second_password = "Second secure replacement passphrase #9382"

    # Issue one reset credential.
    with Session(test_engine) as session:
        raw_token, _ = issue_password_reset_token(
            session,
            actor_id=administrator_id,
            user_id=user_id,
            expiry_minutes=30,
        )

    barrier = Barrier(2, timeout=10)

    def attempt_reset(new_password: str) -> str:
        with Session(test_engine) as session:
            barrier.wait()

            try:
                reset_user_password(
                    session,
                    token=raw_token,
                    new_password=new_password,
                )
            except InvalidPasswordResetTokenError:
                return "rejected"

            return "completed"

    # Submit the same token concurrently with different passwords.
    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(
            attempt_reset,
            first_password,
        )
        second_future = executor.submit(
            attempt_reset,
            second_password,
        )

        results = [
            first_future.result(timeout=20),
            second_future.result(timeout=20),
        ]

    # Exactly one operation must succeed.
    assert sorted(results) == ["completed", "rejected"]

    # Determine which submitted password was accepted.
    successful_password = (
        first_password if results[0] == "completed" else second_password
    )

    rejected_password = second_password if results[0] == "completed" else first_password

    # Verify the final committed database state.
    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.password_hash is not None

        assert verify_password(
            successful_password,
            user.password_hash,
        )

        assert not verify_password(
            rejected_password,
            user.password_hash,
        )

        stored_token = session.scalar(
            select(OneTimeToken).where(OneTimeToken.token_hash == hash_token(raw_token))
        )

        assert stored_token is not None
        assert stored_token.consumed_at is not None
        assert stored_token.revoked_at is None

        completion_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_reset_completed",
            )
        ).all()
        assert len(completion_events) == 1


def test_password_reset_rolls_back_on_transaction_failure(
    test_engine: Engine,
    reset_accounts: tuple[UUID, UUID],
) -> None:
    """Failure after SQL flush must roll back every recovery change."""
    administrator_id, user_id = reset_accounts
    original_hash = "test-password-hash"
    new_password = "A secure replacement passphrase #8472"

    now = datetime.now(UTC)
    raw_refresh_token = generate_token()
    refresh_token_hash = hash_token(raw_refresh_token)

    # Prepare an account with an existing active session.
    with Session(test_engine) as session:
        with session.begin():
            user = session.get(User, user_id)

            assert user is not None
            user.password_reset_required = True

            login_session = LoginSession(
                user_id=user_id,
                refresh_token_hash=refresh_token_hash,
                created_at=now,
                expires_at=now + timedelta(days=7),
            )

            session.add(login_session)
            session.flush()

            session_id = login_session.id

    # Issue a valid recovery token.
    with Session(test_engine) as session:
        raw_token, _ = issue_password_reset_token(
            session,
            actor_id=administrator_id,
            user_id=user_id,
            expiry_minutes=30,
        )

    # Inject a test-only failure after SQL has been flushed.
    # The database transaction has not committed at this point.
    def fail_after_flush(
        _session: Session,
        _flush_context: object,
    ) -> None:
        raise RuntimeError("Simulated transaction failure")

    with Session(test_engine) as session:
        event.listen(
            session,
            "after_flush_postexec",
            fail_after_flush,
        )

        with pytest.raises(
            RuntimeError,
            match="Simulated transaction failure",
        ):
            reset_user_password(
                session,
                token=raw_token,
                new_password=new_password,
            )

    # Read using a fresh session to inspect committed state.
    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.password_hash == original_hash
        assert user.password_reset_required is True
        assert user.status == "active"

        stored_token = session.scalar(
            select(OneTimeToken).where(OneTimeToken.token_hash == hash_token(raw_token))
        )

        assert stored_token is not None
        assert stored_token.consumed_at is None
        assert stored_token.revoked_at is None

        stored_session = session.get(LoginSession, session_id)

        assert stored_session is not None
        assert stored_session.revoked_at is None
        assert stored_session.revocation_reason is None
        assert stored_session.refresh_token_hash == refresh_token_hash

        completion_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_reset_completed",
            )
        ).all()
        assert completion_events == []

    # The token should still be usable after the failed attempt.
    with Session(test_engine) as session:
        reset_user_password(
            session,
            token=raw_token,
            new_password=new_password,
        )

    # A successful retry must commit the expected changes.
    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.password_hash is not None
        assert verify_password(new_password, user.password_hash)
        assert user.password_reset_required is False

        stored_session = session.get(LoginSession, session_id)

        assert stored_session is not None
        assert stored_session.revoked_at is not None
        assert stored_session.refresh_token_hash is None
        assert stored_session.revocation_reason == "password_reset"

        stored_token = session.scalar(
            select(OneTimeToken).where(OneTimeToken.token_hash == hash_token(raw_token))
        )

        assert stored_token is not None
        assert stored_token.consumed_at is not None

        completion_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_reset_completed",
            )
        ).all()
        assert len(completion_events) == 1
        assert completion_events[0].actor_user_id is None


def test_password_reset_issuance_audit_rolls_back_on_failure(
    test_engine: Engine,
    reset_accounts: tuple[UUID, UUID],
) -> None:
    """A failed token issuance must leave neither a token nor an audit event."""
    administrator_id, user_id = reset_accounts

    def fail_after_flush(
        _session: Session,
        _flush_context: object,
    ) -> None:
        raise RuntimeError("Simulated issuance failure")

    with Session(test_engine) as session:
        event.listen(session, "after_flush_postexec", fail_after_flush)
        with pytest.raises(RuntimeError, match="Simulated issuance failure"):
            issue_password_reset_token(
                session,
                actor_id=administrator_id,
                user_id=user_id,
                expiry_minutes=30,
            )

    with Session(test_engine) as session:
        assert (
            session.scalars(
                select(OneTimeToken).where(
                    OneTimeToken.user_id == user_id,
                    OneTimeToken.purpose == "password_reset",
                )
            ).all()
            == []
        )
        assert (
            session.scalars(
                select(AuditLog).where(
                    AuditLog.target_user_id == user_id,
                    AuditLog.action == "user.password_reset_issued",
                )
            ).all()
            == []
        )

    with Session(test_engine) as session:
        issue_password_reset_token(
            session,
            actor_id=administrator_id,
            user_id=user_id,
            expiry_minutes=30,
        )

    with Session(test_engine) as session:
        events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_reset_issued",
            )
        ).all()
        assert len(events) == 1
        assert events[0].actor_user_id == administrator_id
