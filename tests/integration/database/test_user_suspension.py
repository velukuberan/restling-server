"""PostgreSQL integration tests for account suspension."""

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
    User,
)
from restling_server.users.service import (
    InvalidCredentialsError,
    LastAdministratorError,
    UserSuspensionNotAllowedError,
    authenticate_access_token,
    refresh_session,
    suspend_user,
)
from restling_server.users.tokens import generate_token, hash_token


@pytest.fixture
def suspension_accounts(
    test_engine: Engine,
) -> Iterator[tuple[UUID, UUID]]:
    """Create an administrator and an ordinary active user."""
    test_id = uuid7().hex
    admin_email = f"suspension-admin-{test_id}@example.com"
    user_email = f"suspension-user-{test_id}@example.com"

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
                display_name="Ordinary User",
                status="active",
                system_role="user",
                password_hash="test-password-hash",
            )

            session.add_all([administrator, user])
            session.commit()

            administrator_id = administrator.id
            user_id = user.id

        yield administrator_id, user_id

    finally:
        with test_engine.begin() as connection:
            user_ids = select(User.id).where(
                User.normalized_email.in_([admin_email, user_email])
            )

            # Sessions must be deleted before their owning users.
            # Related access tokens cascade through the session FK.
            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )

            # Audit records intentionally do not have foreign keys to users.
            connection.execute(
                delete(AuditLog).where(AuditLog.target_user_id.in_(user_ids))
            )

            connection.execute(
                delete(User).where(User.normalized_email.in_([admin_email, user_email]))
            )


def test_suspension_revokes_all_existing_sessions(
    test_engine: Engine,
    suspension_accounts: tuple[UUID, UUID],
) -> None:
    """Suspension must immediately invalidate every login session."""
    administrator_id, user_id = suspension_accounts

    now = datetime.now(UTC)
    access_tokens: list[str] = []
    refresh_tokens: list[str] = []

    # Create two independent active sessions.
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

                session.add(
                    AccessToken(
                        session_id=login_session.id,
                        token_hash=hash_token(raw_access_token),
                        created_at=now,
                        expires_at=now + timedelta(minutes=15),
                    )
                )

                access_tokens.append(raw_access_token)
                refresh_tokens.append(raw_refresh_token)

    # Both access credentials work before suspension.
    for raw_token in access_tokens:
        with Session(test_engine) as session:
            user = authenticate_access_token(
                session,
                access_token=raw_token,
            )
            assert user.id == user_id

    with Session(test_engine) as session:
        suspend_user(
            session,
            actor_id=administrator_id,
            user_id=user_id,
        )

    # Verify account status and committed session changes.
    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.status == "suspended"
        assert user.password_hash == "test-password-hash"

        sessions = session.scalars(
            select(LoginSession).where(LoginSession.user_id == user_id)
        ).all()

        assert len(sessions) == 2

        for login_session in sessions:
            assert login_session.revoked_at is not None
            assert login_session.refresh_token_hash is None
            assert login_session.revocation_reason == "account_suspended"

    # Existing access tokens must immediately become unusable.
    for raw_token in access_tokens:
        with Session(test_engine) as session:
            with pytest.raises(InvalidCredentialsError):
                authenticate_access_token(
                    session,
                    access_token=raw_token,
                )

    # Existing refresh tokens must also be rejected.
    for raw_token in refresh_tokens:
        with Session(test_engine) as session:
            with pytest.raises(InvalidCredentialsError):
                refresh_session(
                    session,
                    refresh_token=raw_token,
                    access_token_expiry_minutes=15,
                )


def test_ordinary_user_cannot_suspend_an_account(
    test_engine: Engine,
    suspension_accounts: tuple[UUID, UUID],
) -> None:
    """Ordinary users cannot perform administrative suspension."""
    administrator_id, user_id = suspension_accounts

    with Session(test_engine) as session:
        with pytest.raises(UserSuspensionNotAllowedError):
            suspend_user(
                session,
                actor_id=user_id,
                user_id=administrator_id,
            )

    # The denied operation must not change the administrator.
    with Session(test_engine) as session:
        administrator = session.get(User, administrator_id)

        assert administrator is not None
        assert administrator.status == "active"
        assert administrator.system_role == "administrator"


def test_last_active_administrator_cannot_be_suspended(
    test_engine: Engine,
    suspension_accounts: tuple[UUID, UUID],
) -> None:
    """The only active administrator must remain active."""
    administrator_id, _ = suspension_accounts

    with Session(test_engine) as session:
        with pytest.raises(LastAdministratorError):
            suspend_user(
                session,
                actor_id=administrator_id,
                user_id=administrator_id,
            )

    with Session(test_engine) as session:
        administrator = session.get(User, administrator_id)

        assert administrator is not None
        assert administrator.status == "active"
        assert administrator.system_role == "administrator"


def test_suspended_administrator_cannot_suspend_user(
    test_engine: Engine,
    suspension_accounts: tuple[UUID, UUID],
) -> None:
    """Suspended administrators cannot perform privileged operations."""
    administrator_id, user_id = suspension_accounts

    with Session(test_engine) as session:
        with session.begin():
            administrator = session.get(User, administrator_id)

            assert administrator is not None
            administrator.status = "suspended"

    with Session(test_engine) as session:
        with pytest.raises(UserSuspensionNotAllowedError):
            suspend_user(
                session,
                actor_id=administrator_id,
                user_id=user_id,
            )

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.status == "active"


def test_administrator_requiring_password_reset_cannot_suspend_user(
    test_engine: Engine,
    suspension_accounts: tuple[UUID, UUID],
) -> None:
    """Administrators must complete required recovery before acting."""
    administrator_id, user_id = suspension_accounts

    with Session(test_engine) as session:
        with session.begin():
            administrator = session.get(User, administrator_id)

            assert administrator is not None
            administrator.password_reset_required = True

    with Session(test_engine) as session:
        with pytest.raises(UserSuspensionNotAllowedError):
            suspend_user(
                session,
                actor_id=administrator_id,
                user_id=user_id,
            )

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.status == "active"


def test_concurrent_administrator_suspension_preserves_one_admin(
    test_engine: Engine,
    suspension_accounts: tuple[UUID, UUID],
) -> None:
    """Concurrent suspension cannot remove both active administrators."""
    first_admin_id, second_admin_id = suspension_accounts

    # Promote the fixture's ordinary user to a second administrator.
    with Session(test_engine) as session:
        with session.begin():
            second_administrator = session.get(User, second_admin_id)

            assert second_administrator is not None
            second_administrator.system_role = "administrator"

    barrier = Barrier(2, timeout=10)

    def attempt_suspension(
        actor_id: UUID,
        target_id: UUID,
    ) -> str:
        with Session(test_engine) as session:
            barrier.wait()

            try:
                suspend_user(
                    session,
                    actor_id=actor_id,
                    user_id=target_id,
                )
            except (
                LastAdministratorError,
                UserSuspensionNotAllowedError,
            ):
                return "rejected"

            return "completed"

    # Both administrators attempt to suspend each other.
    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(
            attempt_suspension,
            first_admin_id,
            second_admin_id,
        )

        second_future = executor.submit(
            attempt_suspension,
            second_admin_id,
            first_admin_id,
        )

        results = [
            first_future.result(timeout=20),
            second_future.result(timeout=20),
        ]

    # Exactly one suspension must succeed.
    assert sorted(results) == ["completed", "rejected"]

    # Verify the committed state from a fresh database session.
    with Session(test_engine) as session:
        administrators = session.scalars(
            select(User).where(User.id.in_([first_admin_id, second_admin_id]))
        ).all()

        assert len(administrators) == 2
        assert all(
            administrator.system_role == "administrator"
            for administrator in administrators
        )

        active_administrators = [
            administrator
            for administrator in administrators
            if administrator.status == "active"
        ]

        suspended_administrators = [
            administrator
            for administrator in administrators
            if administrator.status == "suspended"
        ]

        assert len(active_administrators) == 1
        assert len(suspended_administrators) == 1


def test_suspension_rolls_back_on_transaction_failure(
    test_engine: Engine,
    suspension_accounts: tuple[UUID, UUID],
) -> None:
    """Failed suspension must preserve account and session state."""
    administrator_id, user_id = suspension_accounts

    now = datetime.now(UTC)
    raw_access_token = generate_token()
    raw_refresh_token = generate_token()
    refresh_hash = hash_token(raw_refresh_token)

    # Establish a real, active login session.
    with Session(test_engine) as session:
        with session.begin():
            login_session = LoginSession(
                user_id=user_id,
                refresh_token_hash=refresh_hash,
                created_at=now,
                expires_at=now + timedelta(days=7),
            )

            session.add(login_session)
            session.flush()

            session_id = login_session.id

            session.add(
                AccessToken(
                    session_id=session_id,
                    token_hash=hash_token(raw_access_token),
                    created_at=now,
                    expires_at=now + timedelta(minutes=15),
                )
            )

    # Verify authentication works before attempting suspension.
    with Session(test_engine) as session:
        user = authenticate_access_token(
            session,
            access_token=raw_access_token,
        )
        assert user.id == user_id

    # Inject a failure after the suspension SQL has been flushed,
    # but before PostgreSQL commits the transaction.
    def fail_after_flush(
        _session: Session,
        _flush_context: object,
    ) -> None:
        raise RuntimeError("Simulated suspension failure")

    with Session(test_engine) as session:
        event.listen(
            session,
            "after_flush_postexec",
            fail_after_flush,
        )

        with pytest.raises(
            RuntimeError,
            match="Simulated suspension failure",
        ):
            suspend_user(
                session,
                actor_id=administrator_id,
                user_id=user_id,
            )

    # A fresh session reads only committed PostgreSQL state.
    with Session(test_engine) as session:
        user = session.get(User, user_id)
        stored_session = session.get(LoginSession, session_id)

        assert user is not None
        assert user.status == "active"
        assert user.password_hash == "test-password-hash"

        assert stored_session is not None
        assert stored_session.revoked_at is None
        assert stored_session.revocation_reason is None
        assert stored_session.refresh_token_hash == refresh_hash

        # The failed transaction must not leave a success audit event.
        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.suspended",
            )
        ).all()
        assert audit_events == []

    # The failed suspension must not invalidate credentials.
    with Session(test_engine) as session:
        authenticated_user = authenticate_access_token(
            session,
            access_token=raw_access_token,
        )
        assert authenticated_user.id == user_id

    # Retry without fault injection.
    with Session(test_engine) as session:
        suspend_user(
            session,
            actor_id=administrator_id,
            user_id=user_id,
        )

    # The successful retry must commit both changes.
    with Session(test_engine) as session:
        user = session.get(User, user_id)
        stored_session = session.get(LoginSession, session_id)

        assert user is not None
        assert user.status == "suspended"

        assert stored_session is not None
        assert stored_session.revoked_at is not None
        assert stored_session.revocation_reason == "account_suspended"
        assert stored_session.refresh_token_hash is None

        # The successful retry commits exactly one audit event.
        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.suspended",
            )
        ).all()
        assert len(audit_events) == 1
        assert audit_events[0].actor_user_id == administrator_id

    with Session(test_engine) as session:
        with pytest.raises(InvalidCredentialsError):
            authenticate_access_token(
                session,
                access_token=raw_access_token,
            )


def test_suspension_creates_audit_event(
    test_engine: Engine,
    suspension_accounts: tuple[UUID, UUID],
) -> None:
    """Successful suspension records exactly one audit event."""
    administrator_id, user_id = suspension_accounts

    with Session(test_engine) as session:
        suspend_user(
            session,
            actor_id=administrator_id,
            user_id=user_id,
        )

    with Session(test_engine) as session:
        events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.suspended",
            )
        ).all()

        assert len(events) == 1

        event = events[0]
        assert event.actor_user_id == administrator_id
        assert event.target_user_id == user_id
        assert event.action == "user.suspended"
        assert event.event_metadata == {}
        assert event.created_at is not None
