"""PostgreSQL integration tests for account restoration."""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy import Engine, delete, event, select
from sqlalchemy.orm import Session
from uuid6 import uuid7

from restling_server.users.models import AccessToken, AuditLog, LoginSession, User
from restling_server.users.passwords import hash_password
from restling_server.users.service import (
    InvalidCredentialsError,
    UserRestorationNotAllowedError,
    authenticate_access_token,
    login_user,
    refresh_session,
    restore_user,
    suspend_user,
)
from restling_server.users.tokens import generate_token, hash_token


@pytest.fixture
def restoration_accounts(
    test_engine: Engine,
) -> Iterator[tuple[UUID, UUID]]:
    """Create independent administrator and ordinary user accounts."""
    test_id = uuid7().hex
    admin_email = f"restore-admin-{test_id}@example.com"
    user_email = f"restore-user-{test_id}@example.com"

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

            connection.execute(
                delete(LoginSession).where(LoginSession.user_id.in_(user_ids))
            )

            connection.execute(
                delete(AuditLog).where(AuditLog.target_user_id.in_(user_ids))
            )

            connection.execute(
                delete(User).where(User.normalized_email.in_([admin_email, user_email]))
            )


def test_restoration_does_not_revive_old_sessions(
    test_engine: Engine,
    restoration_accounts: tuple[UUID, UUID],
) -> None:
    """Restoration must not restore access or refresh credentials."""
    administrator_id, user_id = restoration_accounts

    now = datetime.now(UTC)
    raw_access_token = generate_token()
    raw_refresh_token = generate_token()

    with Session(test_engine) as session:
        with session.begin():
            login_session = LoginSession(
                user_id=user_id,
                refresh_token_hash=hash_token(raw_refresh_token),
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

    # Verify that the access token initially works.
    with Session(test_engine) as session:
        authenticated_user = authenticate_access_token(
            session,
            access_token=raw_access_token,
        )

        assert authenticated_user.id == user_id

    with Session(test_engine) as session:
        suspend_user(
            session,
            actor_id=administrator_id,
            user_id=user_id,
        )

    with Session(test_engine) as session:
        restore_user(
            session,
            actor_id=administrator_id,
            user_id=user_id,
        )

    # Restoration changes status but must not revive old sessions.
    with Session(test_engine) as session:
        user = session.get(User, user_id)
        stored_session = session.get(LoginSession, session_id)

        assert user is not None
        assert user.status == "active"
        assert user.password_reset_required is False
        assert user.password_hash == "test-password-hash"

        assert stored_session is not None
        assert stored_session.revoked_at is not None
        assert stored_session.revocation_reason == "account_suspended"
        assert stored_session.refresh_token_hash is None

    with Session(test_engine) as session:
        with pytest.raises(InvalidCredentialsError):
            authenticate_access_token(
                session,
                access_token=raw_access_token,
            )

    with Session(test_engine) as session:
        with pytest.raises(InvalidCredentialsError):
            refresh_session(
                session,
                refresh_token=raw_refresh_token,
                access_token_expiry_minutes=15,
            )


@pytest.mark.parametrize(
    ("existing_reset_required", "request_reset", "expected_reset_required"),
    [
        (False, False, False),
        (False, True, True),
        (True, False, True),
        (True, True, True),
    ],
)
def test_restoration_preserves_password_reset_policy(
    test_engine: Engine,
    restoration_accounts: tuple[UUID, UUID],
    existing_reset_required: bool,
    request_reset: bool,
    expected_reset_required: bool,
) -> None:
    """Restoration cannot silently remove a reset requirement."""
    administrator_id, user_id = restoration_accounts

    with Session(test_engine) as session:
        with session.begin():
            user = session.get(User, user_id)

            assert user is not None
            user.status = "suspended"
            user.password_reset_required = existing_reset_required

    with Session(test_engine) as session:
        restore_user(
            session,
            actor_id=administrator_id,
            user_id=user_id,
            require_password_reset=request_reset,
        )

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.status == "active"
        assert user.password_reset_required is expected_reset_required

        audit_event = session.scalar(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.restored",
            )
        )

        assert audit_event is not None
        assert audit_event.event_metadata == {
            "password_reset_required": expected_reset_required,
        }


def test_ordinary_user_cannot_restore_an_account(
    test_engine: Engine,
    restoration_accounts: tuple[UUID, UUID],
) -> None:
    """An ordinary account cannot restore a suspended administrator."""
    administrator_id, user_id = restoration_accounts

    with Session(test_engine) as session:
        with session.begin():
            administrator = session.get(User, administrator_id)

            assert administrator is not None
            administrator.status = "suspended"

    with Session(test_engine) as session:
        with pytest.raises(UserRestorationNotAllowedError):
            restore_user(
                session,
                actor_id=user_id,
                user_id=administrator_id,
            )

    with Session(test_engine) as session:
        administrator = session.get(User, administrator_id)

        assert administrator is not None
        assert administrator.status == "suspended"

        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == administrator_id,
                AuditLog.action == "user.restored",
            )
        ).all()
        assert audit_events == []


@pytest.mark.parametrize("status", ["active", "pending"])
def test_ineligible_account_cannot_be_restored(
    test_engine: Engine,
    restoration_accounts: tuple[UUID, UUID],
    status: str,
) -> None:
    """Only suspended accounts are eligible for restoration."""
    administrator_id, user_id = restoration_accounts

    with Session(test_engine) as session:
        with session.begin():
            user = session.get(User, user_id)

            assert user is not None
            user.status = status

            if status == "pending":
                user.password_hash = None

    with Session(test_engine) as session:
        with pytest.raises(UserRestorationNotAllowedError):
            restore_user(
                session,
                actor_id=administrator_id,
                user_id=user_id,
            )

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.status == status


def test_suspended_administrator_cannot_restore_user(
    test_engine: Engine,
    restoration_accounts: tuple[UUID, UUID],
) -> None:
    """Suspended administrators cannot perform restoration."""
    administrator_id, user_id = restoration_accounts

    with Session(test_engine) as session:
        with session.begin():
            administrator = session.get(User, administrator_id)
            user = session.get(User, user_id)

            assert administrator is not None
            assert user is not None

            administrator.status = "suspended"
            user.status = "suspended"

    with Session(test_engine) as session:
        with pytest.raises(UserRestorationNotAllowedError):
            restore_user(
                session,
                actor_id=administrator_id,
                user_id=user_id,
            )

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.status == "suspended"


def test_restored_user_can_create_new_login_session(
    test_engine: Engine,
    restoration_accounts: tuple[UUID, UUID],
) -> None:
    """Restored users can authenticate through a new login session."""
    administrator_id, user_id = restoration_accounts
    password = "A secure restoration passphrase #8472"

    with Session(test_engine) as session:
        with session.begin():
            user = session.get(User, user_id)

            assert user is not None
            user.password_hash = hash_password(password)

    with Session(test_engine) as session:
        suspend_user(
            session,
            actor_id=administrator_id,
            user_id=user_id,
        )

    with Session(test_engine) as session:
        restore_user(
            session,
            actor_id=administrator_id,
            user_id=user_id,
        )

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        email = user.email

    with Session(test_engine) as session:
        result = login_user(
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
            access_token=result.access_token,
        )

        assert authenticated_user.id == user_id

        login_session = session.get(LoginSession, result.session_id)

        assert login_session is not None
        assert login_session.revoked_at is None
        assert login_session.refresh_token_hash == hash_token(result.refresh_token)


def test_restoration_rolls_back_on_transaction_failure(
    test_engine: Engine,
    restoration_accounts: tuple[UUID, UUID],
) -> None:
    """Failed restoration must preserve the suspended account state."""
    administrator_id, user_id = restoration_accounts

    # Prepare a suspended account without a forced-reset flag.
    with Session(test_engine) as session:
        with session.begin():
            user = session.get(User, user_id)

            assert user is not None
            user.status = "suspended"
            user.password_reset_required = False

    # Fail after SQL has been flushed but before transaction commit.
    def fail_after_flush(
        _session: Session,
        _flush_context: object,
    ) -> None:
        raise RuntimeError("Simulated restoration failure")

    with Session(test_engine) as session:
        event.listen(
            session,
            "after_flush_postexec",
            fail_after_flush,
        )

        with pytest.raises(
            RuntimeError,
            match="Simulated restoration failure",
        ):
            restore_user(
                session,
                actor_id=administrator_id,
                user_id=user_id,
                require_password_reset=True,
            )

    # Neither change may have been committed.
    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.status == "suspended"
        assert user.password_reset_required is False

        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.restored",
            )
        ).all()
        assert audit_events == []

    # Retry using a fresh session without fault injection.
    with Session(test_engine) as session:
        restore_user(
            session,
            actor_id=administrator_id,
            user_id=user_id,
            require_password_reset=True,
        )

    # Both changes must now be committed.
    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.status == "active"
        assert user.password_reset_required is True
        assert user.password_hash == "test-password-hash"

        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.restored",
            )
        ).all()
        assert len(audit_events) == 1
        assert audit_events[0].actor_user_id == administrator_id


def test_restoration_creates_audit_event(
    test_engine: Engine,
    restoration_accounts: tuple[UUID, UUID],
) -> None:
    """Successful restoration records one event with the correct participants."""
    administrator_id, user_id = restoration_accounts

    with Session(test_engine) as session:
        with session.begin():
            user = session.get(User, user_id)
            assert user is not None
            user.status = "suspended"

    with Session(test_engine) as session:
        restore_user(
            session,
            actor_id=administrator_id,
            user_id=user_id,
        )

    with Session(test_engine) as session:
        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.restored",
            )
        ).all()

        assert len(audit_events) == 1
        audit_event = audit_events[0]
        assert audit_event.actor_user_id == administrator_id
        assert audit_event.target_user_id == user_id
        assert audit_event.action == "user.restored"
        assert isinstance(audit_event.event_metadata, dict)
        assert audit_event.created_at is not None
        assert audit_events[0].event_metadata == {
            "password_reset_required": False,
        }
