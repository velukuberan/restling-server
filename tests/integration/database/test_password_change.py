"""Integration tests for authenticated password changes."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier
from uuid import UUID

import pytest
from sqlalchemy import Engine, event, select
from sqlalchemy.orm import Session

from restling_server.users.models import (
    AccessToken,
    AuditLog,
    LoginSession,
    OneTimeToken,
    User,
)
from restling_server.users.passwords import (
    hash_password,
    verify_password,
)
from restling_server.users.service import (
    InvalidCredentialsError,
    LoginResult,
    PasswordUnchangedError,
    authenticate_access_token,
    change_user_password,
    login_user,
    logout_session,
    refresh_session,
)
from restling_server.users.tokens import generate_token, hash_token

EMAIL = "password-change@example.com"
PASSWORD = "A secure current password passphrase #8472"
NEW_PASSWORD = "A secure replacement passphrase #9274"


def create_account(
    session: Session,
    *,
    password: str = PASSWORD,
    email: str = EMAIL,
) -> UUID:
    """Persist an active account for password-change testing."""
    with session.begin():
        user = User(
            email=email,
            normalized_email=email.casefold(),
            display_name="Password Change Test User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )

        session.add(user)
        session.flush()

        user_id = user.id

    return user_id


def login(
    session: Session,
    *,
    email: str = EMAIL,
    password: str = PASSWORD,
) -> LoginResult:
    """Authenticate using the real login service."""
    return login_user(
        session,
        email=email,
        password=password,
        access_token_expiry_minutes=15,
        refresh_session_expiry_days=7,
        max_active_sessions=2,
    )


def test_password_change_revokes_all_sessions_and_credentials(
    db_session: Session,
) -> None:
    """Password change invalidates sessions and outstanding credentials."""
    user_id = create_account(db_session)

    first_login = login(db_session)
    second_login = login(db_session)

    raw_reset_token = generate_token()
    raw_email_change_token = generate_token()

    now = datetime.now(UTC)

    with db_session.begin():
        user = db_session.get(User, user_id)

        assert user is not None

        original_password_hash = user.password_hash

        reset_token = OneTimeToken(
            user_id=user_id,
            purpose="password_reset",
            token_hash=hash_token(raw_reset_token),
            created_at=now,
            expires_at=now + timedelta(minutes=30),
        )

        email_change_token = OneTimeToken(
            user_id=user_id,
            purpose="email_change",
            token_hash=hash_token(raw_email_change_token),
            pending_email="changed@example.com",
            created_at=now,
            expires_at=now + timedelta(minutes=30),
        )

        db_session.add_all(
            [
                reset_token,
                email_change_token,
            ]
        )

        db_session.flush()

        reset_token_id = reset_token.id
        email_change_token_id = email_change_token.id

    change_user_password(
        db_session,
        access_token=first_login.access_token,
        current_password=PASSWORD,
        new_password=NEW_PASSWORD,
    )

    assert not db_session.in_transaction()

    with db_session.begin():
        user = db_session.get(User, user_id)

        assert user is not None
        assert user.password_hash is not None
        assert user.password_hash != original_password_hash
        assert user.password_hash.startswith("$argon2id$")
        assert verify_password(NEW_PASSWORD, user.password_hash)
        assert not verify_password(PASSWORD, user.password_hash)
        assert user.password_reset_required is False
        assert user.status == "active"
        assert user.email == EMAIL

        login_sessions = db_session.scalars(
            select(LoginSession).where(
                LoginSession.user_id == user_id,
            )
        ).all()

        assert len(login_sessions) == 2

        assert {item.id for item in login_sessions} == {
            first_login.session_id,
            second_login.session_id,
        }

        for login_session in login_sessions:
            assert login_session.revoked_at is not None
            assert login_session.refresh_token_hash is None
            assert login_session.revocation_reason == "password_changed"

        for token_id in (
            reset_token_id,
            email_change_token_id,
        ):
            stored_token = db_session.get(
                OneTimeToken,
                token_id,
            )

            assert stored_token is not None
            assert stored_token.revoked_at is not None
            assert stored_token.consumed_at is None

        audit_events = db_session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_changed",
            )
        ).all()

        assert len(audit_events) == 1

        audit_event = audit_events[0]

        assert audit_event.actor_user_id == user_id
        assert audit_event.target_user_id == user_id
        assert audit_event.event_metadata == {}

    # Neither previously issued access credential is usable.
    for login_result in (first_login, second_login):
        with db_session.begin():
            with pytest.raises(InvalidCredentialsError):
                authenticate_access_token(
                    db_session,
                    access_token=login_result.access_token,
                )

        with pytest.raises(InvalidCredentialsError):
            refresh_session(
                db_session,
                refresh_token=login_result.refresh_token,
                access_token_expiry_minutes=15,
            )

    # The previous password must no longer authenticate.
    with pytest.raises(InvalidCredentialsError):
        login(db_session, password=PASSWORD)

    # A fresh login using the new password must succeed.
    new_login = login(
        db_session,
        password=NEW_PASSWORD,
    )

    assert new_login.session_id not in {
        first_login.session_id,
        second_login.session_id,
    }

    with db_session.begin():
        authenticated_user = authenticate_access_token(
            db_session,
            access_token=new_login.access_token,
        )

        assert authenticated_user.id == user_id


@pytest.mark.parametrize(
    ("current_password", "new_password", "expected_error"),
    [
        (
            "An incorrect current password #1234",
            NEW_PASSWORD,
            InvalidCredentialsError,
        ),
        (
            PASSWORD,
            "too short",
            ValueError,
        ),
        (
            PASSWORD,
            "x" * 65,
            ValueError,
        ),
        (
            PASSWORD,
            PASSWORD,
            PasswordUnchangedError,
        ),
        (
            PASSWORD,
            "passwordpassword",
            ValueError,
        ),
    ],
)
def test_rejected_password_change_preserves_account_state(
    db_session: Session,
    current_password: str,
    new_password: str,
    expected_error: type[Exception],
) -> None:
    """Rejected password changes must not modify account state."""
    user_id = create_account(db_session)

    login_result = login(db_session)

    now = datetime.now(UTC)

    with db_session.begin():
        user = db_session.get(User, user_id)

        assert user is not None

        original_password_hash = user.password_hash
        original_updated_at = user.updated_at

        reset_token = OneTimeToken(
            user_id=user_id,
            purpose="password_reset",
            token_hash=hash_token(generate_token()),
            created_at=now,
            expires_at=now + timedelta(minutes=30),
        )

        db_session.add(reset_token)
        db_session.flush()

        reset_token_id = reset_token.id

    with pytest.raises(expected_error):
        change_user_password(
            db_session,
            access_token=login_result.access_token,
            current_password=current_password,
            new_password=new_password,
        )

    assert not db_session.in_transaction()

    with db_session.begin():
        user = db_session.get(User, user_id)

        assert user is not None
        assert user.password_hash == original_password_hash
        assert user.updated_at == original_updated_at

        login_session = db_session.get(
            LoginSession,
            login_result.session_id,
        )

        assert login_session is not None
        assert login_session.revoked_at is None
        assert login_session.refresh_token_hash == hash_token(
            login_result.refresh_token
        )

        stored_token = db_session.get(
            OneTimeToken,
            reset_token_id,
        )

        assert stored_token is not None
        assert stored_token.revoked_at is None
        assert stored_token.consumed_at is None

        audit_events = db_session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_changed",
            )
        ).all()

        assert audit_events == []

        authenticated_user = authenticate_access_token(
            db_session,
            access_token=login_result.access_token,
        )

        assert authenticated_user.id == user_id


def test_password_change_rejects_unicode_equivalent_password(
    db_session: Session,
) -> None:
    """Equivalent Unicode passwords cannot bypass reuse protection."""
    original_password = "A secure caf\u00e9 passphrase #8472"
    equivalent_password = "A secure cafe\u0301 passphrase #8472"

    assert original_password != equivalent_password

    user_id = create_account(
        db_session,
        password=original_password,
    )

    login_result = login(
        db_session,
        password=original_password,
    )

    with pytest.raises(
        PasswordUnchangedError,
        match="The new password must differ from the current password.",
    ):
        change_user_password(
            db_session,
            access_token=login_result.access_token,
            current_password=original_password,
            new_password=equivalent_password,
        )

    with db_session.begin():
        authenticated_user = authenticate_access_token(
            db_session,
            access_token=login_result.access_token,
        )

        assert authenticated_user.id == user_id

        assert (
            db_session.scalars(
                select(AuditLog).where(
                    AuditLog.target_user_id == user_id,
                    AuditLog.action == "user.password_changed",
                )
            ).all()
            == []
        )


@pytest.mark.parametrize(
    "credential_state",
    [
        "unknown_access_token",
        "expired_access_token",
        "expired_session",
        "revoked_session",
        "suspended_account",
        "password_reset_required",
    ],
)
def test_password_change_rejects_ineligible_authentication(
    db_session: Session,
    credential_state: str,
) -> None:
    """Only eligible authenticated accounts can change passwords."""
    user_id = create_account(db_session)

    login_result = login(db_session)

    access_token = login_result.access_token

    now = datetime.now(UTC)

    with db_session.begin():
        user = db_session.get(User, user_id)

        assert user is not None

        original_password_hash = user.password_hash

        login_session = db_session.get(
            LoginSession,
            login_result.session_id,
        )

        assert login_session is not None

        stored_access_token = db_session.scalar(
            select(AccessToken).where(
                AccessToken.token_hash == hash_token(access_token),
            )
        )

        assert stored_access_token is not None

        if credential_state == "unknown_access_token":
            access_token = generate_token()

        elif credential_state == "expired_access_token":
            stored_access_token.created_at = now - timedelta(hours=2)
            stored_access_token.expires_at = now - timedelta(hours=1)

        elif credential_state == "expired_session":
            login_session.created_at = now - timedelta(days=8)
            login_session.expires_at = now - timedelta(days=1)

        elif credential_state == "revoked_session":
            login_session.refresh_token_hash = None
            login_session.revoked_at = now
            login_session.revocation_reason = "logout"

        elif credential_state == "suspended_account":
            user.status = "suspended"

        elif credential_state == "password_reset_required":
            user.password_reset_required = True

    with db_session.begin():
        user = db_session.get(User, user_id)

        assert user is not None

        original_updated_at = user.updated_at
        original_status = user.status
        original_reset_required = user.password_reset_required

        login_session = db_session.get(
            LoginSession,
            login_result.session_id,
        )

        assert login_session is not None

        original_revoked_at = login_session.revoked_at
        original_refresh_hash = login_session.refresh_token_hash
        original_revocation_reason = login_session.revocation_reason

    with pytest.raises(
        InvalidCredentialsError,
        match="Invalid access credential.",
    ):
        change_user_password(
            db_session,
            access_token=access_token,
            current_password=PASSWORD,
            new_password=NEW_PASSWORD,
        )

    assert not db_session.in_transaction()

    with db_session.begin():
        user = db_session.get(User, user_id)

        assert user is not None
        assert user.password_hash == original_password_hash
        assert user.updated_at == original_updated_at
        assert user.status == original_status
        assert user.password_reset_required == original_reset_required

        login_session = db_session.get(
            LoginSession,
            login_result.session_id,
        )

        assert login_session is not None
        assert login_session.revoked_at == original_revoked_at
        assert login_session.refresh_token_hash == original_refresh_hash
        assert login_session.revocation_reason == original_revocation_reason

        audit_events = db_session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_changed",
            )
        ).all()

        assert audit_events == []


def test_password_change_does_not_modify_another_account(
    db_session: Session,
) -> None:
    """Password changes must remain within the authenticated account."""
    first_user_id = create_account(db_session)

    second_email = "another-password-change@example.com"

    second_user_id = create_account(
        db_session,
        email=second_email,
    )

    first_login = login(db_session)

    second_login = login(
        db_session,
        email=second_email,
    )

    now = datetime.now(UTC)

    with db_session.begin():
        second_user = db_session.get(User, second_user_id)

        assert second_user is not None

        original_password_hash = second_user.password_hash
        original_updated_at = second_user.updated_at

        second_reset_token = OneTimeToken(
            user_id=second_user_id,
            purpose="password_reset",
            token_hash=hash_token(generate_token()),
            created_at=now,
            expires_at=now + timedelta(minutes=30),
        )

        db_session.add(second_reset_token)
        db_session.flush()

        second_reset_token_id = second_reset_token.id

    change_user_password(
        db_session,
        access_token=first_login.access_token,
        current_password=PASSWORD,
        new_password=NEW_PASSWORD,
    )

    with db_session.begin():
        second_user = db_session.get(User, second_user_id)

        assert second_user is not None
        assert second_user.password_hash == original_password_hash
        assert second_user.updated_at == original_updated_at

        second_session = db_session.get(
            LoginSession,
            second_login.session_id,
        )

        assert second_session is not None
        assert second_session.revoked_at is None
        assert second_session.refresh_token_hash == hash_token(
            second_login.refresh_token
        )

        stored_token = db_session.get(
            OneTimeToken,
            second_reset_token_id,
        )

        assert stored_token is not None
        assert stored_token.revoked_at is None
        assert stored_token.consumed_at is None

        authenticated_user = authenticate_access_token(
            db_session,
            access_token=second_login.access_token,
        )

        assert authenticated_user.id == second_user_id

        audit_events = db_session.scalars(
            select(AuditLog).where(
                AuditLog.action == "user.password_changed",
            )
        ).all()

        assert len(audit_events) == 1
        assert audit_events[0].actor_user_id == first_user_id
        assert audit_events[0].target_user_id == first_user_id


@pytest.mark.parametrize(
    "purpose",
    ["password_reset", "email_change"],
)
def test_password_change_preserves_historical_credentials(
    db_session: Session,
    purpose: str,
) -> None:
    """Password changes preserve historical credential lifecycle records."""
    user_id = create_account(db_session)

    historical_login = login(db_session)

    logout_session(
        db_session,
        access_token=historical_login.access_token,
    )

    current_login = login(db_session)

    now = datetime.now(UTC)
    historical_timestamp = now - timedelta(minutes=5)

    pending_email = "changed@example.com" if purpose == "email_change" else None

    with db_session.begin():
        historical_session = db_session.get(
            LoginSession,
            historical_login.session_id,
        )

        assert historical_session is not None
        assert historical_session.revoked_at is not None

        original_session_revoked_at = historical_session.revoked_at
        original_revocation_reason = historical_session.revocation_reason

        consumed_token = OneTimeToken(
            user_id=user_id,
            purpose=purpose,
            token_hash=hash_token(generate_token()),
            pending_email=pending_email,
            created_at=now - timedelta(minutes=10),
            expires_at=now + timedelta(minutes=20),
            consumed_at=historical_timestamp,
        )

        revoked_token = OneTimeToken(
            user_id=user_id,
            purpose=purpose,
            token_hash=hash_token(generate_token()),
            pending_email=pending_email,
            created_at=now - timedelta(minutes=10),
            expires_at=now + timedelta(minutes=20),
            revoked_at=historical_timestamp,
        )

        expired_token = OneTimeToken(
            user_id=user_id,
            purpose=purpose,
            token_hash=hash_token(generate_token()),
            pending_email=pending_email,
            created_at=now - timedelta(minutes=60),
            expires_at=now - timedelta(minutes=30),
        )

        db_session.add_all(
            [
                consumed_token,
                revoked_token,
                expired_token,
            ]
        )

        db_session.flush()

        consumed_token_id = consumed_token.id
        revoked_token_id = revoked_token.id
        expired_token_id = expired_token.id

    change_user_password(
        db_session,
        access_token=current_login.access_token,
        current_password=PASSWORD,
        new_password=NEW_PASSWORD,
    )

    with db_session.begin():
        consumed_token = db_session.get(
            OneTimeToken,
            consumed_token_id,
        )

        assert consumed_token is not None
        assert consumed_token.consumed_at == historical_timestamp
        assert consumed_token.revoked_at is None

        revoked_token = db_session.get(
            OneTimeToken,
            revoked_token_id,
        )

        assert revoked_token is not None
        assert revoked_token.revoked_at == historical_timestamp
        assert revoked_token.consumed_at is None

        expired_token = db_session.get(
            OneTimeToken,
            expired_token_id,
        )

        assert expired_token is not None
        assert expired_token.revoked_at is not None
        assert expired_token.revoked_at >= now
        assert expired_token.consumed_at is None

        historical_session = db_session.get(
            LoginSession,
            historical_login.session_id,
        )

        assert historical_session is not None
        assert historical_session.revoked_at == original_session_revoked_at
        assert historical_session.revocation_reason == original_revocation_reason
        assert historical_session.refresh_token_hash is None

        current_session = db_session.get(
            LoginSession,
            current_login.session_id,
        )

        assert current_session is not None
        assert current_session.revoked_at is not None
        assert current_session.revocation_reason == "password_changed"
        assert current_session.refresh_token_hash is None


def test_password_change_rolls_back_on_transaction_failure(
    test_engine: Engine,
) -> None:
    """A failed password change preserves all existing account state."""
    now = datetime.now(UTC)

    with Session(test_engine) as session:
        user_id = create_account(session)

        first_login = login(session)
        second_login = login(session)

        with session.begin():
            user = session.get(User, user_id)

            assert user is not None

            original_password_hash = user.password_hash
            original_updated_at = user.updated_at

            reset_token = OneTimeToken(
                user_id=user_id,
                purpose="password_reset",
                token_hash=hash_token(generate_token()),
                created_at=now,
                expires_at=now + timedelta(minutes=30),
            )

            email_change_token = OneTimeToken(
                user_id=user_id,
                purpose="email_change",
                token_hash=hash_token(generate_token()),
                pending_email="changed@example.com",
                created_at=now,
                expires_at=now + timedelta(minutes=30),
            )

            session.add_all(
                [
                    reset_token,
                    email_change_token,
                ]
            )

            session.flush()

            reset_token_id = reset_token.id
            email_change_token_id = email_change_token.id

    def fail_after_flush(
        _session: Session,
        _flush_context: object,
    ) -> None:
        raise RuntimeError("Simulated password-change transaction failure")

    with Session(test_engine) as session:
        event.listen(
            session,
            "after_flush_postexec",
            fail_after_flush,
        )

        with pytest.raises(
            RuntimeError,
            match="Simulated password-change transaction failure",
        ):
            change_user_password(
                session,
                access_token=first_login.access_token,
                current_password=PASSWORD,
                new_password=NEW_PASSWORD,
            )

        assert not session.in_transaction()

    # Verify committed database state using an independent session.
    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.password_hash == original_password_hash
        assert user.updated_at == original_updated_at

        assert user.password_hash is not None
        assert verify_password(PASSWORD, user.password_hash)
        assert not verify_password(
            NEW_PASSWORD,
            user.password_hash,
        )

        for login_result in (first_login, second_login):
            login_session = session.get(
                LoginSession,
                login_result.session_id,
            )

            assert login_session is not None
            assert login_session.revoked_at is None
            assert login_session.revocation_reason is None
            assert login_session.refresh_token_hash == hash_token(
                login_result.refresh_token
            )

            authenticated_user = authenticate_access_token(
                session,
                access_token=login_result.access_token,
            )

            assert authenticated_user.id == user_id

        for token_id in (
            reset_token_id,
            email_change_token_id,
        ):
            stored_token = session.get(
                OneTimeToken,
                token_id,
            )

            assert stored_token is not None
            assert stored_token.revoked_at is None
            assert stored_token.consumed_at is None

        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_changed",
            )
        ).all()

        assert audit_events == []


def test_concurrent_password_changes_allow_only_one_success(
    test_engine: Engine,
) -> None:
    """Concurrent changes using the same old password succeed only once."""
    first_new_password = "First replacement passphrase #9274"
    second_new_password = "Second replacement passphrase #6385"

    with Session(test_engine) as session:
        user_id = create_account(session)

        first_login = login(session)
        second_login = login(session)

    barrier = Barrier(2)

    def execute_password_change(
        access_token: str,
        new_password: str,
    ) -> bool:
        with Session(test_engine) as session:
            barrier.wait(timeout=10)

            try:
                change_user_password(
                    session,
                    access_token=access_token,
                    current_password=PASSWORD,
                    new_password=new_password,
                )

            except InvalidCredentialsError:
                return False

            return True

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(
            execute_password_change,
            first_login.access_token,
            first_new_password,
        )

        second_future = executor.submit(
            execute_password_change,
            second_login.access_token,
            second_new_password,
        )

        first_succeeded = first_future.result(timeout=15)
        second_succeeded = second_future.result(timeout=15)

    assert first_succeeded != second_succeeded

    winning_password = first_new_password if first_succeeded else second_new_password

    rejected_password = second_new_password if first_succeeded else first_new_password

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.password_hash is not None

        assert verify_password(
            winning_password,
            user.password_hash,
        )

        assert not verify_password(
            rejected_password,
            user.password_hash,
        )

        assert not verify_password(
            PASSWORD,
            user.password_hash,
        )

        login_sessions = session.scalars(
            select(LoginSession).where(
                LoginSession.user_id == user_id,
            )
        ).all()

        assert len(login_sessions) == 2

        for login_session in login_sessions:
            assert login_session.revoked_at is not None
            assert login_session.refresh_token_hash is None
            assert login_session.revocation_reason == "password_changed"

        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_changed",
            )
        ).all()

        assert len(audit_events) == 1
        assert audit_events[0].actor_user_id == user_id

    with Session(test_engine) as session:
        new_login = login(
            session,
            password=winning_password,
        )

        assert new_login.session_id not in {
            first_login.session_id,
            second_login.session_id,
        }

    with Session(test_engine) as session:
        with pytest.raises(InvalidCredentialsError):
            login(
                session,
                password=rejected_password,
            )
