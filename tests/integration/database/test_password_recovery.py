"""PostgreSQL integration tests for password-recovery state."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy import event, select
from sqlalchemy.orm import Session

from restling_server.users.models import (
    AuditLog,
    LoginSession,
    OneTimeToken,
    User,
)
from restling_server.users.passwords import hash_password
from restling_server.users.service import (
    InvalidPasswordResetTokenError,
    PasswordRecoveryState,
    commit_password_reset_token_after_delivery,
    issue_password_reset_token,
    login_user,
    prepare_password_recovery,
    reset_user_password,
)
from restling_server.users.tokens import generate_token, hash_token

PASSWORD = "A secure password recovery test passphrase #8472"
EMAIL = "recovery@example.com"


def create_account(
    session: Session,
    *,
    email: str = EMAIL,
    status: str = "active",
    system_role: str = "user",
    password_reset_required: bool = False,
) -> UUID:
    """Create and persist an account for recovery testing."""
    with session.begin():
        user = User(
            email=email,
            normalized_email=email.casefold(),
            display_name="Recovery Test User",
            status=status,
            system_role=system_role,
            password_hash=(None if status == "pending" else hash_password(PASSWORD)),
            password_reset_required=password_reset_required,
        )

        session.add(user)
        session.flush()

        user_id = user.id

    return user_id


def prepare_recovery(
    session: Session,
    *,
    email: str = EMAIL,
) -> PasswordRecoveryState:
    """Prepare recovery for an account expected to be eligible."""
    state = prepare_password_recovery(
        session,
        email=email,
    )

    assert state is not None

    return state


def commit_recovery(
    session: Session,
    *,
    state: PasswordRecoveryState,
    raw_token: str,
    expiry_minutes: int = 30,
) -> bool:
    """Persist a delivered recovery credential."""
    return commit_password_reset_token_after_delivery(
        session,
        expected_state=state,
        raw_token=raw_token,
        expiry_minutes=expiry_minutes,
    )


def seed_reset_token(
    session: Session,
    *,
    user_id: UUID,
    raw_token: str,
) -> UUID:
    """Persist an existing password-reset credential."""
    now = datetime.now(UTC)

    with session.begin():
        token = OneTimeToken(
            user_id=user_id,
            purpose="password_reset",
            token_hash=hash_token(raw_token),
            created_at=now,
            expires_at=now + timedelta(minutes=30),
        )

        session.add(token)
        session.flush()

        token_id = token.id

    return token_id


@pytest.mark.parametrize(
    ("status", "password_reset_required"),
    [
        ("active", False),
        ("active", True),
        ("suspended", False),
        ("suspended", True),
    ],
)
def test_prepare_password_recovery_accepts_eligible_accounts(
    db_session: Session,
    status: str,
    password_reset_required: bool,
) -> None:
    """Active and suspended accounts are eligible for recovery."""
    user_id = create_account(
        db_session,
        status=status,
        password_reset_required=password_reset_required,
    )

    state = prepare_recovery(db_session)

    assert state.user_id == user_id
    assert state.recipient == EMAIL
    assert state.normalized_email == EMAIL
    assert state.reset_token_ids == ()


def test_prepare_password_recovery_rejects_pending_account(
    db_session: Session,
) -> None:
    """Pending accounts must complete activation instead."""
    create_account(
        db_session,
        status="pending",
    )

    assert (
        prepare_password_recovery(
            db_session,
            email=EMAIL,
        )
        is None
    )


def test_prepare_password_recovery_rejects_unknown_account(
    db_session: Session,
) -> None:
    """Unknown accounts do not produce recovery state."""
    assert (
        prepare_password_recovery(
            db_session,
            email="unknown@example.com",
        )
        is None
    )


def test_prepare_password_recovery_normalizes_email(
    db_session: Session,
) -> None:
    """Recovery uses the stored recipient rather than requester input."""
    stored_email = "Recovery@Example.com"

    user_id = create_account(
        db_session,
        email=stored_email,
    )

    state = prepare_recovery(
        db_session,
        email="  RECOVERY@EXAMPLE.COM  ",
    )

    assert state.user_id == user_id
    assert state.recipient == stored_email
    assert state.normalized_email == EMAIL


def test_prepare_password_recovery_preserves_existing_credentials(
    db_session: Session,
) -> None:
    """Preparing recovery must not modify tokens or sessions."""
    user_id = create_account(db_session)

    token_id = seed_reset_token(
        db_session,
        user_id=user_id,
        raw_token=generate_token(),
    )

    login = login_user(
        db_session,
        email=EMAIL,
        password=PASSWORD,
        access_token_expiry_minutes=15,
        refresh_session_expiry_days=7,
        max_active_sessions=2,
    )

    state = prepare_recovery(db_session)

    assert state.reset_token_ids == (token_id,)

    with db_session.begin():
        token = db_session.get(OneTimeToken, token_id)
        login_session = db_session.get(
            LoginSession,
            login.session_id,
        )

        assert token is not None
        assert token.revoked_at is None
        assert token.consumed_at is None

        assert login_session is not None
        assert login_session.revoked_at is None
        assert login_session.refresh_token_hash is not None

        audit_events = db_session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_reset_issued",
            )
        ).all()

        assert audit_events == []


def test_password_recovery_persists_hashed_token_and_audit(
    db_session: Session,
) -> None:
    """Persist only the token hash and record unauthenticated issuance."""
    user_id = create_account(db_session)
    state = prepare_recovery(db_session)
    raw_token = generate_token()

    before = datetime.now(UTC)

    assert (
        commit_recovery(
            db_session,
            state=state,
            raw_token=raw_token,
        )
        is True
    )

    after = datetime.now(UTC)

    with db_session.begin():
        tokens = db_session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "password_reset",
            )
        ).all()

        assert len(tokens) == 1

        token = tokens[0]

        assert token.token_hash == hash_token(raw_token)
        assert token.token_hash != raw_token
        assert token.pending_email is None
        assert token.revoked_at is None
        assert token.consumed_at is None
        assert before <= token.created_at <= after

        assert token.expires_at == (token.created_at + timedelta(minutes=30))

        audit_events = db_session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_reset_issued",
            )
        ).all()

        assert len(audit_events) == 1
        assert audit_events[0].actor_user_id is None
        assert audit_events[0].target_user_id == user_id
        assert raw_token not in str(audit_events[0].event_metadata)


def test_password_recovery_replaces_existing_reset_token(
    db_session: Session,
) -> None:
    """Successful delivery invalidates the previous reset credential."""
    user_id = create_account(db_session)

    old_token = generate_token()

    old_token_id = seed_reset_token(
        db_session,
        user_id=user_id,
        raw_token=old_token,
    )

    state = prepare_recovery(db_session)
    new_token = generate_token()

    assert (
        commit_recovery(
            db_session,
            state=state,
            raw_token=new_token,
        )
        is True
    )

    with db_session.begin():
        previous = db_session.get(
            OneTimeToken,
            old_token_id,
        )

        replacement = db_session.scalar(
            select(OneTimeToken).where(
                OneTimeToken.token_hash == hash_token(new_token),
            )
        )

        assert previous is not None
        assert previous.revoked_at is not None
        assert previous.consumed_at is None

        assert replacement is not None
        assert replacement.revoked_at is None
        assert replacement.consumed_at is None

    with pytest.raises(InvalidPasswordResetTokenError):
        reset_user_password(
            db_session,
            token=old_token,
            new_password="Another secure recovery passphrase #9274",
        )


def test_password_recovery_preserves_active_sessions(
    db_session: Session,
) -> None:
    """Token issuance must not revoke existing login sessions."""
    create_account(db_session)

    login = login_user(
        db_session,
        email=EMAIL,
        password=PASSWORD,
        access_token_expiry_minutes=15,
        refresh_session_expiry_days=7,
        max_active_sessions=2,
    )

    state = prepare_recovery(db_session)

    assert (
        commit_recovery(
            db_session,
            state=state,
            raw_token=generate_token(),
        )
        is True
    )

    with db_session.begin():
        login_session = db_session.get(
            LoginSession,
            login.session_id,
        )

        assert login_session is not None
        assert login_session.revoked_at is None

        assert login_session.refresh_token_hash == hash_token(login.refresh_token)


@pytest.mark.parametrize(
    "account_change",
    [
        "email",
        "password",
        "status",
        "forced_reset",
        "profile",
    ],
)
def test_password_recovery_rejects_changed_account_state(
    db_session: Session,
    account_change: str,
) -> None:
    """A delivered credential must not survive stale account state."""
    user_id = create_account(db_session)

    previous_token_id = seed_reset_token(
        db_session,
        user_id=user_id,
        raw_token=generate_token(),
    )

    state = prepare_recovery(db_session)

    # Simulate a committed account change during SMTP delivery.
    with db_session.begin():
        user = db_session.get(User, user_id)

        assert user is not None

        if account_change == "email":
            user.email = "changed@example.com"
            user.normalized_email = "changed@example.com"

        elif account_change == "password":
            user.password_hash = hash_password("A different secure passphrase #9274")

        elif account_change == "status":
            user.status = "suspended"

        elif account_change == "forced_reset":
            user.password_reset_required = True

        else:
            user.display_name = "Updated Display Name"

        db_session.flush()

        assert user.updated_at != state.updated_at

    delivered_token = generate_token()

    assert (
        commit_recovery(
            db_session,
            state=state,
            raw_token=delivered_token,
        )
        is False
    )

    with db_session.begin():
        tokens = db_session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "password_reset",
            )
        ).all()

        assert len(tokens) == 1
        assert tokens[0].id == previous_token_id
        assert tokens[0].revoked_at is None

        audit_events = db_session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_reset_issued",
            )
        ).all()

        assert audit_events == []

    with pytest.raises(InvalidPasswordResetTokenError):
        reset_user_password(
            db_session,
            token=delivered_token,
            new_password="Another secure recovery passphrase #9274",
        )


def test_password_recovery_preserves_newer_administrator_token(
    db_session: Session,
) -> None:
    """A delayed email must not replace a newer administrator token."""
    administrator_id = create_account(
        db_session,
        email="administrator@example.com",
        system_role="administrator",
    )

    user_id = create_account(db_session)
    state = prepare_recovery(db_session)

    administrator_token, _ = issue_password_reset_token(
        db_session,
        actor_id=administrator_id,
        user_id=user_id,
        expiry_minutes=30,
    )

    delivered_token = generate_token()

    assert (
        commit_recovery(
            db_session,
            state=state,
            raw_token=delivered_token,
        )
        is False
    )

    with db_session.begin():
        tokens = db_session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "password_reset",
            )
        ).all()

        assert len(tokens) == 1
        assert tokens[0].token_hash == hash_token(administrator_token)
        assert tokens[0].revoked_at is None
        assert tokens[0].consumed_at is None

        audit_events = db_session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_reset_issued",
            )
        ).all()

        assert len(audit_events) == 1
        assert audit_events[0].actor_user_id == administrator_id


def test_competing_password_recovery_rejects_stale_state(
    db_session: Session,
) -> None:
    """Only one delivery may commit against the same captured state."""
    user_id = create_account(db_session)

    first_state = prepare_recovery(db_session)
    second_state = prepare_recovery(db_session)

    first_token = generate_token()
    second_token = generate_token()

    assert first_state == second_state

    assert (
        commit_recovery(
            db_session,
            state=first_state,
            raw_token=first_token,
        )
        is True
    )

    assert (
        commit_recovery(
            db_session,
            state=second_state,
            raw_token=second_token,
        )
        is False
    )

    with db_session.begin():
        tokens = db_session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "password_reset",
            )
        ).all()

        assert len(tokens) == 1
        assert tokens[0].token_hash == hash_token(first_token)
        assert tokens[0].revoked_at is None


def test_password_recovery_rejects_consumed_previous_token(
    db_session: Session,
) -> None:
    """A completed password reset invalidates pending delivery state."""
    user_id = create_account(db_session)

    existing_token = generate_token()

    existing_token_id = seed_reset_token(
        db_session,
        user_id=user_id,
        raw_token=existing_token,
    )

    state = prepare_recovery(db_session)

    reset_user_password(
        db_session,
        token=existing_token,
        new_password="Another secure recovery passphrase #9274",
    )

    assert (
        commit_recovery(
            db_session,
            state=state,
            raw_token=generate_token(),
        )
        is False
    )

    with db_session.begin():
        tokens = db_session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "password_reset",
            )
        ).all()

        assert len(tokens) == 1
        assert tokens[0].id == existing_token_id
        assert tokens[0].consumed_at is not None


@pytest.mark.parametrize("expiry_minutes", [0, -1])
def test_password_recovery_rejects_invalid_expiry(
    db_session: Session,
    expiry_minutes: int,
) -> None:
    """Reject nonpositive reset-token expiry configuration."""
    create_account(db_session)
    state = prepare_recovery(db_session)

    with pytest.raises(
        ValueError,
        match="Password-reset expiry must be positive",
    ):
        commit_recovery(
            db_session,
            state=state,
            raw_token=generate_token(),
            expiry_minutes=expiry_minutes,
        )


def test_password_recovery_rolls_back_on_transaction_failure(
    db_session: Session,
) -> None:
    """Failed persistence preserves the previous recovery credential."""
    user_id = create_account(db_session)

    previous_token_id = seed_reset_token(
        db_session,
        user_id=user_id,
        raw_token=generate_token(),
    )

    state = prepare_recovery(db_session)
    delivered_token = generate_token()

    def fail_after_flush(
        _session: Session,
        _flush_context: object,
    ) -> None:
        raise RuntimeError("Simulated password-recovery persistence failure")

    event.listen(
        db_session,
        "after_flush_postexec",
        fail_after_flush,
    )

    try:
        with pytest.raises(
            RuntimeError,
            match="Simulated password-recovery persistence failure",
        ):
            commit_recovery(
                db_session,
                state=state,
                raw_token=delivered_token,
            )

    finally:
        event.remove(
            db_session,
            "after_flush_postexec",
            fail_after_flush,
        )

    with db_session.begin():
        tokens = db_session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "password_reset",
            )
        ).all()

        assert len(tokens) == 1
        assert tokens[0].id == previous_token_id
        assert tokens[0].revoked_at is None
        assert tokens[0].consumed_at is None

        audit_events = db_session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_reset_issued",
            )
        ).all()

        assert audit_events == []


def test_password_recovery_does_not_restore_suspended_account(
    db_session: Session,
) -> None:
    """Recovering a password must not reactivate a suspended account."""
    user_id = create_account(
        db_session,
        status="suspended",
        password_reset_required=True,
    )

    state = prepare_recovery(db_session)
    raw_token = generate_token()

    assert (
        commit_recovery(
            db_session,
            state=state,
            raw_token=raw_token,
        )
        is True
    )

    reset_user_password(
        db_session,
        token=raw_token,
        new_password="Another secure recovery passphrase #9274",
    )

    with db_session.begin():
        user = db_session.get(User, user_id)

        assert user is not None
        assert user.status == "suspended"
        assert user.password_reset_required is False
