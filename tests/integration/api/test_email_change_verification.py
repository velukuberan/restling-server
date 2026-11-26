"""Integration tests for email-change verification."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from threading import Barrier
from typing import cast
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
from uuid6 import uuid7

from restling_server.core.config import Settings
from restling_server.main import app
from restling_server.users.models import (
    AuditLog,
    LoginSession,
    OneTimeToken,
    User,
)
from restling_server.users.passwords import hash_password
from restling_server.users.tokens import hash_token


def test_valid_token_verifies_email_change(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """A valid token changes the login email and revokes sessions."""
    key = uuid7().hex
    old_email = f"old-{key}@example.com"
    new_email = f"new-{key}@example.com"
    password = "A secure email verification test passphrase"
    raw_token = f"email-verification-{key}"
    now = datetime.now(UTC)

    with Session(test_engine) as session:
        user = User(
            email=old_email,
            normalized_email=old_email,
            display_name="Email Verification Test User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )
        session.add(user)
        session.flush()
        user_id = user.id

        session.add(
            OneTimeToken(
                user_id=user_id,
                purpose="email_change",
                token_hash=hash_token(raw_token),
                pending_email=new_email,
                created_at=now,
                expires_at=now + timedelta(minutes=30),
            )
        )
        session.commit()

    login = api_client.post(
        "/api/v1/auth/login",
        json={"email": old_email, "password": password},
    )
    assert login.status_code == 200

    response = api_client.post(
        "/api/v1/auth/verify-email-change",
        json={"token": raw_token},
    )

    assert response.status_code == 200

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.email == new_email
        assert user.normalized_email == new_email

        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.email_change.verified",
            )
        ).all()

        assert len(audit_events) == 1
        assert audit_events[0].actor_user_id == user_id

        stored_token = session.scalar(
            select(OneTimeToken).where(
                OneTimeToken.token_hash == hash_token(raw_token),
            )
        )

        assert stored_token is not None
        assert stored_token.consumed_at is not None
        assert stored_token.revoked_at is None

        login_sessions = session.scalars(
            select(LoginSession).where(
                LoginSession.user_id == user_id,
            )
        ).all()

        assert len(login_sessions) == 1
        assert login_sessions[0].revoked_at is not None
        assert login_sessions[0].refresh_token_hash is None

    # A consumed verification token must not be reusable.
    replay_response = api_client.post(
        "/api/v1/auth/verify-email-change",
        json={"token": raw_token},
    )

    assert replay_response.status_code == 400
    assert replay_response.json()["error"]["code"] == "INVALID_EMAIL_CHANGE_TOKEN"


def test_expired_email_change_token_is_rejected(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """An expired token cannot change a user's email."""
    key = uuid7().hex
    old_email = f"expired-old-{key}@example.com"
    new_email = f"expired-new-{key}@example.com"
    raw_token = f"expired-verification-{key}"

    now = datetime.now(UTC)

    with Session(test_engine) as session:
        user = User(
            email=old_email,
            normalized_email=old_email,
            display_name="Expired Token Test User",
            status="active",
            system_role="user",
            password_hash=hash_password(
                "A secure expired verification test passphrase"
            ),
        )
        session.add(user)
        session.flush()

        user_id = user.id

        session.add(
            OneTimeToken(
                user_id=user_id,
                purpose="email_change",
                token_hash=hash_token(raw_token),
                pending_email=new_email,
                created_at=now - timedelta(minutes=60),
                expires_at=now - timedelta(minutes=30),
            )
        )
        session.commit()

    response = api_client.post(
        "/api/v1/auth/verify-email-change",
        json={"token": raw_token},
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_EMAIL_CHANGE_TOKEN"

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.email == old_email
        assert user.normalized_email == old_email

        stored_token = session.scalar(
            select(OneTimeToken).where(
                OneTimeToken.token_hash == hash_token(raw_token),
            )
        )

        assert stored_token is not None
        assert stored_token.consumed_at is None
        assert stored_token.revoked_at is None


def test_revoked_email_change_token_is_rejected(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """A revoked token cannot change a user's email."""
    key = uuid7().hex
    old_email = f"revoked-old-{key}@example.com"
    new_email = f"revoked-new-{key}@example.com"
    raw_token = f"revoked-verification-{key}"
    now = datetime.now(UTC)

    with Session(test_engine) as session:
        user = User(
            email=old_email,
            normalized_email=old_email,
            display_name="Revoked Token Test User",
            status="active",
            system_role="user",
            password_hash=hash_password(
                "A secure revoked verification test passphrase"
            ),
        )
        session.add(user)
        session.flush()

        user_id = user.id

        session.add(
            OneTimeToken(
                user_id=user_id,
                purpose="email_change",
                token_hash=hash_token(raw_token),
                pending_email=new_email,
                created_at=now,
                expires_at=now + timedelta(minutes=30),
                revoked_at=now,
            )
        )
        session.commit()

    response = api_client.post(
        "/api/v1/auth/verify-email-change",
        json={"token": raw_token},
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_EMAIL_CHANGE_TOKEN"

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.email == old_email
        assert user.normalized_email == old_email

        stored_token = session.scalar(
            select(OneTimeToken).where(
                OneTimeToken.token_hash == hash_token(raw_token),
            )
        )

        assert stored_token is not None
        assert stored_token.revoked_at is not None
        assert stored_token.consumed_at is None


@pytest.mark.parametrize(
    ("status", "password_reset_required"),
    [
        ("suspended", False),
        ("active", True),
    ],
)
def test_ineligible_account_cannot_verify_email_change(
    api_client: TestClient,
    test_engine: Engine,
    status: str,
    password_reset_required: bool,
) -> None:
    """Ineligible accounts cannot complete email verification."""
    key = uuid7().hex
    old_email = f"ineligible-old-{key}@example.com"
    new_email = f"ineligible-new-{key}@example.com"
    raw_token = f"ineligible-verification-{key}"
    now = datetime.now(UTC)

    with Session(test_engine) as session:
        user = User(
            email=old_email,
            normalized_email=old_email,
            display_name="Ineligible Verification Test User",
            status=status,
            system_role="user",
            password_hash=hash_password("A secure account eligibility test passphrase"),
            password_reset_required=password_reset_required,
        )

        session.add(user)
        session.flush()
        user_id = user.id

        session.add(
            OneTimeToken(
                user_id=user_id,
                purpose="email_change",
                token_hash=hash_token(raw_token),
                pending_email=new_email,
                created_at=now,
                expires_at=now + timedelta(minutes=30),
            )
        )
        session.commit()

    response = api_client.post(
        "/api/v1/auth/verify-email-change",
        json={"token": raw_token},
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_EMAIL_CHANGE_TOKEN"

    with Session(test_engine) as session:
        stored_user = session.get(User, user_id)

        assert stored_user is not None
        assert stored_user.email == old_email
        assert stored_user.normalized_email == old_email

        stored_token = session.scalar(
            select(OneTimeToken).where(
                OneTimeToken.token_hash == hash_token(raw_token),
            )
        )

        assert stored_token is not None
        assert stored_token.consumed_at is None
        assert stored_token.revoked_at is None


def test_concurrent_email_change_verification_allows_one_success(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Concurrent verification of one token succeeds only once."""
    key = uuid7().hex
    old_email = f"concurrent-old-{key}@example.com"
    new_email = f"concurrent-new-{key}@example.com"
    raw_token = f"concurrent-verification-{key}"
    now = datetime.now(UTC)

    with Session(test_engine) as session:
        user = User(
            email=old_email,
            normalized_email=old_email,
            display_name="Concurrent Verification Test User",
            status="active",
            system_role="user",
            password_hash=hash_password("A secure concurrent verification passphrase"),
        )
        session.add(user)
        session.flush()
        user_id = user.id

        session.add(
            OneTimeToken(
                user_id=user_id,
                purpose="email_change",
                token_hash=hash_token(raw_token),
                pending_email=new_email,
                created_at=now,
                expires_at=now + timedelta(minutes=30),
            )
        )
        session.commit()

    barrier = Barrier(2)

    def verify() -> int:
        barrier.wait()

        response = api_client.post(
            "/api/v1/auth/verify-email-change",
            json={"token": raw_token},
        )
        return response.status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(verify)
        second = executor.submit(verify)

        results = [first.result(), second.result()]

    assert sorted(results) == [200, 400]

    with Session(test_engine) as session:
        stored_user = session.get(User, user_id)

        assert stored_user is not None
        assert stored_user.email == new_email
        assert stored_user.normalized_email == new_email

        stored_token = session.scalar(
            select(OneTimeToken).where(
                OneTimeToken.token_hash == hash_token(raw_token),
            )
        )

        assert stored_token is not None
        assert stored_token.consumed_at is not None
        assert stored_token.revoked_at is None


def test_email_change_verification_rejects_email_claimed_by_another_user(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Verification rejects an email acquired after token issuance."""
    key = uuid7().hex
    old_email = f"original-{key}@example.com"
    new_email = f"claimed-{key}@example.com"
    raw_token = f"claimed-verification-{key}"
    now = datetime.now(UTC)

    with Session(test_engine) as session:
        original_user = User(
            email=old_email,
            normalized_email=old_email,
            display_name="Original Email Owner",
            status="active",
            system_role="user",
            password_hash=hash_password(
                "A secure original user verification passphrase"
            ),
        )
        session.add(original_user)
        session.flush()
        original_user_id = original_user.id

        session.add(
            OneTimeToken(
                user_id=original_user_id,
                purpose="email_change",
                token_hash=hash_token(raw_token),
                pending_email=new_email,
                created_at=now,
                expires_at=now + timedelta(minutes=30),
            )
        )

        # Another user acquires the requested address before verification.
        other_user = User(
            email=new_email,
            normalized_email=new_email,
            display_name="New Email Owner",
            status="active",
            system_role="user",
            password_hash=hash_password("A secure other user verification passphrase"),
        )
        session.add(other_user)
        session.commit()

    response = api_client.post(
        "/api/v1/auth/verify-email-change",
        json={"token": raw_token},
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "EMAIL_ALREADY_EXISTS"

    with Session(test_engine) as session:
        stored_user = session.get(User, original_user_id)

        assert stored_user is not None
        assert stored_user.email == old_email
        assert stored_user.normalized_email == old_email

        stored_token = session.scalar(
            select(OneTimeToken).where(
                OneTimeToken.token_hash == hash_token(raw_token),
            )
        )

        assert stored_token is not None
        assert stored_token.consumed_at is None
        assert stored_token.revoked_at is None

        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == original_user_id,
                AuditLog.action == "user.email_change.verified",
            )
        ).all()

        assert audit_events == []


def test_concurrent_users_cannot_claim_same_email(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Only one user can acquire an email during concurrent verification."""
    key = uuid7().hex
    shared_email = f"shared-{key}@example.com"
    now = datetime.now(UTC)

    users: list[tuple[str, str]] = []

    with Session(test_engine) as session:
        for index in range(2):
            original_email = f"user-{index}-{key}@example.com"
            raw_token = f"verification-{index}-{key}"

            user = User(
                email=original_email,
                normalized_email=original_email,
                display_name=f"Concurrent Email User {index}",
                status="active",
                system_role="user",
                password_hash=hash_password(
                    "A secure concurrent email ownership passphrase"
                ),
            )
            session.add(user)
            session.flush()

            session.add(
                OneTimeToken(
                    user_id=user.id,
                    purpose="email_change",
                    token_hash=hash_token(raw_token),
                    pending_email=shared_email,
                    created_at=now,
                    expires_at=now + timedelta(minutes=30),
                )
            )

            users.append((original_email, raw_token))

        session.commit()

    for original_email, _ in users:
        login_response = api_client.post(
            "/api/v1/auth/login",
            json={
                "email": original_email,
                "password": "A secure concurrent email ownership passphrase",
            },
        )

        assert login_response.status_code == 200

    barrier = Barrier(2)

    def verify(raw_token: str) -> int:
        barrier.wait()

        response = api_client.post(
            "/api/v1/auth/verify-email-change",
            json={"token": raw_token},
        )

        return response.status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(verify, raw_token) for _, raw_token in users]

        results = [future.result() for future in futures]

    assert sorted(results) == [200, 409]

    with Session(test_engine) as session:
        stored_users = session.scalars(
            select(User).where(
                User.email.in_(
                    [original_email for original_email, _ in users] + [shared_email]
                )
            )
        ).all()

        shared_email_owners = [
            user for user in stored_users if user.email == shared_email
        ]

        assert len(shared_email_owners) == 1

        unchanged_users = [user for user in stored_users if user.email != shared_email]

        assert len(unchanged_users) == 1

        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.token_hash.in_(
                    [hash_token(raw_token) for _, raw_token in users]
                )
            )
        ).all()

        assert len(tokens) == 2

        consumed_tokens = [token for token in tokens if token.consumed_at is not None]

        assert len(consumed_tokens) == 1
        assert consumed_tokens[0].user_id == shared_email_owners[0].id

        unconsumed_tokens = [token for token in tokens if token.consumed_at is None]

        assert len(unconsumed_tokens) == 1
        assert unconsumed_tokens[0].revoked_at is None

        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.action == "user.email_change.verified",
                AuditLog.target_user_id.in_([token.user_id for token in tokens]),
            )
        ).all()

        assert len(audit_events) == 1
        assert audit_events[0].target_user_id == shared_email_owners[0].id
        assert audit_events[0].actor_user_id == shared_email_owners[0].id

        login_sessions = session.scalars(
            select(LoginSession).where(
                LoginSession.user_id.in_([token.user_id for token in tokens]),
            )
        ).all()

        assert len(login_sessions) == 2

        winning_user_id = shared_email_owners[0].id

        for login_session in login_sessions:
            if login_session.user_id == winning_user_id:
                assert login_session.revoked_at is not None
                assert login_session.revocation_reason == "email_change"
                assert login_session.refresh_token_hash is None
            else:
                assert login_session.revoked_at is None
                assert login_session.revocation_reason is None
                assert login_session.refresh_token_hash is not None


def test_successful_email_change_revokes_other_pending_tokens(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Confirming one email change invalidates other pending email-change links."""
    key = uuid7().hex
    original_email = f"pending-original-{key}@example.com"
    verified_email = f"pending-verified-{key}@example.com"
    alternate_email = f"pending-alternate-{key}@example.com"
    verified_token = f"pending-verified-token-{key}"
    alternate_token = f"pending-alternate-token-{key}"
    now = datetime.now(UTC)

    with Session(test_engine) as session:
        user = User(
            email=original_email,
            normalized_email=original_email,
            display_name="Multiple Pending Email Tokens User",
            status="active",
            system_role="user",
            password_hash=hash_password("A secure multiple email tokens passphrase"),
        )
        session.add(user)
        session.flush()
        user_id = user.id

        for raw_token, pending_email in (
            (verified_token, verified_email),
            (alternate_token, alternate_email),
        ):
            session.add(
                OneTimeToken(
                    user_id=user_id,
                    purpose="email_change",
                    token_hash=hash_token(raw_token),
                    pending_email=pending_email,
                    created_at=now,
                    expires_at=now + timedelta(minutes=30),
                )
            )

        session.commit()

    response = api_client.post(
        "/api/v1/auth/verify-email-change",
        json={"token": verified_token},
    )
    assert response.status_code == 200

    with Session(test_engine) as session:
        stored_user = session.get(User, user_id)
        assert stored_user is not None
        assert stored_user.email == verified_email
        assert stored_user.normalized_email == verified_email

        tokens_by_hash = {
            token.token_hash: token
            for token in session.scalars(
                select(OneTimeToken).where(
                    OneTimeToken.user_id == user_id,
                    OneTimeToken.purpose == "email_change",
                )
            ).all()
        }

        confirmed = tokens_by_hash[hash_token(verified_token)]
        alternate = tokens_by_hash[hash_token(alternate_token)]

        assert confirmed.consumed_at is not None
        assert confirmed.revoked_at is None
        assert alternate.consumed_at is None
        assert alternate.revoked_at is not None

    rejected_response = api_client.post(
        "/api/v1/auth/verify-email-change",
        json={"token": alternate_token},
    )
    assert rejected_response.status_code == 400
    assert rejected_response.json()["error"]["code"] == "INVALID_EMAIL_CHANGE_TOKEN"

    with Session(test_engine) as session:
        stored_user = session.get(User, user_id)
        assert stored_user is not None
        assert stored_user.email == verified_email


def test_email_change_succeeds_when_old_email_notification_fails(
    api_client: TestClient,
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SMTP failure must not undo a verified email change."""
    key = uuid7().hex
    old_email = f"notification-old-{key}@example.com"
    new_email = f"notification-new-{key}@example.com"
    raw_token = f"notification-verification-{key}"
    now = datetime.now(UTC)

    with Session(test_engine) as session:
        user = User(
            email=old_email,
            normalized_email=old_email,
            display_name="Notification Failure Test User",
            status="active",
            system_role="user",
            password_hash=hash_password(
                "A secure notification failure test passphrase"
            ),
        )
        session.add(user)
        session.flush()

        user_id = user.id

        session.add(
            OneTimeToken(
                user_id=user_id,
                purpose="email_change",
                token_hash=hash_token(raw_token),
                pending_email=new_email,
                created_at=now,
                expires_at=now + timedelta(minutes=30),
            )
        )
        session.commit()

    settings = cast(Settings, app.state.settings)
    monkeypatch.setattr(settings, "smtp_host", "127.0.0.1")
    monkeypatch.setattr(settings, "smtp_from_email", "no-reply@example.com")
    monkeypatch.setattr(settings, "smtp_security", "none")

    with patch(
        "smtplib.SMTP",
        side_effect=OSError("SMTP unavailable"),
    ) as mock_smtp:
        response = api_client.post(
            "/api/v1/auth/verify-email-change",
            json={"token": raw_token},
        )

    # Notification delivery was attempted, even though SMTP failed.
    mock_smtp.assert_called_once()

    # Verification itself must remain successful.
    assert response.status_code == 200

    with Session(test_engine) as session:
        stored_user = session.get(User, user_id)

        assert stored_user is not None
        assert stored_user.email == new_email
        assert stored_user.normalized_email == new_email

        stored_token = session.scalar(
            select(OneTimeToken).where(
                OneTimeToken.token_hash == hash_token(raw_token),
            )
        )

        assert stored_token is not None
        assert stored_token.consumed_at is not None
        assert stored_token.revoked_at is None

        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.email_change.verified",
            )
        ).all()

        assert len(audit_events) == 1


def test_email_change_notifies_previous_email_address(
    api_client: TestClient,
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Successful verification notifies the previous email address."""
    key = uuid7().hex
    old_email = f"previous-{key}@example.com"
    new_email = f"updated-{key}@example.com"
    raw_token = f"notification-token-{key}"
    now = datetime.now(UTC)

    with Session(test_engine) as session:
        user = User(
            email=old_email,
            normalized_email=old_email,
            display_name="Email Notification Test User",
            status="active",
            system_role="user",
            password_hash=hash_password("A secure email notification test passphrase"),
        )
        session.add(user)
        session.flush()
        user_id = user.id

        session.add(
            OneTimeToken(
                user_id=user_id,
                purpose="email_change",
                token_hash=hash_token(raw_token),
                pending_email=new_email,
                created_at=now,
                expires_at=now + timedelta(minutes=30),
            )
        )
        session.commit()

    settings = cast(Settings, app.state.settings)
    monkeypatch.setattr(settings, "smtp_host", "127.0.0.1")
    monkeypatch.setattr(settings, "smtp_from_email", "no-reply@example.com")
    monkeypatch.setattr(settings, "smtp_security", "none")

    def check_database_before_sending(_message: EmailMessage) -> None:
        """The email change must already be committed before SMTP delivery."""
        with Session(test_engine) as db_session:
            stored_user = db_session.get(User, user_id)

            assert stored_user is not None
            assert stored_user.email == new_email
            assert stored_user.normalized_email == new_email

            stored_token = db_session.scalar(
                select(OneTimeToken).where(
                    OneTimeToken.token_hash == hash_token(raw_token),
                )
            )

            assert stored_token is not None
            assert stored_token.consumed_at is not None

            audit_events = db_session.scalars(
                select(AuditLog).where(
                    AuditLog.target_user_id == user_id,
                    AuditLog.action == "user.email_change.verified",
                )
            ).all()

            assert len(audit_events) == 1

    with patch("smtplib.SMTP") as mock_smtp:
        smtp_connection = mock_smtp.return_value.__enter__.return_value
        smtp_connection.send_message.side_effect = check_database_before_sending

        response = api_client.post(
            "/api/v1/auth/verify-email-change",
            json={"token": raw_token},
        )

    assert response.status_code == 200

    smtp_connection = mock_smtp.return_value.__enter__.return_value
    smtp_connection.send_message.assert_called_once()

    message = smtp_connection.send_message.call_args.args[0]

    assert message["To"] == old_email
    assert message["From"] == "no-reply@example.com"
    assert new_email in message.get_content()

    # The notification must not disclose the verification credential.
    assert raw_token not in message.get_content()

    with Session(test_engine) as session:
        stored_user = session.get(User, user_id)

        assert stored_user is not None
        assert stored_user.email == new_email
        assert stored_user.normalized_email == new_email


@pytest.mark.parametrize(
    "token_state",
    ["active", "expired", "consumed", "revoked"],
)
def test_verified_email_change_invalidates_outstanding_password_reset(
    api_client: TestClient,
    test_engine: Engine,
    token_state: str,
) -> None:
    """Email changes revoke outstanding reset credentials."""
    key = uuid7().hex
    old_email = f"reset-old-{key}@example.com"
    new_email = f"reset-new-{key}@example.com"
    password = "A secure email change recovery passphrase"
    raw_verification_token = f"email-verification-{key}"
    raw_reset_token = f"password-reset-{key}"

    now = datetime.now(UTC)
    created_at = now - timedelta(minutes=10)
    expires_at = now + timedelta(minutes=20)

    consumed_at = None
    revoked_at = None

    if token_state == "expired":
        created_at = now - timedelta(minutes=60)
        expires_at = now - timedelta(minutes=30)

    elif token_state == "consumed":
        consumed_at = now - timedelta(minutes=5)

    elif token_state == "revoked":
        revoked_at = now - timedelta(minutes=5)

    with Session(test_engine) as session:
        user = User(
            email=old_email,
            normalized_email=old_email,
            display_name="Password Reset Revocation Test User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )

        session.add(user)
        session.flush()

        user_id = user.id

        verification_token = OneTimeToken(
            user_id=user_id,
            purpose="email_change",
            token_hash=hash_token(raw_verification_token),
            pending_email=new_email,
            created_at=now,
            expires_at=now + timedelta(minutes=30),
        )

        reset_token = OneTimeToken(
            user_id=user_id,
            purpose="password_reset",
            token_hash=hash_token(raw_reset_token),
            created_at=created_at,
            expires_at=expires_at,
            consumed_at=consumed_at,
            revoked_at=revoked_at,
        )

        session.add_all(
            [
                verification_token,
                reset_token,
            ]
        )

        session.flush()

        verification_token_id = verification_token.id
        reset_token_id = reset_token.id

        session.commit()

    response = api_client.post(
        "/api/v1/auth/verify-email-change",
        json={"token": raw_verification_token},
    )

    assert response.status_code == 200

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.email == new_email
        assert user.normalized_email == new_email

        stored_verification = session.get(
            OneTimeToken,
            verification_token_id,
        )

        assert stored_verification is not None
        assert stored_verification.consumed_at is not None
        assert stored_verification.revoked_at is None

        stored_reset = session.get(
            OneTimeToken,
            reset_token_id,
        )

        assert stored_reset is not None
        assert stored_reset.token_hash == hash_token(raw_reset_token)
        assert stored_reset.created_at == created_at
        assert stored_reset.expires_at == expires_at
        assert stored_reset.consumed_at == consumed_at

        if token_state in ("active", "expired"):
            assert stored_reset.revoked_at is not None
            assert stored_reset.revoked_at == stored_verification.consumed_at

        else:
            # Previously consumed or revoked credentials must
            # retain their historical lifecycle information.
            assert stored_reset.revoked_at == revoked_at

    reset_response = api_client.post(
        "/api/v1/auth/reset-password",
        json={
            "token": raw_reset_token,
            "new_password": "Another secure recovery passphrase #9274",
        },
    )

    assert reset_response.status_code == 400

    assert reset_response.json()["error"]["code"] == ("INVALID_PASSWORD_RESET_TOKEN")


def test_failed_email_change_preserves_password_reset_credential(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Failed verification must not revoke an existing reset credential."""
    key = uuid7().hex
    old_email = f"failed-old-{key}@example.com"
    new_email = f"failed-new-{key}@example.com"

    raw_verification_token = f"expired-verification-{key}"
    raw_reset_token = f"valid-password-reset-{key}"

    now = datetime.now(UTC)

    with Session(test_engine) as session:
        user = User(
            email=old_email,
            normalized_email=old_email,
            display_name="Failed Email Change Recovery Test User",
            status="active",
            system_role="user",
            password_hash=hash_password("A secure failed verification passphrase"),
        )

        session.add(user)
        session.flush()

        user_id = user.id

        verification_token = OneTimeToken(
            user_id=user_id,
            purpose="email_change",
            token_hash=hash_token(raw_verification_token),
            pending_email=new_email,
            created_at=now - timedelta(minutes=60),
            expires_at=now - timedelta(minutes=30),
        )

        reset_token = OneTimeToken(
            user_id=user_id,
            purpose="password_reset",
            token_hash=hash_token(raw_reset_token),
            created_at=now,
            expires_at=now + timedelta(minutes=30),
        )

        session.add_all(
            [
                verification_token,
                reset_token,
            ]
        )

        session.flush()

        reset_token_id = reset_token.id

        session.commit()

    response = api_client.post(
        "/api/v1/auth/verify-email-change",
        json={"token": raw_verification_token},
    )

    assert response.status_code == 400

    assert response.json()["error"]["code"] == ("INVALID_EMAIL_CHANGE_TOKEN")

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.email == old_email
        assert user.normalized_email == old_email

        stored_reset = session.get(
            OneTimeToken,
            reset_token_id,
        )

        assert stored_reset is not None
        assert stored_reset.revoked_at is None
        assert stored_reset.consumed_at is None

    # The existing reset credential must remain usable.
    reset_response = api_client.post(
        "/api/v1/auth/reset-password",
        json={
            "token": raw_reset_token,
            "new_password": "Another secure recovery passphrase #9274",
        },
    )

    assert reset_response.status_code == 200
