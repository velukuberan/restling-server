"""Integration tests for self-service email-change requests."""

from datetime import UTC, datetime, timedelta
from typing import cast
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from pydantic import AnyHttpUrl
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session
from uuid6 import uuid7

from restling_server.core.config import Settings
from restling_server.main import app
from restling_server.users.models import AuditLog, LoginSession, OneTimeToken, User
from restling_server.users.passwords import hash_password
from restling_server.users.tokens import hash_token


def test_email_change_requires_authentication(
    api_client: TestClient,
) -> None:
    """An unauthenticated user cannot request an email change."""
    response = api_client.post(
        "/api/v1/users/me/email-change",
        json={
            "email": "new@example.com",
            "current_password": "A secure test passphrase",
        },
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"


def test_email_change_rejects_incorrect_password(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """A valid access token is insufficient without the current password."""
    email = f"email-change-{uuid7().hex}@example.com"
    password = "A secure email change test passphrase"

    with Session(test_engine) as session:
        user = User(
            email=email,
            normalized_email=email,
            display_name="Test User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )

        session.add(user)
        session.commit()

        user_id = user.id

    login = api_client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": password,
        },
    )

    assert login.status_code == 200

    access_token = login.json()["data"]["access_token"]

    response = api_client.post(
        "/api/v1/users/me/email-change",
        headers={
            "Authorization": f"Bearer {access_token}",
        },
        json={
            "email": "new@example.com",
            "current_password": "An incorrect password",
        },
    )

    assert response.status_code == 401

    with Session(test_engine) as session:
        unchanged_user = session.get(User, user_id)

        assert unchanged_user is not None
        assert unchanged_user.email == email


def test_suspended_user_cannot_request_email_change(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """A suspended user cannot change their email using an existing token."""
    email = f"email-change-suspended-{uuid7().hex}@example.com"
    password = "A secure suspended account test passphrase"

    # Create an active user.
    with Session(test_engine) as session:
        user = User(
            email=email,
            normalized_email=email,
            display_name="Suspended Test User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )
        session.add(user)
        session.commit()

        user_id = user.id

    # Log in while the account is active.
    login = api_client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": password,
        },
    )

    assert login.status_code == 200

    access_token = login.json()["data"]["access_token"]

    # Suspend the account after login.
    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None

        user.status = "suspended"
        session.commit()

    # Attempt email change using the existing access token.
    response = api_client.post(
        "/api/v1/users/me/email-change",
        headers={
            "Authorization": f"Bearer {access_token}",
        },
        json={
            "email": "new@example.com",
            "current_password": password,
        },
    )

    assert response.status_code == 401

    # Confirm that the account email remains unchanged.
    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.email == email
        assert user.normalized_email == email


def test_password_reset_required_blocks_email_change(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """An account requiring a password reset cannot request an email change."""
    email = f"email-change-reset-{uuid7().hex}@example.com"
    password = "A secure password reset restriction test passphrase"

    with Session(test_engine) as session:
        user = User(
            email=email,
            normalized_email=email,
            display_name="Password Reset Test User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )
        session.add(user)
        session.commit()

        user_id = user.id

    # Authenticate before the password-reset restriction is applied.
    login = api_client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": password,
        },
    )

    assert login.status_code == 200

    access_token = login.json()["data"]["access_token"]

    # Administrator requires a password reset after login.
    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None

        user.password_reset_required = True
        session.commit()

    response = api_client.post(
        "/api/v1/users/me/email-change",
        headers={"Authorization": f"Bearer {access_token}"},
        json={
            "email": "new@example.com",
            "current_password": password,
        },
    )

    assert response.status_code == 401

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.email == email
        assert user.normalized_email == email


def test_revoked_session_cannot_request_email_change(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Logging out invalidates access to the email-change operation."""
    email = f"email-change-revoked-{uuid7().hex}@example.com"
    password = "A secure revoked session test passphrase"

    with Session(test_engine) as session:
        user = User(
            email=email,
            normalized_email=email,
            display_name="Revoked Session Test User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )
        session.add(user)
        session.commit()

        user_id = user.id

    login = api_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )

    assert login.status_code == 200

    access_token = login.json()["data"]["access_token"]

    headers = {"Authorization": f"Bearer {access_token}"}

    # Revoke the authenticated session.
    logout = api_client.post(
        "/api/v1/auth/logout",
        headers=headers,
    )

    assert logout.status_code == 204

    # The same access token must no longer authorize an email change.
    response = api_client.post(
        "/api/v1/users/me/email-change",
        headers=headers,
        json={
            "email": "new@example.com",
            "current_password": password,
        },
    )

    assert response.status_code == 401

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.email == email
        assert user.normalized_email == email


def test_same_email_change_is_no_op(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Requesting the existing email leaves account state unchanged."""
    email = f"email-change-noop-{uuid7().hex}@example.com"
    password = "A secure same email test passphrase"

    with Session(test_engine) as session:
        user = User(
            email=email,
            normalized_email=email,
            display_name="No-op Test User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )
        session.add(user)
        session.commit()

        user_id = user.id
        original_updated_at = user.updated_at

    login = api_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )

    assert login.status_code == 200

    access_token = login.json()["data"]["access_token"]

    response = api_client.post(
        "/api/v1/users/me/email-change",
        headers={"Authorization": f"Bearer {access_token}"},
        json={
            "email": f"  {email.upper()}  ",
            "current_password": password,
        },
    )

    assert response.status_code == 200

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.email == email
        assert user.normalized_email == email
        assert user.updated_at == original_updated_at

        token_count = session.scalar(
            select(func.count(OneTimeToken.id)).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "email_change",
            )
        )

        audit_count = session.scalar(
            select(func.count(AuditLog.id)).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.email_change.requested",
            )
        )

        active_sessions = session.scalar(
            select(func.count(LoginSession.id)).where(
                LoginSession.user_id == user_id,
                LoginSession.revoked_at.is_(None),
            )
        )

        assert token_count == 0
        assert audit_count == 0
        assert active_sessions == 1


def test_email_change_rejects_existing_email(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """An email owned by another user cannot be requested."""
    key = uuid7().hex
    first_email = f"first-{key}@example.com"
    second_email = f"second-{key}@example.com"
    password = "A secure duplicate email test passphrase"

    with Session(test_engine) as session:
        first_user = User(
            email=first_email,
            normalized_email=first_email,
            display_name="First User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )

        second_user = User(
            email=second_email,
            normalized_email=second_email,
            display_name="Second User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )

        session.add_all([first_user, second_user])
        session.commit()

        first_user_id = first_user.id

    login = api_client.post(
        "/api/v1/auth/login",
        json={
            "email": first_email,
            "password": password,
        },
    )

    assert login.status_code == 200

    access_token = login.json()["data"]["access_token"]

    response = api_client.post(
        "/api/v1/users/me/email-change",
        headers={"Authorization": f"Bearer {access_token}"},
        json={
            "email": second_email.upper(),
            "current_password": password,
        },
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "EMAIL_ALREADY_EXISTS"

    with Session(test_engine) as session:
        user = session.get(User, first_user_id)

        assert user is not None
        assert user.email == first_email
        assert user.normalized_email == first_email

        token_count = session.scalar(
            select(func.count(OneTimeToken.id)).where(
                OneTimeToken.user_id == first_user_id,
                OneTimeToken.purpose == "email_change",
            )
        )

        assert token_count == 0


def test_email_change_requires_smtp(
    api_client: TestClient,
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unavailable SMTP must not create an email-change credential."""
    email = f"email-change-no-smtp-{uuid7().hex}@example.com"
    password = "A secure SMTP prerequisite test passphrase"

    with Session(test_engine) as session:
        user = User(
            email=email,
            normalized_email=email,
            display_name="SMTP Test User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )
        session.add(user)
        session.commit()
        user_id = user.id

    login = api_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert login.status_code == 200

    settings = cast(Settings, app.state.settings)
    monkeypatch.setattr(settings, "smtp_host", None)
    monkeypatch.setattr(settings, "smtp_from_email", None)

    response = api_client.post(
        "/api/v1/users/me/email-change",
        headers={"Authorization": f"Bearer {login.json()['data']['access_token']}"},
        json={
            "email": "new@example.com",
            "current_password": password,
        },
    )

    assert response.status_code == 503
    assert response.headers["cache-control"] == "no-store"

    with Session(test_engine) as session:
        unchanged_user = session.get(User, user_id)

        assert unchanged_user is not None
        assert unchanged_user.email == email

        token_count = session.scalar(
            select(func.count(OneTimeToken.id)).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "email_change",
            )
        )

        assert token_count == 0


def test_smtp_failure_preserves_existing_email_change_token(
    api_client: TestClient,
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Failed SMTP delivery must preserve the previous verification token."""
    key = uuid7().hex
    email = f"email-change-smtp-failure-{key}@example.com"
    password = "A secure SMTP failure test passphrase"
    now = datetime.now(UTC) - timedelta(minutes=2)

    with Session(test_engine) as session:
        user = User(
            email=email,
            normalized_email=email,
            display_name="SMTP Failure Test User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )
        session.add(user)
        session.flush()

        user_id = user.id

        previous_token = OneTimeToken(
            user_id=user_id,
            purpose="email_change",
            token_hash=hash_token(f"previous-token-{key}"),
            pending_email="previous-new@example.com",
            created_at=now,
            expires_at=now + timedelta(minutes=30),
        )

        session.add(previous_token)
        session.commit()

        previous_token_id = previous_token.id

    login = api_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )

    assert login.status_code == 200

    settings = cast(Settings, app.state.settings)
    monkeypatch.setattr(settings, "smtp_host", "127.0.0.1")
    monkeypatch.setattr(settings, "smtp_from_email", "no-reply@example.com")
    monkeypatch.setattr(settings, "smtp_security", "none")

    # Simulate an external SMTP transport failure.
    with patch("smtplib.SMTP", side_effect=OSError("SMTP unavailable")):
        response = api_client.post(
            "/api/v1/users/me/email-change",
            headers={"Authorization": f"Bearer {login.json()['data']['access_token']}"},
            json={
                "email": f"replacement-{key}@example.com",
                "current_password": password,
            },
        )

    assert response.status_code == 503
    assert response.headers["cache-control"] == "no-store"

    with Session(test_engine) as session:
        user = session.get(User, user_id)
        previous_token = session.get(OneTimeToken, previous_token_id)

        assert user is not None
        assert user.email == email

        assert previous_token is not None
        assert previous_token.revoked_at is None
        assert previous_token.consumed_at is None
        assert previous_token.expires_at > datetime.now(UTC)

        token_count = session.scalar(
            select(func.count(OneTimeToken.id)).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "email_change",
            )
        )

        assert token_count == 1


def test_successful_email_change_request_issues_token(
    api_client: TestClient,
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A successful request issues a token without changing the login email."""
    key = uuid7().hex
    email = f"email-change-success-{key}@example.com"
    new_email = f"new-{key}@example.com"
    password = "A secure email change success test passphrase"

    with Session(test_engine) as session:
        user = User(
            email=email,
            normalized_email=email,
            display_name="Email Change Test User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )
        session.add(user)
        session.commit()
        user_id = user.id

    login = api_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )

    assert login.status_code == 200

    settings = cast(Settings, app.state.settings)
    monkeypatch.setattr(
        settings,
        "public_url",
        AnyHttpUrl("https://restling.example.com"),
    )
    monkeypatch.setattr(settings, "smtp_host", "127.0.0.1")
    monkeypatch.setattr(settings, "smtp_from_email", "no-reply@example.com")
    monkeypatch.setattr(settings, "smtp_security", "none")

    with patch("smtplib.SMTP") as mock_smtp:
        response = api_client.post(
            "/api/v1/users/me/email-change",
            headers={"Authorization": f"Bearer {login.json()['data']['access_token']}"},
            json={
                "email": new_email,
                "current_password": password,
            },
        )

    assert response.status_code == 200

    smtp_connection = mock_smtp.return_value.__enter__.return_value
    smtp_connection.send_message.assert_called_once()

    message = smtp_connection.send_message.call_args.args[0]
    assert message["To"] == new_email

    with Session(test_engine) as session:
        unchanged_user = session.get(User, user_id)

        assert unchanged_user is not None
        assert unchanged_user.email == email
        assert unchanged_user.normalized_email == email

        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "email_change",
            )
        ).all()

        assert len(tokens) == 1
        assert tokens[0].pending_email == new_email
        assert tokens[0].token_hash
        assert tokens[0].consumed_at is None
        assert tokens[0].revoked_at is None
        assert tokens[0].expires_at > datetime.now(UTC)


def test_successful_email_change_replaces_previous_token(
    api_client: TestClient,
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Successful delivery revokes the previous verification token."""
    key = uuid7().hex
    email = f"email-change-replace-{key}@example.com"
    new_email = f"replacement-{key}@example.com"
    password = "A secure token replacement test passphrase"
    now = datetime.now(UTC) - timedelta(minutes=2)

    with Session(test_engine) as session:
        user = User(
            email=email,
            normalized_email=email,
            display_name="Token Replacement Test User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )

        session.add(user)
        session.flush()

        user_id = user.id

        previous_token = OneTimeToken(
            user_id=user_id,
            purpose="email_change",
            token_hash=hash_token(f"previous-token-{key}"),
            pending_email=f"previous-{key}@example.com",
            created_at=now,
            expires_at=now + timedelta(minutes=30),
        )

        session.add(previous_token)
        session.commit()

        previous_token_id = previous_token.id

    login = api_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )

    assert login.status_code == 200

    settings = cast(Settings, app.state.settings)
    monkeypatch.setattr(
        settings,
        "public_url",
        AnyHttpUrl("https://restling.example.com"),
    )
    monkeypatch.setattr(settings, "smtp_host", "127.0.0.1")
    monkeypatch.setattr(settings, "smtp_from_email", "no-reply@example.com")
    monkeypatch.setattr(settings, "smtp_security", "none")

    with patch("smtplib.SMTP") as mock_smtp:
        response = api_client.post(
            "/api/v1/users/me/email-change",
            headers={"Authorization": f"Bearer {login.json()['data']['access_token']}"},
            json={
                "email": new_email,
                "current_password": password,
            },
        )

    assert response.status_code == 200

    smtp_connection = mock_smtp.return_value.__enter__.return_value
    smtp_connection.send_message.assert_called_once()

    with Session(test_engine) as session:
        previous_token = session.get(OneTimeToken, previous_token_id)

        assert previous_token is not None
        assert previous_token.revoked_at is not None
        assert previous_token.consumed_at is None

        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "email_change",
            )
        ).all()

        assert len(tokens) == 2

        active_tokens = [
            token
            for token in tokens
            if token.revoked_at is None
            and token.consumed_at is None
            and token.expires_at > datetime.now(UTC)
        ]

        assert len(active_tokens) == 1
        assert active_tokens[0].pending_email == new_email

        user = session.get(User, user_id)

        assert user is not None
        assert user.email == email
        assert user.normalized_email == email


def test_email_change_enforces_cooldown(
    api_client: TestClient,
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A second successful request within the cooldown is rejected."""
    key = uuid7().hex
    email = f"email-change-cooldown-{key}@example.com"
    password = "A secure email change cooldown test passphrase"

    with Session(test_engine) as session:
        user = User(
            email=email,
            normalized_email=email,
            display_name="Cooldown Test User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )
        session.add(user)
        session.commit()

        user_id = user.id

    login = api_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )

    assert login.status_code == 200

    settings = cast(Settings, app.state.settings)
    monkeypatch.setattr(
        settings,
        "public_url",
        AnyHttpUrl("https://restling.example.com"),
    )
    monkeypatch.setattr(settings, "smtp_host", "127.0.0.1")
    monkeypatch.setattr(settings, "smtp_from_email", "no-reply@example.com")
    monkeypatch.setattr(settings, "smtp_security", "none")
    monkeypatch.setattr(settings, "email_change_cooldown_seconds", 60)

    headers = {"Authorization": f"Bearer {login.json()['data']['access_token']}"}

    with patch("smtplib.SMTP"):
        first_response = api_client.post(
            "/api/v1/users/me/email-change",
            headers=headers,
            json={
                "email": f"first-{key}@example.com",
                "current_password": password,
            },
        )

        second_response = api_client.post(
            "/api/v1/users/me/email-change",
            headers=headers,
            json={
                "email": f"second-{key}@example.com",
                "current_password": password,
            },
        )

    assert first_response.status_code == 200
    assert second_response.status_code == 429
    assert second_response.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"

    with Session(test_engine) as session:
        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "email_change",
            )
        ).all()

        assert len(tokens) == 1
        assert tokens[0].pending_email == f"first-{key}@example.com"
        assert tokens[0].revoked_at is None


def test_email_change_enforces_hourly_limit(
    api_client: TestClient,
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject a sixth email-change request within one hour."""
    key = uuid7().hex
    email = f"email-change-hourly-{key}@example.com"
    password = "A secure hourly limit test passphrase"
    now = datetime.now(UTC)

    with Session(test_engine) as session:
        user = User(
            email=email,
            normalized_email=email,
            display_name="Hourly Limit Test User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )

        session.add(user)
        session.flush()
        user_id = user.id

        # Simulate five successful requests within the previous hour.
        for index in range(5):
            created_at = now - timedelta(minutes=10 + index)

            session.add(
                OneTimeToken(
                    user_id=user_id,
                    purpose="email_change",
                    token_hash=hash_token(f"hourly-{key}-{index}"),
                    pending_email=f"previous-{index}-{key}@example.com",
                    created_at=created_at,
                    expires_at=created_at + timedelta(minutes=30),
                    revoked_at=created_at + timedelta(seconds=30),
                )
            )

        session.commit()

    login = api_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )

    assert login.status_code == 200

    settings = cast(Settings, app.state.settings)
    monkeypatch.setattr(settings, "smtp_host", "127.0.0.1")
    monkeypatch.setattr(settings, "smtp_from_email", "no-reply@example.com")
    monkeypatch.setattr(settings, "smtp_security", "none")
    monkeypatch.setattr(settings, "email_change_cooldown_seconds", 60)
    monkeypatch.setattr(settings, "email_change_hourly_limit", 5)

    with patch("smtplib.SMTP") as mock_smtp:
        response = api_client.post(
            "/api/v1/users/me/email-change",
            headers={"Authorization": f"Bearer {login.json()['data']['access_token']}"},
            json={
                "email": f"new-{key}@example.com",
                "current_password": password,
            },
        )

    assert response.status_code == 429
    assert response.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"

    # An already-limited request should be rejected before SMTP.
    mock_smtp.assert_not_called()

    with Session(test_engine) as session:
        token_count = session.scalar(
            select(func.count(OneTimeToken.id)).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "email_change",
            )
        )

        assert token_count == 5


def test_email_change_can_retry_after_smtp_failure(
    api_client: TestClient,
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Failed SMTP delivery must not consume successful-request limits."""
    key = uuid7().hex
    email = f"email-change-retry-{key}@example.com"
    new_email = f"new-{key}@example.com"
    password = "A secure email change retry test passphrase"

    with Session(test_engine) as session:
        user = User(
            email=email,
            normalized_email=email,
            display_name="SMTP Retry Test User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )

        session.add(user)
        session.commit()

        user_id = user.id

    login = api_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )

    assert login.status_code == 200

    settings = cast(Settings, app.state.settings)
    monkeypatch.setattr(
        settings,
        "public_url",
        AnyHttpUrl("https://restling.example.com"),
    )
    monkeypatch.setattr(settings, "smtp_host", "127.0.0.1")
    monkeypatch.setattr(settings, "smtp_from_email", "no-reply@example.com")
    monkeypatch.setattr(settings, "smtp_security", "none")
    monkeypatch.setattr(settings, "email_change_cooldown_seconds", 60)
    monkeypatch.setattr(settings, "email_change_hourly_limit", 1)

    headers = {"Authorization": f"Bearer {login.json()['data']['access_token']}"}

    payload = {
        "email": new_email,
        "current_password": password,
    }

    # First attempt: SMTP delivery fails.
    with patch("smtplib.SMTP", side_effect=OSError("Connection refused")):
        failed_response = api_client.post(
            "/api/v1/users/me/email-change",
            headers=headers,
            json=payload,
        )

    assert failed_response.status_code == 503

    # Immediate retry: SMTP delivery succeeds.
    with patch("smtplib.SMTP") as mock_smtp:
        successful_response = api_client.post(
            "/api/v1/users/me/email-change",
            headers=headers,
            json=payload,
        )

    assert successful_response.status_code == 200

    smtp_connection = mock_smtp.return_value.__enter__.return_value
    smtp_connection.send_message.assert_called_once()

    with Session(test_engine) as session:
        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "email_change",
            )
        ).all()

        assert len(tokens) == 1
        assert tokens[0].pending_email == new_email
        assert tokens[0].revoked_at is None
        assert tokens[0].consumed_at is None

        user = session.get(User, user_id)

        assert user is not None
        assert user.email == email
