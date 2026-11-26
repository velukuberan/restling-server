"""Integration tests for the authenticated password-change endpoint."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select
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
from restling_server.users.tokens import generate_token, hash_token

EMAIL = "password-change@example.com"
PASSWORD = "A secure current password passphrase #8472"
NEW_PASSWORD = "A secure replacement passphrase #9274"
ENDPOINT = "/api/v1/auth/change-password"


def create_account(
    engine: Engine,
    *,
    email: str = EMAIL,
    password: str = PASSWORD,
) -> UUID:
    """Persist an active account for API testing."""
    with Session(engine) as session:
        with session.begin():
            user = User(
                email=email,
                normalized_email=email.casefold(),
                display_name="Password Change API Test User",
                status="active",
                system_role="user",
                password_hash=hash_password(password),
            )

            session.add(user)
            session.flush()

            user_id = user.id

    return user_id


def login(
    client: TestClient,
    *,
    email: str = EMAIL,
    password: str = PASSWORD,
) -> tuple[str, str]:
    """Authenticate through the actual login endpoint."""
    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": password,
        },
    )

    assert response.status_code == 200

    data = response.json()["data"]

    access_token = data["access_token"]
    refresh_token = data["refresh_token"]

    assert isinstance(access_token, str)
    assert isinstance(refresh_token, str)

    return access_token, refresh_token


def test_change_password_revokes_all_sessions_and_credentials(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Successful password change invalidates existing credentials."""
    user_id = create_account(test_engine)

    first_access_token, first_refresh_token = login(api_client)
    second_access_token, second_refresh_token = login(api_client)

    raw_reset_token = generate_token()
    raw_email_change_token = generate_token()

    now = datetime.now(UTC)

    with Session(test_engine) as session:
        with session.begin():
            session.add_all(
                [
                    OneTimeToken(
                        user_id=user_id,
                        purpose="password_reset",
                        token_hash=hash_token(raw_reset_token),
                        created_at=now,
                        expires_at=now + timedelta(minutes=30),
                    ),
                    OneTimeToken(
                        user_id=user_id,
                        purpose="email_change",
                        token_hash=hash_token(raw_email_change_token),
                        pending_email="changed@example.com",
                        created_at=now,
                        expires_at=now + timedelta(minutes=30),
                    ),
                ]
            )

    response = api_client.post(
        ENDPOINT,
        headers={
            "Authorization": f"Bearer {first_access_token}",
        },
        json={
            "current_password": PASSWORD,
            "new_password": NEW_PASSWORD,
        },
    )

    assert response.status_code == 204
    assert response.content == b""
    assert response.headers["cache-control"] == "no-store"

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.password_hash is not None
        assert user.password_hash.startswith("$argon2id$")
        assert verify_password(
            NEW_PASSWORD,
            user.password_hash,
        )
        assert not verify_password(
            PASSWORD,
            user.password_hash,
        )

        assert user.status == "active"
        assert user.password_reset_required is False
        assert user.email == EMAIL

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

        one_time_tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
            )
        ).all()

        assert len(one_time_tokens) == 2

        for token in one_time_tokens:
            assert token.revoked_at is not None
            assert token.consumed_at is None

        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_changed",
            )
        ).all()

        assert len(audit_events) == 1
        assert audit_events[0].actor_user_id == user_id
        assert audit_events[0].event_metadata == {}

    # Both previous access credentials must be unusable.
    for access_token in (
        first_access_token,
        second_access_token,
    ):
        profile_response = api_client.get(
            "/api/v1/users/me",
            headers={
                "Authorization": f"Bearer {access_token}",
            },
        )

        assert profile_response.status_code == 401

    # Both previous refresh credentials must be unusable.
    for refresh_token in (
        first_refresh_token,
        second_refresh_token,
    ):
        refresh_response = api_client.post(
            "/api/v1/auth/refresh",
            json={
                "refresh_token": refresh_token,
            },
        )

        assert refresh_response.status_code == 401

    # The previously issued reset credential must be unusable.
    reset_response = api_client.post(
        "/api/v1/auth/reset-password",
        json={
            "token": raw_reset_token,
            "new_password": "Another secure replacement password #1234",
        },
    )

    assert reset_response.status_code == 400

    assert reset_response.json()["error"]["code"] == ("INVALID_PASSWORD_RESET_TOKEN")

    # The previously issued email-change credential must be unusable.
    verification_response = api_client.post(
        "/api/v1/auth/verify-email-change",
        json={
            "token": raw_email_change_token,
        },
    )

    assert verification_response.status_code == 400

    assert verification_response.json()["error"]["code"] == (
        "INVALID_EMAIL_CHANGE_TOKEN"
    )

    # The original password must no longer authenticate.
    old_login = api_client.post(
        "/api/v1/auth/login",
        json={
            "email": EMAIL,
            "password": PASSWORD,
        },
    )

    assert old_login.status_code == 401

    # A new login using the replacement password must succeed.
    new_access_token, _ = login(
        api_client,
        password=NEW_PASSWORD,
    )

    profile_response = api_client.get(
        "/api/v1/users/me",
        headers={
            "Authorization": f"Bearer {new_access_token}",
        },
    )

    assert profile_response.status_code == 200
    assert profile_response.json()["data"]["id"] == str(user_id)


@pytest.mark.parametrize(
    "authorization",
    [
        None,
        "Basic invalid-credentials",
        "Bearer invalid-access-token",
    ],
)
def test_change_password_requires_authentication(
    api_client: TestClient,
    authorization: str | None,
) -> None:
    """Password changes require a valid bearer credential."""
    headers: dict[str, str] = {}

    if authorization is not None:
        headers["Authorization"] = authorization

    response = api_client.post(
        ENDPOINT,
        headers=headers,
        json={
            "current_password": PASSWORD,
            "new_password": NEW_PASSWORD,
        },
    )

    assert response.status_code == 401

    assert response.json() == {
        "error": {
            "code": "UNAUTHORIZED",
            "message": "Authentication is required.",
        }
    }

    assert response.headers["www-authenticate"] == "Bearer"
    assert response.headers["cache-control"] == "no-store"

    assert PASSWORD not in response.text
    assert NEW_PASSWORD not in response.text


@pytest.mark.parametrize(
    ("current_password", "new_password", "expected_status", "expected_code"),
    [
        (
            "An incorrect current password #1234",
            NEW_PASSWORD,
            401,
            "UNAUTHORIZED",
        ),
        (
            PASSWORD,
            "",
            422,
            "PASSWORD_POLICY_VIOLATION",
        ),
        (
            PASSWORD,
            "too short",
            422,
            "PASSWORD_POLICY_VIOLATION",
        ),
        (
            PASSWORD,
            "x" * 65,
            422,
            "PASSWORD_POLICY_VIOLATION",
        ),
        (
            PASSWORD,
            "passwordpassword",
            422,
            "PASSWORD_POLICY_VIOLATION",
        ),
        (
            PASSWORD,
            PASSWORD,
            422,
            "PASSWORD_UNCHANGED",
        ),
    ],
)
def test_rejected_password_change_preserves_account_state(
    api_client: TestClient,
    test_engine: Engine,
    current_password: str,
    new_password: str,
    expected_status: int,
    expected_code: str,
) -> None:
    """Rejected password changes preserve credentials and sessions."""
    user_id = create_account(test_engine)

    access_token, refresh_token = login(api_client)

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None

        original_password_hash = user.password_hash
        original_updated_at = user.updated_at

    response = api_client.post(
        ENDPOINT,
        headers={
            "Authorization": f"Bearer {access_token}",
        },
        json={
            "current_password": current_password,
            "new_password": new_password,
        },
    )

    assert response.status_code == expected_status
    assert response.json()["error"]["code"] == expected_code
    assert response.headers["cache-control"] == "no-store"

    if expected_status == 401:
        assert response.headers["www-authenticate"] == "Bearer"

    assert current_password not in response.text
    assert PASSWORD not in response.text

    if new_password:
        assert new_password not in response.text

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.password_hash == original_password_hash
        assert user.updated_at == original_updated_at

        login_session = session.scalar(
            select(LoginSession).where(
                LoginSession.user_id == user_id,
            )
        )

        assert login_session is not None
        assert login_session.revoked_at is None
        assert login_session.refresh_token_hash == hash_token(refresh_token)

        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_changed",
            )
        ).all()

        assert audit_events == []

    # The existing access credential remains usable.
    profile_response = api_client.get(
        "/api/v1/users/me",
        headers={
            "Authorization": f"Bearer {access_token}",
        },
    )

    assert profile_response.status_code == 200


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"current_password": PASSWORD},
        {"new_password": NEW_PASSWORD},
        {
            "current_password": "",
            "new_password": NEW_PASSWORD,
        },
        {
            "current_password": None,
            "new_password": NEW_PASSWORD,
        },
        {
            "current_password": PASSWORD,
            "new_password": None,
        },
        {
            "current_password": 12345,
            "new_password": NEW_PASSWORD,
        },
        {
            "current_password": PASSWORD,
            "new_password": 12345,
        },
        {
            "current_password": PASSWORD,
            "new_password": NEW_PASSWORD,
            "user_id": "unexpected-user-id",
        },
        {
            "current_password": PASSWORD,
            "new_password": NEW_PASSWORD,
            "confirm_password": NEW_PASSWORD,
        },
    ],
)
def test_change_password_rejects_invalid_request_body(
    api_client: TestClient,
    test_engine: Engine,
    payload: dict[str, object],
) -> None:
    """Invalid request bodies are rejected without exposing credentials."""
    user_id = create_account(test_engine)

    access_token, refresh_token = login(api_client)

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None

        original_password_hash = user.password_hash
        original_updated_at = user.updated_at

    response = api_client.post(
        ENDPOINT,
        headers={
            "Authorization": f"Bearer {access_token}",
        },
        json=payload,
    )

    assert response.status_code == 422

    assert response.json() == {
        "error": {
            "code": "VALIDATION_ERROR",
            "message": "Invalid request data.",
        }
    }

    assert response.headers["cache-control"] == "no-store"

    assert PASSWORD not in response.text
    assert NEW_PASSWORD not in response.text
    assert access_token not in response.text
    assert refresh_token not in response.text

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.password_hash == original_password_hash
        assert user.updated_at == original_updated_at

        login_session = session.scalar(
            select(LoginSession).where(
                LoginSession.user_id == user_id,
            )
        )

        assert login_session is not None
        assert login_session.revoked_at is None
        assert login_session.refresh_token_hash == hash_token(refresh_token)

        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_changed",
            )
        ).all()

        assert audit_events == []

    profile_response = api_client.get(
        "/api/v1/users/me",
        headers={
            "Authorization": f"Bearer {access_token}",
        },
    )

    assert profile_response.status_code == 200


def test_change_password_rejects_malformed_json(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Malformed JSON receives a sanitized validation response."""
    create_account(test_engine)

    access_token, _ = login(api_client)

    malformed_body = (
        f'{{"current_password": "{PASSWORD}", "new_password": "{NEW_PASSWORD}"'
    )

    response = api_client.post(
        ENDPOINT,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
        content=malformed_body,
    )

    assert response.status_code == 422

    assert response.json() == {
        "error": {
            "code": "VALIDATION_ERROR",
            "message": "Invalid request data.",
        }
    }

    assert response.headers["cache-control"] == "no-store"

    assert PASSWORD not in response.text
    assert NEW_PASSWORD not in response.text
    assert access_token not in response.text

    profile_response = api_client.get(
        "/api/v1/users/me",
        headers={
            "Authorization": f"Bearer {access_token}",
        },
    )

    assert profile_response.status_code == 200


@pytest.mark.parametrize(
    "credential_state",
    [
        "expired_access_token",
        "expired_session",
        "revoked_session",
        "suspended_account",
        "password_reset_required",
    ],
)
def test_change_password_rejects_ineligible_authentication(
    api_client: TestClient,
    test_engine: Engine,
    credential_state: str,
) -> None:
    """Ineligible accounts and credentials cannot change passwords."""
    user_id = create_account(test_engine)

    access_token, _ = login(api_client)

    now = datetime.now(UTC)

    with Session(test_engine) as session:
        with session.begin():
            user = session.get(User, user_id)

            assert user is not None

            login_session = session.scalar(
                select(LoginSession).where(
                    LoginSession.user_id == user_id,
                )
            )

            assert login_session is not None

            stored_access_token = session.scalar(
                select(AccessToken).where(
                    AccessToken.token_hash == hash_token(access_token),
                )
            )

            assert stored_access_token is not None

            if credential_state == "expired_access_token":
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

            session.flush()

            original_password_hash = user.password_hash
            original_updated_at = user.updated_at
            original_status = user.status
            original_reset_required = user.password_reset_required

            original_revoked_at = login_session.revoked_at
            original_refresh_hash = login_session.refresh_token_hash
            original_revocation_reason = login_session.revocation_reason

            session_id = login_session.id

    response = api_client.post(
        ENDPOINT,
        headers={
            "Authorization": f"Bearer {access_token}",
        },
        json={
            "current_password": PASSWORD,
            "new_password": NEW_PASSWORD,
        },
    )

    assert response.status_code == 401

    assert response.json() == {
        "error": {
            "code": "UNAUTHORIZED",
            "message": "Authentication is required.",
        }
    }

    assert response.headers["www-authenticate"] == "Bearer"
    assert response.headers["cache-control"] == "no-store"

    assert PASSWORD not in response.text
    assert NEW_PASSWORD not in response.text
    assert access_token not in response.text

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.password_hash == original_password_hash
        assert user.updated_at == original_updated_at
        assert user.status == original_status
        assert user.password_reset_required == original_reset_required

        login_session = session.get(
            LoginSession,
            session_id,
        )

        assert login_session is not None
        assert login_session.revoked_at == original_revoked_at
        assert login_session.refresh_token_hash == original_refresh_hash
        assert login_session.revocation_reason == original_revocation_reason

        audit_events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.password_changed",
            )
        ).all()

        assert audit_events == []
