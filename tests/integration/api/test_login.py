"""HTTP integration tests for password login."""

from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session
from uuid6 import uuid7

from restling_server.users.models import User
from restling_server.users.passwords import hash_password


def create_test_user(
    engine: Engine,
    *,
    email: str,
    password: str,
    status: str = "active",
) -> None:
    """Persist a test account with genuine password hashing."""
    with Session(engine) as session:
        user = User(
            email=email,
            normalized_email=email,
            display_name="Login Test User",
            status=status,
            system_role="user",
            password_hash=(hash_password(password) if status != "pending" else None),
        )

        session.add(user)
        session.commit()


def test_login_returns_credentials(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Successful login creates usable access credentials."""
    email = f"login-{uuid7().hex}@example.com"
    password = "A secure login passphrase #8472"

    create_test_user(
        test_engine,
        email=email,
        password=password,
    )

    response = api_client.post(
        "/api/v1/auth/login",
        json={
            "email": email.upper(),
            "password": password,
        },
    )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"

    data = response.json()["data"]

    assert data["token_type"] == "Bearer"
    assert data["expires_in"] == 900
    assert data["access_token"]
    assert data["refresh_token"]
    assert data["access_token"] != data["refresh_token"]
    assert data["session_id"]
    assert data["refresh_expires_at"]

    profile_response = api_client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {data['access_token']}"},
    )

    assert profile_response.status_code == 200
    assert profile_response.json()["data"]["email"] == email


def test_login_rejects_invalid_credentials(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Unknown users and incorrect passwords are rejected generically."""
    email = f"invalid-{uuid7().hex}@example.com"
    password = "Another secure passphrase #8472"

    create_test_user(
        test_engine,
        email=email,
        password=password,
    )

    for attempted_email, attempted_password in (
        (email, "incorrect-password"),
        ("unknown@example.com", password),
    ):
        response = api_client.post(
            "/api/v1/auth/login",
            json={
                "email": attempted_email,
                "password": attempted_password,
            },
        )

        assert response.status_code == 401
        assert response.headers["cache-control"] == "no-store"
        assert response.json() == {
            "error": {
                "code": "INVALID_CREDENTIALS",
                "message": "Invalid email address or password.",
            }
        }


def test_login_rejects_pending_account(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Pending accounts cannot authenticate."""
    email = f"pending-{uuid7().hex}@example.com"

    create_test_user(
        test_engine,
        email=email,
        password="A secure pending passphrase #8472",
        status="pending",
    )

    response = api_client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": "A secure pending passphrase #8472",
        },
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "INVALID_CREDENTIALS"


def test_login_enforces_session_limit(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """A third login cannot exceed the configured two-session limit."""
    email = f"limit-{uuid7().hex}@example.com"
    password = "A secure session passphrase #8472"

    create_test_user(
        test_engine,
        email=email,
        password=password,
    )

    credentials = {
        "email": email,
        "password": password,
    }

    first = api_client.post("/api/v1/auth/login", json=credentials)
    second = api_client.post("/api/v1/auth/login", json=credentials)
    third = api_client.post("/api/v1/auth/login", json=credentials)

    assert first.status_code == 200
    assert second.status_code == 200
    assert third.status_code == 409

    assert third.json()["error"]["code"] == "SESSION_LIMIT_REACHED"
    assert third.headers["cache-control"] == "no-store"

    assert first.json()["data"]["session_id"] != second.json()["data"]["session_id"]


def test_login_validates_request_body(
    api_client: TestClient,
) -> None:
    """Malformed or unsupported login input is rejected."""
    response = api_client.post(
        "/api/v1/auth/login",
        json={"email": "user@example.com"},
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"

    unsupported_field = api_client.post(
        "/api/v1/auth/login",
        json={
            "email": "user@example.com",
            "password": "A secure test passphrase #8472",
            "machine_name": "not-supported-yet",
        },
    )

    assert unsupported_field.status_code == 422
