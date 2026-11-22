"""HTTP integration tests for token refresh and logout."""

from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session
from uuid6 import uuid7

from restling_server.users.models import User
from restling_server.users.passwords import hash_password


def login_test_user(
    api_client: TestClient,
    test_engine: Engine,
) -> dict[str, str]:
    """Create a real user and log in through HTTP."""
    email = f"refresh-{uuid7().hex}@example.com"
    password = "A secure refresh passphrase #8472"

    with Session(test_engine) as session:
        session.add(
            User(
                email=email,
                normalized_email=email,
                display_name="Refresh Test User",
                status="active",
                system_role="user",
                password_hash=hash_password(password),
            )
        )
        session.commit()

    response = api_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )

    assert response.status_code == 200
    return response.json()["data"]


def profile_status(
    api_client: TestClient,
    access_token: str,
) -> int:
    """Return profile HTTP status for an access credential."""
    response = api_client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    return response.status_code


def test_refresh_rotates_credentials(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Refresh rotates tokens without extending session lifetime."""
    original = login_test_user(api_client, test_engine)

    response = api_client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": original["refresh_token"]},
    )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"

    refreshed = response.json()["data"]

    assert refreshed["session_id"] == original["session_id"]
    assert refreshed["refresh_expires_at"] == original["refresh_expires_at"]
    assert refreshed["access_token"] != original["access_token"]
    assert refreshed["refresh_token"] != original["refresh_token"]
    assert refreshed["token_type"] == "Bearer"
    assert 0 < refreshed["expires_in"] <= 900

    assert profile_status(api_client, refreshed["access_token"]) == 200


def test_refresh_replay_revokes_session(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Reusing a consumed refresh token revokes its session."""
    original = login_test_user(api_client, test_engine)

    first_refresh = api_client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": original["refresh_token"]},
    )
    assert first_refresh.status_code == 200

    rotated = first_refresh.json()["data"]

    replay = api_client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": original["refresh_token"]},
    )

    assert replay.status_code == 401
    assert replay.json()["error"]["code"] == "INVALID_REFRESH_TOKEN"

    assert profile_status(api_client, rotated["access_token"]) == 401

    # The latest refresh token must also be unusable.
    retry = api_client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": rotated["refresh_token"]},
    )
    assert retry.status_code == 401


def test_logout_revokes_session(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Logout immediately invalidates access and refresh tokens."""
    login = login_test_user(api_client, test_engine)

    assert profile_status(api_client, login["access_token"]) == 200

    logout = api_client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {login['access_token']}"},
    )

    assert logout.status_code == 204
    assert logout.content == b""
    assert logout.headers["cache-control"] == "no-store"

    assert profile_status(api_client, login["access_token"]) == 401

    refresh = api_client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": login["refresh_token"]},
    )
    assert refresh.status_code == 401


def test_logout_rejects_missing_or_invalid_token(
    api_client: TestClient,
) -> None:
    """Logout requires an active access credential."""
    for headers in (
        {},
        {"Authorization": "Bearer invalid-token"},
    ):
        response = api_client.post(
            "/api/v1/auth/logout",
            headers=headers,
        )

        assert response.status_code == 401
        assert response.json()["error"]["code"] == "UNAUTHORIZED"
        assert response.headers["cache-control"] == "no-store"


def test_refresh_rejects_invalid_input(
    api_client: TestClient,
) -> None:
    """Refresh requires a nonempty token and rejects unknown fields."""
    for payload in (
        {},
        {"refresh_token": ""},
        {"refresh_token": "invalid", "unexpected": True},
    ):
        response = api_client.post(
            "/api/v1/auth/refresh",
            json=payload,
        )

        assert response.status_code == 422

    invalid_token = api_client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": "invalid"},
    )

    assert invalid_token.status_code == 401
    assert invalid_token.json()["error"]["code"] == "INVALID_REFRESH_TOKEN"
