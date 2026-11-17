"""HTTP integration tests for user session listing."""

from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session
from uuid6 import uuid7

from restling_server.users.models import User
from restling_server.users.passwords import hash_password


def create_login(
    api_client: TestClient,
    test_engine: Engine,
) -> dict[str, str]:
    """Create an account and obtain real HTTP credentials."""
    email = f"sessions-{uuid7().hex}@example.com"
    password = "A secure session test passphrase #8472"

    with Session(test_engine) as session:
        session.add(
            User(
                email=email,
                normalized_email=email,
                display_name="Session Test User",
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

    return {
        "email": email,
        "password": password,
        **response.json()["data"],
    }


def test_list_my_active_sessions(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """List two sessions and identify the requesting session."""
    first = create_login(api_client, test_engine)

    second_response = api_client.post(
        "/api/v1/auth/login",
        json={
            "email": first["email"],
            "password": first["password"],
        },
    )
    assert second_response.status_code == 200

    second = second_response.json()["data"]

    response = api_client.get(
        "/api/v1/users/me/sessions",
        headers={"Authorization": f"Bearer {first['access_token']}"},
    )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"

    sessions = response.json()["data"]

    assert len(sessions) == 2
    assert {item["session_id"] for item in sessions} == {
        first["session_id"],
        second["session_id"],
    }

    current = [item for item in sessions if item["is_current"]]

    assert len(current) == 1
    assert current[0]["session_id"] == first["session_id"]

    for item in sessions:
        assert item["created_at"]
        assert item["expires_at"]
        assert "refresh_token" not in item
        assert "access_token" not in item


def test_session_listing_requires_authentication(
    api_client: TestClient,
) -> None:
    """Unauthenticated requests cannot list sessions."""
    for headers in (
        {},
        {"Authorization": "Bearer invalid-token"},
    ):
        response = api_client.get(
            "/api/v1/users/me/sessions",
            headers=headers,
        )

        assert response.status_code == 401
        assert response.json()["error"]["code"] == "UNAUTHORIZED"


def test_session_listing_excludes_other_users(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """A user cannot view another user's login sessions."""
    first = create_login(api_client, test_engine)
    second = create_login(api_client, test_engine)

    response = api_client.get(
        "/api/v1/users/me/sessions",
        headers={"Authorization": f"Bearer {first['access_token']}"},
    )

    assert response.status_code == 200

    session_ids = {item["session_id"] for item in response.json()["data"]}

    assert first["session_id"] in session_ids
    assert second["session_id"] not in session_ids
