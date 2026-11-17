"""HTTP integration tests for user session listing."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session
from uuid6 import uuid7

from restling_server.users.models import LoginSession, User
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


def test_session_history_filters_and_pagination(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Show active, revoked and expired sessions with stable paging."""
    first = create_login(api_client, test_engine)

    credentials = {
        "email": first["email"],
        "password": first["password"],
    }

    def new_login() -> dict[str, str]:
        response = api_client.post(
            "/api/v1/auth/login",
            json=credentials,
        )
        assert response.status_code == 200
        return response.json()["data"]

    second = new_login()

    logout = api_client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {second['access_token']}"},
    )
    assert logout.status_code == 204

    third = new_login()

    with Session(test_engine) as session:
        expired = session.get(
            LoginSession,
            UUID(third["session_id"]),
        )
        assert expired is not None

        now = datetime.now(UTC)
        expired.created_at = now - timedelta(days=8)
        expired.expires_at = now - timedelta(days=1)
        session.commit()

    fourth = new_login()

    headers = {"Authorization": f"Bearer {first['access_token']}"}
    url = "/api/v1/users/me/sessions"

    response = api_client.get(url, headers=headers)

    assert response.status_code == 200

    body = response.json()
    assert body["pagination"] == {
        "limit": 25,
        "offset": 0,
        "total": 4,
    }

    sessions = body["data"]

    assert [item["status"] for item in sessions] == [
        "active",
        "active",
        "revoked",
        "expired",
    ]

    assert {item["session_id"] for item in sessions} == {
        first["session_id"],
        second["session_id"],
        third["session_id"],
        fourth["session_id"],
    }

    current = [item for item in sessions if item["is_current"]]
    assert len(current) == 1
    assert current[0]["session_id"] == first["session_id"]

    for status, expected_id in (
        ("revoked", second["session_id"]),
        ("expired", third["session_id"]),
    ):
        filtered = api_client.get(
            url,
            params={"status": status},
            headers=headers,
        )

        assert filtered.status_code == 200
        assert filtered.json()["pagination"]["total"] == 1
        assert filtered.json()["data"][0]["session_id"] == expected_id

    first_page = api_client.get(
        url,
        params={"limit": 1, "offset": 0},
        headers=headers,
    )
    second_page = api_client.get(
        url,
        params={"limit": 1, "offset": 1},
        headers=headers,
    )

    assert first_page.status_code == 200
    assert second_page.status_code == 200

    assert first_page.json()["pagination"]["total"] == 4
    assert second_page.json()["pagination"]["total"] == 4

    assert (
        first_page.json()["data"][0]["session_id"]
        != second_page.json()["data"][0]["session_id"]
    )


def test_session_history_validates_query_parameters(
    api_client: TestClient,
) -> None:
    """Reject unsupported filters and invalid pagination values."""
    url = "/api/v1/users/me/sessions"

    for params in (
        {"status": "unknown"},
        {"limit": 0},
        {"limit": 101},
        {"offset": -1},
    ):
        response = api_client.get(url, params=params)

        assert response.status_code == 422
        assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_delete_owned_session_preserves_history(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Revoking another session preserves the caller and history."""
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

    first_headers = {"Authorization": f"Bearer {first['access_token']}"}
    second_headers = {"Authorization": f"Bearer {second['access_token']}"}

    url = f"/api/v1/users/me/sessions/{second['session_id']}"

    deleted = api_client.delete(url, headers=first_headers)

    assert deleted.status_code == 204
    assert deleted.content == b""

    # The target credentials must immediately stop working.
    rejected = api_client.get(
        "/api/v1/users/me",
        headers=second_headers,
    )
    assert rejected.status_code == 401

    # The caller remains authenticated.
    profile = api_client.get(
        "/api/v1/users/me",
        headers=first_headers,
    )
    assert profile.status_code == 200

    # The revoked session remains visible in history.
    history = api_client.get(
        "/api/v1/users/me/sessions",
        params={"status": "revoked"},
        headers=first_headers,
    )

    assert history.status_code == 200
    assert second["session_id"] in {
        item["session_id"] for item in history.json()["data"]
    }

    # Revoking the same owned session again succeeds.
    repeated = api_client.delete(url, headers=first_headers)

    assert repeated.status_code == 204


def test_delete_session_rejects_unknown_target(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Unknown session identifiers must not be revocable."""
    login = create_login(api_client, test_engine)

    response = api_client.delete(
        f"/api/v1/users/me/sessions/{uuid7()}",
        headers={"Authorization": f"Bearer {login['access_token']}"},
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "SESSION_NOT_FOUND"


def test_delete_current_session_invalidates_access(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """A user may revoke their own current session."""
    login = create_login(api_client, test_engine)

    headers = {"Authorization": f"Bearer {login['access_token']}"}

    response = api_client.delete(
        f"/api/v1/users/me/sessions/{login['session_id']}",
        headers=headers,
    )

    assert response.status_code == 204

    profile = api_client.get(
        "/api/v1/users/me",
        headers=headers,
    )

    assert profile.status_code == 401
