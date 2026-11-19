"""HTTP integration tests for self-service profile updates."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session
from uuid6 import uuid7

from restling_server.users.models import AuditLog, User
from restling_server.users.passwords import hash_password


def test_user_can_update_own_profile(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """An authenticated user can update editable profile fields."""
    key = uuid7().hex
    password = "A secure profile update test passphrase"
    email = f"profile-update-{key}@example.com"

    with Session(test_engine) as session:
        user = User(
            email=email,
            normalized_email=email,
            display_name="Original Name",
            job_title="Original Job",
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

    response = api_client.patch(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {access_token}"},
        json={
            "display_name": "  Updated Name  ",
            "job_title": "  Senior Backend Engineer  ",
        },
    )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"

    profile = response.json()["data"]

    assert profile["id"] == str(user_id)
    assert profile["display_name"] == "Updated Name"
    assert profile["job_title"] == "Senior Backend Engineer"
    assert profile["email"] == email
    assert profile["system_role"] == "user"
    assert profile["status"] == "active"

    with Session(test_engine) as session:
        updated_user = session.get(User, user_id)

        assert updated_user is not None
        assert updated_user.display_name == "Updated Name"
        assert updated_user.job_title == "Senior Backend Engineer"
        assert updated_user.email == email
        assert updated_user.system_role == "user"

    # Capture the timestamp after the successful update.
    with Session(test_engine) as session:
        updated_user = session.get(User, user_id)
        assert updated_user is not None
        updated_at = updated_user.updated_at

        events = session.scalars(
            select(AuditLog).where(
                AuditLog.actor_user_id == user_id,
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.profile.updated",
            )
        ).all()

        assert len(events) == 1
        assert events[0].event_metadata["changed_fields"] == [
            "display_name",
            "job_title",
        ]

    # Repeating an identical update must not modify the account.
    repeated = api_client.patch(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {access_token}"},
        json={
            "display_name": "Updated Name",
            "job_title": "Senior Backend Engineer",
        },
    )

    assert repeated.status_code == 200

    with Session(test_engine) as session:
        unchanged_user = session.get(User, user_id)
        assert unchanged_user is not None
        assert unchanged_user.updated_at == updated_at

        events = session.scalars(
            select(AuditLog).where(
                AuditLog.actor_user_id == user_id,
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.profile.updated",
            )
        ).all()

        assert len(events) == 1


def test_profile_update_supports_partial_changes_and_null(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Omitted fields stay unchanged and null clears the job title."""
    key = uuid7().hex
    password = "A secure partial profile update test passphrase"
    email = f"profile-partial-{key}@example.com"

    with Session(test_engine) as session:
        user = User(
            email=email,
            normalized_email=email,
            display_name="Original Name",
            job_title="Backend Engineer",
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

    headers = {"Authorization": f"Bearer {login.json()['data']['access_token']}"}

    # Update only the display name.
    response = api_client.patch(
        "/api/v1/users/me",
        headers=headers,
        json={"display_name": "Updated Name"},
    )

    assert response.status_code == 200
    assert response.json()["data"]["display_name"] == "Updated Name"
    assert response.json()["data"]["job_title"] == "Backend Engineer"

    # Explicit null clears the optional job title.
    response = api_client.patch(
        "/api/v1/users/me",
        headers=headers,
        json={"job_title": None},
    )

    assert response.status_code == 200
    assert response.json()["data"]["display_name"] == "Updated Name"
    assert response.json()["data"]["job_title"] is None

    # Verify both changes persisted.
    with Session(test_engine) as session:
        updated_user = session.get(User, user_id)

        assert updated_user is not None
        assert updated_user.display_name == "Updated Name"
        assert updated_user.job_title is None


def test_empty_profile_update_does_not_modify_account(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """An empty PATCH succeeds without changing the account."""
    key = uuid7().hex
    password = "A secure empty profile update test passphrase"
    email = f"profile-empty-{key}@example.com"

    with Session(test_engine) as session:
        user = User(
            email=email,
            normalized_email=email,
            display_name="Original Name",
            job_title="Backend Engineer",
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

    response = api_client.patch(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {login.json()['data']['access_token']}"},
        json={},
    )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"

    profile = response.json()["data"]
    assert profile["display_name"] == "Original Name"
    assert profile["job_title"] == "Backend Engineer"

    with Session(test_engine) as session:
        unchanged_user = session.get(User, user_id)

        assert unchanged_user is not None
        assert unchanged_user.display_name == "Original Name"
        assert unchanged_user.job_title == "Backend Engineer"
        assert unchanged_user.updated_at == original_updated_at


@pytest.mark.parametrize(
    "protected_field",
    [
        "email",
        "system_role",
        "status",
        "password_reset_required",
    ],
)
def test_profile_update_rejects_protected_fields_atomically(
    api_client: TestClient,
    test_engine: Engine,
    protected_field: str,
) -> None:
    """An unsupported field rejects the entire profile update."""
    key = uuid7().hex
    password = "A secure profile validation test passphrase"
    email = f"profile-protected-{key}@example.com"

    with Session(test_engine) as session:
        user = User(
            email=email,
            normalized_email=email,
            display_name="Original Name",
            job_title="Backend Engineer",
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

    response = api_client.patch(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {login.json()['data']['access_token']}"},
        json={
            "display_name": "Updated Name",
            protected_field: "unexpected-value",
        },
    )

    assert response.status_code == 422

    # Even the valid display_name change must be rejected.
    with Session(test_engine) as session:
        unchanged_user = session.get(User, user_id)

        assert unchanged_user is not None
        assert unchanged_user.display_name == "Original Name"
        assert unchanged_user.job_title == "Backend Engineer"
        assert unchanged_user.email == email
        assert unchanged_user.status == "active"
        assert unchanged_user.system_role == "user"
        assert unchanged_user.password_reset_required is False
        assert unchanged_user.updated_at == original_updated_at


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer invalid-token"},
    ],
)
def test_profile_update_requires_authentication(
    api_client: TestClient,
    headers: dict[str, str],
) -> None:
    """Missing or invalid credentials cannot update a profile."""
    response = api_client.patch(
        "/api/v1/users/me",
        headers=headers,
        json={"display_name": "Unauthorized Change"},
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"
    assert response.headers["cache-control"] == "no-store"
