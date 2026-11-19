"""HTTP integration tests for administrator profile updates."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session
from uuid6 import uuid7

from restling_server.users.models import AuditLog, User
from restling_server.users.passwords import hash_password


def test_administrator_can_update_user_profile(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """An administrator can edit another user's profile."""
    key = uuid7().hex
    password = "A secure administrator profile test passphrase"

    admin_email = f"profile-admin-{key}@example.com"
    user_email = f"profile-target-{key}@example.com"

    with Session(test_engine) as session:
        administrator = User(
            email=admin_email,
            normalized_email=admin_email,
            display_name="Administrator",
            status="active",
            system_role="administrator",
            password_hash=hash_password(password),
        )
        target = User(
            email=user_email,
            normalized_email=user_email,
            display_name="Original Name",
            job_title="Original Job",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )

        session.add_all([administrator, target])
        session.commit()

        admin_id = administrator.id
        target_id = target.id

    login = api_client.post(
        "/api/v1/auth/login",
        json={"email": admin_email, "password": password},
    )
    assert login.status_code == 200

    response = api_client.patch(
        f"/api/v1/users/{target_id}",
        headers={"Authorization": f"Bearer {login.json()['data']['access_token']}"},
        json={
            "display_name": "  Updated Name  ",
            "job_title": "  Senior Engineer  ",
        },
    )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"

    access_token = login.json()["data"]["access_token"]

    profile = response.json()["data"]
    assert profile["id"] == str(target_id)
    assert profile["display_name"] == "Updated Name"
    assert profile["job_title"] == "Senior Engineer"
    assert profile["email"] == user_email
    assert profile["system_role"] == "user"

    with Session(test_engine) as session:
        updated_user = session.get(User, target_id)

        assert updated_user is not None
        assert updated_user.display_name == "Updated Name"
        assert updated_user.job_title == "Senior Engineer"
        assert updated_user.email == user_email

        events = session.scalars(
            select(AuditLog).where(
                AuditLog.actor_user_id == admin_id,
                AuditLog.target_user_id == target_id,
                AuditLog.action == "user.profile.updated",
            )
        ).all()

        assert len(events) == 1
        assert events[0].event_metadata["changed_fields"] == [
            "display_name",
            "job_title",
        ]

    # Capture the timestamp after the successful update.
    with Session(test_engine) as session:
        updated_target = session.get(User, target_id)
        assert updated_target is not None
        updated_at = updated_target.updated_at

    # Repeating the same update must not change the account.
    repeated = api_client.patch(
        f"/api/v1/users/{target_id}",
        headers={"Authorization": f"Bearer {access_token}"},
        json={
            "display_name": "Updated Name",
            "job_title": "Senior Engineer",
        },
    )

    assert repeated.status_code == 200

    with Session(test_engine) as session:
        unchanged_target = session.get(User, target_id)
        assert unchanged_target is not None
        assert unchanged_target.updated_at == updated_at

        events = session.scalars(
            select(AuditLog).where(
                AuditLog.actor_user_id == admin_id,
                AuditLog.target_user_id == target_id,
                AuditLog.action == "user.profile.updated",
            )
        ).all()

        assert len(events) == 1

    # An empty PATCH must not modify the target or create an audit event.
    empty_response = api_client.patch(
        f"/api/v1/users/{target_id}",
        headers={"Authorization": f"Bearer {access_token}"},
        json={},
    )

    assert empty_response.status_code == 200
    assert empty_response.headers["cache-control"] == "no-store"
    assert empty_response.json()["data"]["display_name"] == "Updated Name"
    assert empty_response.json()["data"]["job_title"] == "Senior Engineer"

    with Session(test_engine) as session:
        unchanged_target = session.get(User, target_id)

        assert unchanged_target is not None
        assert unchanged_target.updated_at == updated_at

        events = session.scalars(
            select(AuditLog).where(
                AuditLog.actor_user_id == admin_id,
                AuditLog.target_user_id == target_id,
                AuditLog.action == "user.profile.updated",
            )
        ).all()

        assert len(events) == 1

    # An administrator can also update their own profile by ID.
    self_update = api_client.patch(
        f"/api/v1/users/{admin_id}",
        headers={"Authorization": f"Bearer {access_token}"},
        json={"job_title": "Platform Administrator"},
    )

    assert self_update.status_code == 200
    assert self_update.json()["data"]["job_title"] == "Platform Administrator"

    with Session(test_engine) as session:
        administrator = session.get(User, admin_id)
        assert administrator is not None
        assert administrator.job_title == "Platform Administrator"
        assert administrator.system_role == "administrator"

        self_events = session.scalars(
            select(AuditLog).where(
                AuditLog.actor_user_id == admin_id,
                AuditLog.target_user_id == admin_id,
                AuditLog.action == "user.profile.updated",
            )
        ).all()

        assert len(self_events) == 1
        assert self_events[0].event_metadata["changed_fields"] == ["job_title"]


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer invalid-token"},
    ],
)
def test_admin_profile_update_requires_authentication(
    api_client: TestClient,
    headers: dict[str, str],
) -> None:
    """Missing or invalid credentials cannot update user profiles."""
    response = api_client.patch(
        f"/api/v1/users/{uuid7()}",
        headers=headers,
        json={"display_name": "Unauthorized Change"},
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"
    assert response.headers["cache-control"] == "no-store"


def test_regular_user_cannot_update_other_profiles(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """An ordinary user cannot access administrator profile updates."""
    key = uuid7().hex
    password = "A secure profile authorization test passphrase"
    email = f"profile-regular-{key}@example.com"

    with Session(test_engine) as session:
        user = User(
            email=email,
            normalized_email=email,
            display_name="Regular User",
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

    access_token = login.json()["data"]["access_token"]

    response = api_client.patch(
        f"/api/v1/users/{user_id}",
        headers={"Authorization": f"Bearer {access_token}"},
        json={"display_name": "Unauthorized Change"},
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"
    assert response.headers["cache-control"] == "no-store"

    with Session(test_engine) as session:
        unchanged_user = session.get(User, user_id)

        assert unchanged_user is not None
        assert unchanged_user.display_name == "Regular User"
        assert unchanged_user.job_title == "Backend Engineer"


def test_admin_profile_update_rejects_unknown_user(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """An administrator receives 404 for a nonexistent target account."""
    key = uuid7().hex
    password = "A secure profile lookup test passphrase"
    admin_email = f"profile-lookup-admin-{key}@example.com"

    with Session(test_engine) as session:
        administrator = User(
            email=admin_email,
            normalized_email=admin_email,
            display_name="Administrator",
            status="active",
            system_role="administrator",
            password_hash=hash_password(password),
        )
        session.add(administrator)
        session.commit()

    login = api_client.post(
        "/api/v1/auth/login",
        json={"email": admin_email, "password": password},
    )
    assert login.status_code == 200

    response = api_client.patch(
        f"/api/v1/users/{uuid7()}",
        headers={"Authorization": f"Bearer {login.json()['data']['access_token']}"},
        json={"display_name": "Updated Name"},
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "USER_NOT_FOUND"
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize(
    "protected_field",
    [
        "email",
        "system_role",
        "status",
        "password_reset_required",
    ],
)
def test_admin_profile_update_rejects_protected_fields_atomically(
    api_client: TestClient,
    test_engine: Engine,
    protected_field: str,
) -> None:
    """An unsupported field rejects the entire administrator update."""
    key = uuid7().hex
    password = "A secure administrator validation test passphrase"

    admin_email = f"profile-validation-admin-{key}@example.com"
    target_email = f"profile-validation-target-{key}@example.com"

    with Session(test_engine) as session:
        administrator = User(
            email=admin_email,
            normalized_email=admin_email,
            display_name="Administrator",
            status="active",
            system_role="administrator",
            password_hash=hash_password(password),
        )
        target = User(
            email=target_email,
            normalized_email=target_email,
            display_name="Original Name",
            job_title="Backend Engineer",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )

        session.add_all([administrator, target])
        session.commit()

        target_id = target.id
        original_updated_at = target.updated_at

    login = api_client.post(
        "/api/v1/auth/login",
        json={"email": admin_email, "password": password},
    )
    assert login.status_code == 200

    response = api_client.patch(
        f"/api/v1/users/{target_id}",
        headers={"Authorization": f"Bearer {login.json()['data']['access_token']}"},
        json={
            "display_name": "Unauthorized Change",
            protected_field: "unexpected-value",
        },
    )

    assert response.status_code == 422

    with Session(test_engine) as session:
        unchanged_user = session.get(User, target_id)

        assert unchanged_user is not None
        assert unchanged_user.display_name == "Original Name"
        assert unchanged_user.job_title == "Backend Engineer"
        assert unchanged_user.email == target_email
        assert unchanged_user.status == "active"
        assert unchanged_user.system_role == "user"
        assert unchanged_user.password_reset_required is False
        assert unchanged_user.updated_at == original_updated_at

        events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == target_id,
                AuditLog.action == "user.profile.updated",
            )
        ).all()

        assert events == []


@pytest.mark.parametrize("target_status", ["pending", "suspended"])
def test_administrator_can_update_inactive_user_profiles(
    api_client: TestClient,
    test_engine: Engine,
    target_status: str,
) -> None:
    """Administrators can edit pending and suspended user profiles."""
    key = uuid7().hex
    password = "A secure inactive profile test passphrase"

    admin_email = f"inactive-profile-admin-{key}@example.com"
    target_email = f"inactive-profile-target-{key}@example.com"

    with Session(test_engine) as session:
        administrator = User(
            email=admin_email,
            normalized_email=admin_email,
            display_name="Administrator",
            status="active",
            system_role="administrator",
            password_hash=hash_password(password),
        )

        target = User(
            email=target_email,
            normalized_email=target_email,
            display_name="Original Name",
            job_title=None,
            status=target_status,
            system_role="user",
            password_hash=(
                None if target_status == "pending" else hash_password(password)
            ),
        )

        session.add_all([administrator, target])
        session.commit()

        admin_id = administrator.id
        target_id = target.id

    login = api_client.post(
        "/api/v1/auth/login",
        json={"email": admin_email, "password": password},
    )
    assert login.status_code == 200

    response = api_client.patch(
        f"/api/v1/users/{target_id}",
        headers={"Authorization": f"Bearer {login.json()['data']['access_token']}"},
        json={
            "display_name": "Updated Name",
            "job_title": "Project Engineer",
        },
    )

    assert response.status_code == 200
    assert response.json()["data"]["display_name"] == "Updated Name"
    assert response.json()["data"]["job_title"] == "Project Engineer"
    assert response.json()["data"]["status"] == target_status

    with Session(test_engine) as session:
        updated_user = session.get(User, target_id)

        assert updated_user is not None
        assert updated_user.display_name == "Updated Name"
        assert updated_user.job_title == "Project Engineer"
        assert updated_user.status == target_status

        if target_status == "pending":
            assert updated_user.password_hash is None
        else:
            assert updated_user.password_hash is not None

        events = session.scalars(
            select(AuditLog).where(
                AuditLog.actor_user_id == admin_id,
                AuditLog.target_user_id == target_id,
                AuditLog.action == "user.profile.updated",
            )
        ).all()

        assert len(events) == 1
        assert events[0].event_metadata["changed_fields"] == [
            "display_name",
            "job_title",
        ]
