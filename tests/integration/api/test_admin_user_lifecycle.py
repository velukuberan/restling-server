"""HTTP integration tests for administrator account lifecycle."""

from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session
from uuid6 import uuid7

from restling_server.users.models import AuditLog, LoginSession, User
from restling_server.users.passwords import hash_password


@pytest.fixture
def accounts(
    api_client: TestClient,
    test_engine: Engine,
) -> dict[str, str]:
    """Create an administrator and an active ordinary user."""
    key = uuid7().hex
    password = "A secure lifecycle test passphrase #8472"

    administrator_email = f"lifecycle-admin-{key}@example.com"
    user_email = f"lifecycle-user-{key}@example.com"

    with Session(test_engine) as session:
        administrator = User(
            email=administrator_email,
            normalized_email=administrator_email,
            display_name="Lifecycle Administrator",
            status="active",
            system_role="administrator",
            password_hash=hash_password(password),
        )

        user = User(
            email=user_email,
            normalized_email=user_email,
            display_name="Lifecycle User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )

        session.add_all([administrator, user])
        session.commit()

        administrator_id = administrator.id
        user_id = user.id

    def login(email: str) -> str:
        response = api_client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password},
        )

        assert response.status_code == 200
        return str(response.json()["data"]["access_token"])

    return {
        "administrator_id": str(administrator_id),
        "user_id": str(user_id),
        "administrator_token": login(administrator_email),
        "user_token": login(user_email),
    }


def auth(token: str) -> dict[str, str]:
    """Build the Authorization header."""
    return {"Authorization": f"Bearer {token}"}


def suspend(
    api_client: TestClient,
    user_id: str,
    token: str,
):
    """Submit a suspension request."""
    return api_client.post(
        f"/api/v1/users/{user_id}/suspend",
        headers=auth(token),
    )


def test_administrator_suspends_active_user(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
) -> None:
    """Suspension changes account state and revokes existing sessions."""
    user_id = UUID(accounts["user_id"])

    response = suspend(
        api_client,
        accounts["user_id"],
        accounts["administrator_token"],
    )

    assert response.status_code == 204
    assert response.content == b""
    assert response.headers["cache-control"] == "no-store"

    with Session(test_engine) as session:
        user = session.get(User, user_id)
        assert user is not None
        assert user.status == "suspended"

        sessions = session.scalars(
            select(LoginSession).where(LoginSession.user_id == user_id)
        ).all()

        assert len(sessions) == 1
        assert sessions[0].revoked_at is not None
        assert sessions[0].refresh_token_hash is None
        assert sessions[0].revocation_reason == "account_suspended"

        events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.suspended",
            )
        ).all()

        assert len(events) == 1
        assert events[0].actor_user_id == UUID(accounts["administrator_id"])

    # The previously valid access token must no longer work.
    profile = api_client.get(
        "/api/v1/users/me",
        headers=auth(accounts["user_token"]),
    )

    assert profile.status_code == 401


def test_regular_user_cannot_suspend_account(
    api_client: TestClient,
    accounts: dict[str, str],
) -> None:
    """Ordinary users cannot perform administrator suspension."""
    response = suspend(
        api_client,
        accounts["administrator_id"],
        accounts["user_token"],
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


@pytest.mark.parametrize("token", [None, "invalid-token"])
def test_suspension_requires_authentication(
    api_client: TestClient,
    accounts: dict[str, str],
    token: str | None,
) -> None:
    """Missing or invalid bearer credentials are rejected."""
    headers = auth(token) if token is not None else {}

    response = api_client.post(
        f"/api/v1/users/{accounts['user_id']}/suspend",
        headers=headers,
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"


def test_last_administrator_cannot_be_suspended(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
) -> None:
    """The system must preserve its last active administrator."""
    response = suspend(
        api_client,
        accounts["administrator_id"],
        accounts["administrator_token"],
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "LAST_ADMINISTRATOR"

    with Session(test_engine) as session:
        administrator = session.get(
            User,
            UUID(accounts["administrator_id"]),
        )

        assert administrator is not None
        assert administrator.status == "active"


def test_suspended_user_cannot_be_suspended_again(
    api_client: TestClient,
    accounts: dict[str, str],
) -> None:
    """An account cannot undergo the same state transition twice."""
    first_response = suspend(
        api_client,
        accounts["user_id"],
        accounts["administrator_token"],
    )

    assert first_response.status_code == 204

    second_response = suspend(
        api_client,
        accounts["user_id"],
        accounts["administrator_token"],
    )

    assert second_response.status_code == 409
    assert second_response.json()["error"]["code"] == "SUSPENSION_NOT_ALLOWED"


def test_unknown_user_cannot_be_suspended(
    api_client: TestClient,
    accounts: dict[str, str],
) -> None:
    """Suspending an unknown account is rejected."""
    response = suspend(
        api_client,
        str(uuid7()),
        accounts["administrator_token"],
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "SUSPENSION_NOT_ALLOWED"


def test_administrator_restores_suspended_user(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
) -> None:
    """Restoration permits fresh login but never revives old sessions."""
    user_id = UUID(accounts["user_id"])

    suspension = suspend(
        api_client,
        accounts["user_id"],
        accounts["administrator_token"],
    )
    assert suspension.status_code == 204

    response = api_client.post(
        f"/api/v1/users/{user_id}/restore",
        headers=auth(accounts["administrator_token"]),
        json={},
    )

    assert response.status_code == 204
    assert response.content == b""
    assert response.headers["cache-control"] == "no-store"

    with Session(test_engine) as session:
        user = session.get(User, user_id)
        assert user is not None
        assert user.status == "active"
        assert user.password_reset_required is False

        sessions = session.scalars(
            select(LoginSession).where(LoginSession.user_id == user_id)
        ).all()

        assert len(sessions) == 1
        assert sessions[0].revoked_at is not None
        assert sessions[0].refresh_token_hash is None

        events = session.scalars(
            select(AuditLog).where(
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.restored",
            )
        ).all()

        assert len(events) == 1
        assert events[0].actor_user_id == UUID(accounts["administrator_id"])

    old_session = api_client.get(
        "/api/v1/users/me",
        headers=auth(accounts["user_token"]),
    )
    assert old_session.status_code == 401


def test_restoration_can_require_password_reset(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
) -> None:
    """Administrator may require password reset on restoration."""
    suspension = suspend(
        api_client,
        accounts["user_id"],
        accounts["administrator_token"],
    )
    assert suspension.status_code == 204

    response = api_client.post(
        f"/api/v1/users/{accounts['user_id']}/restore",
        headers=auth(accounts["administrator_token"]),
        json={"require_password_reset": True},
    )

    assert response.status_code == 204

    with Session(test_engine) as session:
        user = session.get(User, UUID(accounts["user_id"]))
        assert user is not None
        assert user.status == "active"
        assert user.password_reset_required is True


def test_regular_user_cannot_restore_account(
    api_client: TestClient,
    accounts: dict[str, str],
) -> None:
    """Ordinary users cannot restore suspended accounts."""
    suspension = suspend(
        api_client,
        accounts["user_id"],
        accounts["administrator_token"],
    )
    assert suspension.status_code == 204

    response = api_client.post(
        f"/api/v1/users/{accounts['user_id']}/restore",
        headers=auth(accounts["user_token"]),
        json={},
    )

    # The ordinary user's access token was revoked by suspension.
    assert response.status_code == 401


@pytest.mark.parametrize("token", [None, "invalid-token"])
def test_restoration_requires_authentication(
    api_client: TestClient,
    accounts: dict[str, str],
    token: str | None,
) -> None:
    """Restoration rejects absent or invalid credentials."""
    headers = auth(token) if token is not None else {}

    response = api_client.post(
        f"/api/v1/users/{accounts['user_id']}/restore",
        headers=headers,
        json={},
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"


def test_active_user_cannot_be_restored(
    api_client: TestClient,
    accounts: dict[str, str],
) -> None:
    """Only suspended accounts can be restored."""
    response = api_client.post(
        f"/api/v1/users/{accounts['user_id']}/restore",
        headers=auth(accounts["administrator_token"]),
        json={},
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "RESTORATION_NOT_ALLOWED"


def test_unknown_user_cannot_be_restored(
    api_client: TestClient,
    accounts: dict[str, str],
) -> None:
    """Restoration rejects an unknown account."""
    response = api_client.post(
        f"/api/v1/users/{uuid7()}/restore",
        headers=auth(accounts["administrator_token"]),
        json={},
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "RESTORATION_NOT_ALLOWED"


def test_restoration_rejects_unknown_fields(
    api_client: TestClient,
    accounts: dict[str, str],
) -> None:
    """Administrators cannot submit unsupported restoration options."""
    response = api_client.post(
        f"/api/v1/users/{accounts['user_id']}/restore",
        headers=auth(accounts["administrator_token"]),
        json={"change_role": "administrator"},
    )

    assert response.status_code == 422


def test_active_regular_user_cannot_restore_account(
    api_client: TestClient,
    accounts: dict[str, str],
) -> None:
    """An authenticated ordinary user cannot restore accounts."""
    response = api_client.post(
        f"/api/v1/users/{accounts['administrator_id']}/restore",
        headers=auth(accounts["user_token"]),
        json={},
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"
