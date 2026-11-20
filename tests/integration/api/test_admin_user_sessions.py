"""HTTP integration tests for administrator session listing."""

from datetime import UTC, datetime, timedelta
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
    """Create an administrator and an ordinary user with real sessions."""
    key = uuid7().hex
    password = "A secure administrator session test passphrase"

    admin_email = f"session-admin-{key}@example.com"
    user_email = f"session-user-{key}@example.com"

    with Session(test_engine) as session:
        admin = User(
            email=admin_email,
            normalized_email=admin_email,
            display_name="Session Administrator",
            status="active",
            system_role="administrator",
            password_hash=hash_password(password),
        )
        user = User(
            email=user_email,
            normalized_email=user_email,
            display_name="Session User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )

        session.add_all([admin, user])
        session.commit()

        admin_id = str(admin.id)
        user_id = str(user.id)

    def login(email: str) -> dict[str, str]:
        response = api_client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password},
        )
        assert response.status_code == 200
        return response.json()["data"]

    admin_login = login(admin_email)
    user_login = login(user_email)

    return {
        "admin_id": admin_id,
        "user_id": user_id,
        "user_email": user_email,
        "user_password": password,
        "admin_refresh_token": admin_login["refresh_token"],
        "admin_token": admin_login["access_token"],
        "user_token": user_login["access_token"],
        "admin_session_id": admin_login["session_id"],
        "user_session_id": user_login["session_id"],
        "user_refresh_token": user_login["refresh_token"],
    }


def auth(token: str) -> dict[str, str]:
    """Build an authorization header."""
    return {"Authorization": f"Bearer {token}"}


def test_administrator_lists_user_sessions(
    api_client: TestClient,
    accounts: dict[str, str],
) -> None:
    """Administrator can view another user's session metadata."""
    response = api_client.get(
        f"/api/v1/users/{accounts['user_id']}/sessions",
        headers=auth(accounts["admin_token"]),
    )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"

    body = response.json()
    assert body["pagination"]["total"] == 1
    assert len(body["data"]) == 1

    item = body["data"][0]
    assert item["session_id"] == accounts["user_session_id"]
    assert item["status"] == "active"
    assert item["is_current"] is False
    assert "access_token" not in item
    assert "refresh_token" not in item


def test_administrator_lists_own_sessions(
    api_client: TestClient,
    accounts: dict[str, str],
) -> None:
    """Administrator's own session is identified as current."""
    response = api_client.get(
        f"/api/v1/users/{accounts['admin_id']}/sessions",
        headers=auth(accounts["admin_token"]),
    )

    assert response.status_code == 200
    assert response.json()["data"][0]["session_id"] == accounts["admin_session_id"]
    assert response.json()["data"][0]["is_current"] is True


def test_regular_user_cannot_list_administrator_sessions(
    api_client: TestClient,
    accounts: dict[str, str],
) -> None:
    """Ordinary users cannot inspect another account's sessions."""
    response = api_client.get(
        f"/api/v1/users/{accounts['admin_id']}/sessions",
        headers=auth(accounts["user_token"]),
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


@pytest.mark.parametrize("token", [None, "invalid-token"])
def test_administrator_session_listing_requires_authentication(
    api_client: TestClient,
    accounts: dict[str, str],
    token: str | None,
) -> None:
    """Missing and invalid credentials are rejected."""
    headers = auth(token) if token is not None else {}

    response = api_client.get(
        f"/api/v1/users/{accounts['user_id']}/sessions",
        headers=headers,
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"


def test_administrator_session_listing_rejects_unknown_user(
    api_client: TestClient,
    accounts: dict[str, str],
) -> None:
    """An unknown target account returns 404."""
    response = api_client.get(
        f"/api/v1/users/{uuid7()}/sessions",
        headers=auth(accounts["admin_token"]),
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "USER_NOT_FOUND"


def test_administrator_session_listing_filters_and_paginates(
    api_client: TestClient,
    accounts: dict[str, str],
) -> None:
    """Session filters and pagination use the existing contract."""
    url = f"/api/v1/users/{accounts['user_id']}/sessions"
    headers = auth(accounts["admin_token"])

    active = api_client.get(
        url,
        headers=headers,
        params={"status": "active", "limit": 1, "offset": 0},
    )
    assert active.status_code == 200
    assert active.json()["pagination"]["total"] == 1
    assert len(active.json()["data"]) == 1

    revoked = api_client.get(
        url,
        headers=headers,
        params={"status": "revoked"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["data"] == []

    out_of_range = api_client.get(
        url,
        headers=headers,
        params={"limit": 1, "offset": 1},
    )
    assert out_of_range.status_code == 200
    assert out_of_range.json()["data"] == []
    assert out_of_range.json()["pagination"]["total"] == 1


@pytest.mark.parametrize(
    "params",
    [
        {"limit": 0},
        {"limit": 101},
        {"offset": -1},
        {"status": "unknown"},
    ],
)
def test_administrator_session_listing_rejects_invalid_filters(
    api_client: TestClient,
    accounts: dict[str, str],
    params: dict[str, int | str],
) -> None:
    """Invalid pagination and status values return 422."""
    response = api_client.get(
        f"/api/v1/users/{accounts['user_id']}/sessions",
        headers=auth(accounts["admin_token"]),
        params=params,
    )

    assert response.status_code == 422


def test_administrator_lists_session_history(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
) -> None:
    """Administrator can filter active, revoked and expired sessions."""
    user_id = UUID(accounts["user_id"])
    now = datetime.now(UTC)

    with Session(test_engine) as session:
        revoked_session = LoginSession(
            user_id=user_id,
            created_at=now - timedelta(days=2),
            expires_at=now + timedelta(days=5),
            revoked_at=now - timedelta(days=1),
            revocation_reason="user_revoked",
            refresh_token_hash=None,
        )
        expired_session = LoginSession(
            user_id=user_id,
            created_at=now - timedelta(days=10),
            expires_at=now - timedelta(days=3),
            refresh_token_hash=None,
        )
        old_revoked_session = LoginSession(
            user_id=user_id,
            created_at=now - timedelta(days=45),
            expires_at=now - timedelta(days=38),
            revoked_at=now - timedelta(days=35),
            revocation_reason="user_revoked",
            refresh_token_hash=None,
        )

        session.add_all([revoked_session, expired_session, old_revoked_session])
        session.commit()

        revoked_id = str(revoked_session.id)
        expired_id = str(expired_session.id)
        old_revoked_id = str(old_revoked_session.id)

    url = f"/api/v1/users/{user_id}/sessions"
    headers = auth(accounts["admin_token"])

    all_response = api_client.get(url, headers=headers)
    assert all_response.status_code == 200

    all_ids = {item["session_id"] for item in all_response.json()["data"]}

    assert accounts["user_session_id"] in all_ids
    assert revoked_id in all_ids
    assert expired_id in all_ids
    assert old_revoked_id not in all_ids

    for status, expected_id in (
        ("active", accounts["user_session_id"]),
        ("revoked", revoked_id),
        ("expired", expired_id),
    ):
        response = api_client.get(
            url,
            headers=headers,
            params={"status": status},
        )

        assert response.status_code == 200
        assert {item["session_id"] for item in response.json()["data"]} == {expected_id}


def test_administrator_revokes_user_session(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
) -> None:
    """Revocation invalidates credentials and creates an audit event."""
    url = f"/api/v1/users/{accounts['user_id']}/sessions/{accounts['user_session_id']}"

    response = api_client.delete(
        url,
        headers=auth(accounts["admin_token"]),
    )

    assert response.status_code == 204
    assert response.content == b""
    assert response.headers["cache-control"] == "no-store"

    # The revoked session's access token is no longer usable.
    rejected = api_client.get(
        "/api/v1/users/me",
        headers=auth(accounts["user_token"]),
    )
    assert rejected.status_code == 401

    # The administrator's session is unaffected.
    administrator = api_client.get(
        "/api/v1/users/me",
        headers=auth(accounts["admin_token"]),
    )
    assert administrator.status_code == 200

    with Session(test_engine) as session:
        target = session.get(
            LoginSession,
            UUID(accounts["user_session_id"]),
        )
        assert target is not None
        assert target.revoked_at is not None
        assert target.refresh_token_hash is None
        assert target.revocation_reason == "administrator_revoked"

        events = session.scalars(
            select(AuditLog).where(
                AuditLog.actor_user_id == UUID(accounts["admin_id"]),
                AuditLog.target_user_id == UUID(accounts["user_id"]),
                AuditLog.action == "user.session.revoked",
            )
        ).all()

        assert len(events) == 1
        assert events[0].event_metadata["session_id"] == accounts["user_session_id"]


def test_administrator_session_revocation_is_idempotent(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
) -> None:
    """Repeated revocation succeeds without duplicate audit events."""
    url = f"/api/v1/users/{accounts['user_id']}/sessions/{accounts['user_session_id']}"

    headers = auth(accounts["admin_token"])

    first = api_client.delete(url, headers=headers)
    second = api_client.delete(url, headers=headers)

    assert first.status_code == 204
    assert second.status_code == 204

    with Session(test_engine) as session:
        events = session.scalars(
            select(AuditLog).where(
                AuditLog.actor_user_id == UUID(accounts["admin_id"]),
                AuditLog.target_user_id == UUID(accounts["user_id"]),
                AuditLog.action == "user.session.revoked",
            )
        ).all()

        assert len(events) == 1


def test_regular_user_cannot_revoke_administrator_session(
    api_client: TestClient,
    accounts: dict[str, str],
) -> None:
    """Ordinary users cannot revoke an administrator's session."""
    response = api_client.delete(
        f"/api/v1/users/{accounts['admin_id']}/sessions/{accounts['admin_session_id']}",
        headers=auth(accounts["user_token"]),
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"

    administrator = api_client.get(
        "/api/v1/users/me",
        headers=auth(accounts["admin_token"]),
    )
    assert administrator.status_code == 200


@pytest.mark.parametrize("token", [None, "invalid-token"])
def test_administrator_session_revocation_requires_authentication(
    api_client: TestClient,
    accounts: dict[str, str],
    token: str | None,
) -> None:
    """Missing and invalid bearer credentials cannot revoke sessions."""
    headers = auth(token) if token is not None else {}

    response = api_client.delete(
        f"/api/v1/users/{accounts['user_id']}/sessions/{accounts['user_session_id']}",
        headers=headers,
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"


def test_administrator_cannot_revoke_unknown_session(
    api_client: TestClient,
    accounts: dict[str, str],
) -> None:
    """An unknown session ID returns 404."""
    response = api_client.delete(
        f"/api/v1/users/{accounts['user_id']}/sessions/{uuid7()}",
        headers=auth(accounts["admin_token"]),
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "SESSION_NOT_FOUND"


def test_administrator_cannot_revoke_session_of_wrong_user(
    api_client: TestClient,
    accounts: dict[str, str],
) -> None:
    """Session ownership is enforced even for administrator requests."""
    response = api_client.delete(
        f"/api/v1/users/{accounts['user_id']}/sessions/{accounts['admin_session_id']}",
        headers=auth(accounts["admin_token"]),
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "SESSION_NOT_FOUND"


def test_administrator_session_revocation_rejects_unknown_user(
    api_client: TestClient,
    accounts: dict[str, str],
) -> None:
    """An unknown target account returns 404."""
    response = api_client.delete(
        f"/api/v1/users/{uuid7()}/sessions/{accounts['user_session_id']}",
        headers=auth(accounts["admin_token"]),
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "USER_NOT_FOUND"


def test_administrator_revocation_invalidates_refresh_token(
    api_client: TestClient,
    accounts: dict[str, str],
) -> None:
    """An administrator-revoked session cannot refresh credentials."""
    response = api_client.delete(
        f"/api/v1/users/{accounts['user_id']}/sessions/{accounts['user_session_id']}",
        headers=auth(accounts["admin_token"]),
    )

    assert response.status_code == 204

    refresh_response = api_client.post(
        "/api/v1/auth/refresh",
        json={
            "refresh_token": accounts["user_refresh_token"],
        },
    )

    assert refresh_response.status_code == 401
    assert refresh_response.json()["error"]["code"] == "INVALID_REFRESH_TOKEN"


def test_administrator_can_revoke_own_current_session(
    api_client: TestClient,
    accounts: dict[str, str],
) -> None:
    """An administrator can revoke their own current login session."""
    headers = auth(accounts["admin_token"])

    response = api_client.delete(
        f"/api/v1/users/{accounts['admin_id']}/sessions/{accounts['admin_session_id']}",
        headers=headers,
    )

    assert response.status_code == 204
    assert response.content == b""
    assert response.headers["cache-control"] == "no-store"

    # Revoking the current session invalidates the caller's access token.
    profile_response = api_client.get(
        "/api/v1/users/me",
        headers=headers,
    )

    assert profile_response.status_code == 401


def test_administrator_revokes_all_user_sessions(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
) -> None:
    """Bulk revocation invalidates sessions and records one audit event."""
    second_login = api_client.post(
        "/api/v1/auth/login",
        json={
            "email": accounts["user_email"],
            "password": accounts["user_password"],
        },
    )
    assert second_login.status_code == 200
    second = second_login.json()["data"]

    response = api_client.delete(
        f"/api/v1/users/{accounts['user_id']}/sessions",
        headers=auth(accounts["admin_token"]),
    )

    assert response.status_code == 204
    assert response.content == b""
    assert response.headers["cache-control"] == "no-store"

    for token in (accounts["user_token"], second["access_token"]):
        profile = api_client.get(
            "/api/v1/users/me",
            headers=auth(token),
        )
        assert profile.status_code == 401

    for token in (
        accounts["user_refresh_token"],
        second["refresh_token"],
    ):
        refreshed = api_client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": token},
        )
        assert refreshed.status_code == 401

    # The administrator remains authenticated.
    profile = api_client.get(
        "/api/v1/users/me",
        headers=auth(accounts["admin_token"]),
    )
    assert profile.status_code == 200

    with Session(test_engine) as session:
        sessions = session.scalars(
            select(LoginSession).where(
                LoginSession.user_id == UUID(accounts["user_id"])
            )
        ).all()

        assert len(sessions) == 2
        assert all(item.revoked_at is not None for item in sessions)
        assert all(item.refresh_token_hash is None for item in sessions)
        assert all(
            item.revocation_reason == "administrator_revoked" for item in sessions
        )

        events = session.scalars(
            select(AuditLog).where(
                AuditLog.actor_user_id == UUID(accounts["admin_id"]),
                AuditLog.target_user_id == UUID(accounts["user_id"]),
                AuditLog.action == "user.sessions.revoked",
            )
        ).all()

        assert len(events) == 1
        assert events[0].event_metadata["revoked_count"] == 2


def test_administrator_bulk_revocation_is_idempotent(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
) -> None:
    """A repeated request succeeds without creating another audit event."""
    url = f"/api/v1/users/{accounts['user_id']}/sessions"
    headers = auth(accounts["admin_token"])

    first = api_client.delete(url, headers=headers)
    second = api_client.delete(url, headers=headers)

    assert first.status_code == 204
    assert second.status_code == 204

    with Session(test_engine) as session:
        events = session.scalars(
            select(AuditLog).where(
                AuditLog.actor_user_id == UUID(accounts["admin_id"]),
                AuditLog.target_user_id == UUID(accounts["user_id"]),
                AuditLog.action == "user.sessions.revoked",
            )
        ).all()

        assert len(events) == 1
        assert events[0].event_metadata["revoked_count"] == 1


def test_regular_user_cannot_bulk_revoke_sessions(
    api_client: TestClient,
    accounts: dict[str, str],
) -> None:
    """A regular user cannot revoke administrator sessions."""
    response = api_client.delete(
        f"/api/v1/users/{accounts['admin_id']}/sessions",
        headers=auth(accounts["user_token"]),
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"

    profile = api_client.get(
        "/api/v1/users/me",
        headers=auth(accounts["admin_token"]),
    )
    assert profile.status_code == 200


@pytest.mark.parametrize("token", [None, "invalid-token"])
def test_administrator_bulk_revocation_requires_authentication(
    api_client: TestClient,
    accounts: dict[str, str],
    token: str | None,
) -> None:
    """Missing or invalid credentials cannot revoke sessions."""
    headers = auth(token) if token is not None else {}

    response = api_client.delete(
        f"/api/v1/users/{accounts['user_id']}/sessions",
        headers=headers,
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"


def test_administrator_bulk_revocation_rejects_unknown_user(
    api_client: TestClient,
    accounts: dict[str, str],
) -> None:
    """An unknown target account returns 404."""
    response = api_client.delete(
        f"/api/v1/users/{uuid7()}/sessions",
        headers=auth(accounts["admin_token"]),
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "USER_NOT_FOUND"


def test_administrator_can_bulk_revoke_own_sessions(
    api_client: TestClient,
    accounts: dict[str, str],
) -> None:
    """An administrator may revoke their own current session."""
    headers = auth(accounts["admin_token"])

    response = api_client.delete(
        f"/api/v1/users/{accounts['admin_id']}/sessions",
        headers=headers,
    )

    assert response.status_code == 204

    profile = api_client.get(
        "/api/v1/users/me",
        headers=headers,
    )
    assert profile.status_code == 401

    refresh = api_client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": accounts["admin_refresh_token"]},
    )
    assert refresh.status_code == 401


@pytest.mark.parametrize(
    "account_change",
    ["suspended", "password_reset_required"],
)
def test_ineligible_administrator_cannot_revoke_sessions(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
    account_change: str,
) -> None:
    """An ineligible administrator cannot revoke another user's sessions."""
    with Session(test_engine) as session:
        administrator = session.get(User, UUID(accounts["admin_id"]))
        assert administrator is not None

        if account_change == "suspended":
            administrator.status = "suspended"
        else:
            administrator.password_reset_required = True

        session.commit()

    response = api_client.delete(
        f"/api/v1/users/{accounts['user_id']}/sessions",
        headers=auth(accounts["admin_token"]),
    )

    assert response.status_code == 401

    with Session(test_engine) as session:
        target = session.get(
            LoginSession,
            UUID(accounts["user_session_id"]),
        )
        assert target is not None
        assert target.revoked_at is None
