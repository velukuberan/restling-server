"""HTTP integration tests for administrator invitation revocation."""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session
from uuid6 import uuid7

from restling_server.users.models import AuditLog, OneTimeToken, User
from restling_server.users.passwords import hash_password
from restling_server.users.service import issue_activation_token
from restling_server.users.tokens import generate_token, hash_token


def test_administrator_revokes_activation_invitation(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """A revoked invitation cannot activate its pending account."""
    key = uuid7().hex
    password = "A secure invitation revocation test passphrase"
    admin_email = f"invitation-admin-{key}@example.com"
    pending_email = f"invitation-pending-{key}@example.com"

    with Session(test_engine) as session:
        administrator = User(
            email=admin_email,
            normalized_email=admin_email,
            display_name="Invitation Administrator",
            status="active",
            system_role="administrator",
            password_hash=hash_password(password),
        )
        pending_user = User(
            email=pending_email,
            normalized_email=pending_email,
            display_name="Pending Invitation User",
            status="pending",
            system_role="user",
            password_hash=None,
        )

        session.add_all([administrator, pending_user])
        session.commit()

        admin_id = administrator.id
        user_id = pending_user.id

    with Session(test_engine) as session:
        activation_token, _ = issue_activation_token(
            session,
            actor_id=admin_id,
            user_id=user_id,
            expiry_hours=24,
        )

    login = api_client.post(
        "/api/v1/auth/login",
        json={"email": admin_email, "password": password},
    )

    assert login.status_code == 200
    access_token = login.json()["data"]["access_token"]

    response = api_client.delete(
        f"/api/v1/users/{user_id}/invitations",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 204
    assert response.content == b""
    assert response.headers["cache-control"] == "no-store"

    # Repeated revocation must succeed without changing state again.
    repeated = api_client.delete(
        f"/api/v1/users/{user_id}/invitations",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert repeated.status_code == 204
    assert repeated.content == b""

    activation = api_client.post(
        "/api/v1/auth/activate",
        json={
            "token": activation_token,
            "password": password,
        },
    )

    assert activation.status_code == 400
    assert activation.json()["error"]["code"] == "INVALID_ACTIVATION_TOKEN"

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.status == "pending"
        assert user.password_hash is None

        invitations = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "account_activation",
            )
        ).all()

        assert len(invitations) == 1
        assert invitations[0].revoked_at is not None
        assert invitations[0].consumed_at is None

        events = session.scalars(
            select(AuditLog).where(
                AuditLog.actor_user_id == admin_id,
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.invitations.revoked",
            )
        ).all()

        assert len(events) == 1
        assert events[0].event_metadata["revoked_count"] == 1


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer invalid-token"},
    ],
)
def test_invitation_revocation_requires_authentication(
    api_client: TestClient,
    headers: dict[str, str],
) -> None:
    """Missing or invalid credentials cannot revoke invitations."""
    response = api_client.delete(
        f"/api/v1/users/{uuid7()}/invitations",
        headers=headers,
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"
    assert response.headers["cache-control"] == "no-store"


def test_regular_user_cannot_revoke_invitations(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """An authenticated ordinary user cannot revoke invitations."""
    key = uuid7().hex
    password = "A secure invitation authorization test passphrase"
    email = f"invitation-regular-{key}@example.com"

    with Session(test_engine) as session:
        user = User(
            email=email,
            normalized_email=email,
            display_name="Ordinary User",
            status="active",
            system_role="user",
            password_hash=hash_password(password),
        )
        session.add(user)
        session.commit()

    login = api_client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": password,
        },
    )
    assert login.status_code == 200

    access_token = login.json()["data"]["access_token"]

    response = api_client.delete(
        f"/api/v1/users/{uuid7()}/invitations",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"
    assert response.headers["cache-control"] == "no-store"


def test_invitation_revocation_rejects_unknown_user(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """An administrator receives 404 for a nonexistent target account."""
    key = uuid7().hex
    password = "A secure invitation test passphrase"
    admin_email = f"invitation-admin-{key}@example.com"

    with Session(test_engine) as session:
        administrator = User(
            email=admin_email,
            normalized_email=admin_email,
            display_name="Invitation Administrator",
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

    access_token = login.json()["data"]["access_token"]

    response = api_client.delete(
        f"/api/v1/users/{uuid7()}/invitations",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "USER_NOT_FOUND"
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("target_status", ["active", "suspended"])
def test_invitation_revocation_rejects_non_pending_accounts(
    api_client: TestClient,
    test_engine: Engine,
    target_status: str,
) -> None:
    """Only pending accounts are eligible for invitation revocation."""
    key = uuid7().hex
    password = "A secure invitation eligibility test passphrase"

    admin_email = f"eligibility-admin-{key}@example.com"
    target_email = f"eligibility-target-{key}@example.com"

    with Session(test_engine) as session:
        administrator = User(
            email=admin_email,
            normalized_email=admin_email,
            display_name="Invitation Administrator",
            status="active",
            system_role="administrator",
            password_hash=hash_password(password),
        )

        target = User(
            email=target_email,
            normalized_email=target_email,
            display_name="Invitation Target",
            status=target_status,
            system_role="user",
            password_hash=hash_password(password),
        )

        session.add_all([administrator, target])
        session.commit()

        target_id = target.id

    login = api_client.post(
        "/api/v1/auth/login",
        json={"email": admin_email, "password": password},
    )
    assert login.status_code == 200

    access_token = login.json()["data"]["access_token"]

    response = api_client.delete(
        f"/api/v1/users/{target_id}/invitations",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "INVITATION_REVOCATION_NOT_ALLOWED"
    assert response.headers["cache-control"] == "no-store"


def test_revocation_without_outstanding_invitations(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """Revocation succeeds when a pending account has no invitations."""
    key = uuid7().hex
    password = "A secure invitation no-op test passphrase"

    admin_email = f"no-invites-admin-{key}@example.com"
    pending_email = f"no-invites-user-{key}@example.com"

    with Session(test_engine) as session:
        administrator = User(
            email=admin_email,
            normalized_email=admin_email,
            display_name="Invitation Administrator",
            status="active",
            system_role="administrator",
            password_hash=hash_password(password),
        )

        pending_user = User(
            email=pending_email,
            normalized_email=pending_email,
            display_name="Pending User",
            status="pending",
            system_role="user",
            password_hash=None,
        )

        session.add_all([administrator, pending_user])
        session.commit()

        admin_id = administrator.id
        user_id = pending_user.id

    login = api_client.post(
        "/api/v1/auth/login",
        json={"email": admin_email, "password": password},
    )
    assert login.status_code == 200

    response = api_client.delete(
        f"/api/v1/users/{user_id}/invitations",
        headers={"Authorization": f"Bearer {login.json()['data']['access_token']}"},
    )

    assert response.status_code == 204
    assert response.content == b""
    assert response.headers["cache-control"] == "no-store"

    with Session(test_engine) as session:
        user = session.get(User, user_id)
        assert user is not None
        assert user.status == "pending"
        assert user.password_hash is None

        events = session.scalars(
            select(AuditLog).where(
                AuditLog.actor_user_id == admin_id,
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.invitations.revoked",
            )
        ).all()

        assert events == []


def test_revocation_invalidates_multiple_invitations(
    api_client: TestClient,
    test_engine: Engine,
) -> None:
    """All outstanding activation credentials are revoked together."""
    key = uuid7().hex
    password = "A secure multiple invitations test passphrase"

    admin_email = f"multi-admin-{key}@example.com"
    pending_email = f"multi-pending-{key}@example.com"

    with Session(test_engine) as session:
        administrator = User(
            email=admin_email,
            normalized_email=admin_email,
            display_name="Invitation Administrator",
            status="active",
            system_role="administrator",
            password_hash=hash_password(password),
        )

        pending_user = User(
            email=pending_email,
            normalized_email=pending_email,
            display_name="Pending User",
            status="pending",
            system_role="user",
            password_hash=None,
        )

        session.add_all([administrator, pending_user])
        session.commit()

        admin_id = administrator.id
        user_id = pending_user.id

    # Issue one invitation through the existing service.
    with Session(test_engine) as session:
        first_token, _ = issue_activation_token(
            session,
            actor_id=admin_id,
            user_id=user_id,
            expiry_hours=24,
        )

    # Simulate two outstanding tokens for the same account.
    second_token = generate_token()
    now = datetime.now(UTC)

    with Session(test_engine) as session:
        session.add(
            OneTimeToken(
                user_id=user_id,
                purpose="account_activation",
                token_hash=hash_token(second_token),
                created_at=now,
                expires_at=now + timedelta(hours=24),
            )
        )
        session.commit()

    login = api_client.post(
        "/api/v1/auth/login",
        json={"email": admin_email, "password": password},
    )
    assert login.status_code == 200

    response = api_client.delete(
        f"/api/v1/users/{user_id}/invitations",
        headers={"Authorization": f"Bearer {login.json()['data']['access_token']}"},
    )

    assert response.status_code == 204

    # Neither activation credential must remain usable.
    for token in (first_token, second_token):
        activation = api_client.post(
            "/api/v1/auth/activate",
            json={
                "token": token,
                "password": password,
            },
        )

        assert activation.status_code == 400
        assert activation.json()["error"]["code"] == "INVALID_ACTIVATION_TOKEN"

    with Session(test_engine) as session:
        user = session.get(User, user_id)
        assert user is not None
        assert user.status == "pending"

        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "account_activation",
            )
        ).all()

        assert len(tokens) == 2
        assert all(token.revoked_at is not None for token in tokens)
        assert all(token.consumed_at is None for token in tokens)

        events = session.scalars(
            select(AuditLog).where(
                AuditLog.actor_user_id == admin_id,
                AuditLog.target_user_id == user_id,
                AuditLog.action == "user.invitations.revoked",
            )
        ).all()

        assert len(events) == 1
        assert events[0].event_metadata["revoked_count"] == 2
