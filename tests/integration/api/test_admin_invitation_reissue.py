"""HTTP integration tests for administrator invitation reissuance."""

from urllib.parse import parse_qs, urlsplit
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from pydantic import AnyHttpUrl
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session
from uuid6 import uuid7

import restling_server.users.invitations as invitations
from restling_server.main import app
from restling_server.users.invitation_email import InvitationDeliveryError
from restling_server.users.models import OneTimeToken, User
from restling_server.users.passwords import hash_password
from restling_server.users.tokens import hash_token


@pytest.fixture
def accounts(
    api_client: TestClient,
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, str]:
    """Create administrator and ordinary-user access credentials."""
    key = uuid7().hex
    password = "A secure invitation test passphrase #8472"

    admin_email = f"reissue-admin-{key}@example.com"
    user_email = f"reissue-user-{key}@example.com"

    with Session(test_engine) as session:
        session.add_all(
            [
                User(
                    email=admin_email,
                    normalized_email=admin_email,
                    display_name="Invitation Administrator",
                    status="active",
                    system_role="administrator",
                    password_hash=hash_password(password),
                ),
                User(
                    email=user_email,
                    normalized_email=user_email,
                    display_name="Ordinary User",
                    status="active",
                    system_role="user",
                    password_hash=hash_password(password),
                ),
            ]
        )
        session.commit()

    monkeypatch.setattr(
        app.state.settings,
        "public_url",
        AnyHttpUrl("http://127.0.0.1:8000"),
    )
    monkeypatch.setattr(app.state.settings, "smtp_host", None)
    monkeypatch.setattr(app.state.settings, "smtp_from_email", None)

    def login(email: str) -> str:
        response = api_client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password},
        )
        assert response.status_code == 200
        return str(response.json()["data"]["access_token"])

    return {
        "administrator": login(admin_email),
        "user": login(user_email),
    }


def auth(token: str) -> dict[str, str]:
    """Build the bearer authentication header."""
    return {"Authorization": f"Bearer {token}"}


def create_pending_user(
    api_client: TestClient,
    administrator_token: str,
) -> tuple[UUID, str]:
    """Create a pending account with its first activation token."""
    response = api_client.post(
        "/api/v1/users",
        headers=auth(administrator_token),
        json={
            "email": f"pending-{uuid7().hex}@example.com",
            "display_name": "Pending Invitation User",
            "invitation_delivery": "manual",
        },
    )

    assert response.status_code == 201

    result = response.json()
    user_id = UUID(result["data"]["id"])

    activation_url: str = result["invitation"]["activation_url"]
    assert isinstance(activation_url, str)
    first_token = parse_qs(urlsplit(activation_url).query)["token"][0]

    return user_id, first_token


def test_administrator_reissues_manual_invitation(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
) -> None:
    """Reissuing creates a new token and invalidates the previous one."""
    administrator_token = accounts["administrator"]

    user_id, first_token = create_pending_user(
        api_client,
        administrator_token,
    )

    response = api_client.post(
        f"/api/v1/users/{user_id}/invitations",
        headers=auth(administrator_token),
        json={"invitation_delivery": "manual"},
    )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"

    invitation = response.json()["invitation"]

    assert invitation["delivery"] == "manual"
    assert invitation["expires_at"]

    activation_url = invitation["activation_url"]
    assert isinstance(activation_url, str)

    second_token = parse_qs(urlsplit(activation_url).query)["token"][0]

    assert first_token != second_token

    with Session(test_engine) as session:
        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "account_activation",
            )
        ).all()

        assert len(tokens) == 2

        old_token = next(
            token for token in tokens if token.token_hash == hash_token(first_token)
        )

        new_token = next(
            token for token in tokens if token.token_hash == hash_token(second_token)
        )

        assert old_token.revoked_at is not None
        assert new_token.revoked_at is None
        assert new_token.consumed_at is None


def test_regular_user_cannot_reissue_invitation(
    api_client: TestClient,
    accounts: dict[str, str],
) -> None:
    """An ordinary user cannot reissue another user's invitation."""
    user_id, _ = create_pending_user(
        api_client,
        accounts["administrator"],
    )

    response = api_client.post(
        f"/api/v1/users/{user_id}/invitations",
        headers=auth(accounts["user"]),
        json={"invitation_delivery": "manual"},
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


def test_reissue_requires_authentication(
    api_client: TestClient,
    accounts: dict[str, str],
) -> None:
    """Missing or invalid access credentials receive 401."""
    user_id, _ = create_pending_user(
        api_client,
        accounts["administrator"],
    )

    for headers in ({}, auth("invalid-token")):
        response = api_client.post(
            f"/api/v1/users/{user_id}/invitations",
            headers=headers,
            json={"invitation_delivery": "manual"},
        )

        assert response.status_code == 401
        assert response.json()["error"]["code"] == "UNAUTHORIZED"


def test_reissue_rejects_unknown_user(
    api_client: TestClient,
    accounts: dict[str, str],
) -> None:
    """An administrator cannot reissue for a nonexistent account."""
    unknown_user_id = uuid7()

    response = api_client.post(
        f"/api/v1/users/{unknown_user_id}/invitations",
        headers=auth(accounts["administrator"]),
        json={"invitation_delivery": "manual"},
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "USER_NOT_FOUND"


def test_reissue_rejects_active_account(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
) -> None:
    """Activation invitations are restricted to pending accounts."""
    user_id, _ = create_pending_user(
        api_client,
        accounts["administrator"],
    )

    with Session(test_engine) as session:
        with session.begin():
            user = session.get(User, user_id)

            assert user is not None

            user.status = "active"
            user.password_hash = hash_password(
                "A secure activated test passphrase #8472"
            )

    response = api_client.post(
        f"/api/v1/users/{user_id}/invitations",
        headers=auth(accounts["administrator"]),
        json={"invitation_delivery": "manual"},
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "INVITATION_NOT_ALLOWED"


def test_reissue_sends_smtp_invitation(
    api_client: TestClient,
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    accounts: dict[str, str],
) -> None:
    """SMTP reissuance replaces the token without exposing it."""
    administrator_token = accounts["administrator"]

    user_id, first_token = create_pending_user(
        api_client,
        administrator_token,
    )

    monkeypatch.setattr(app.state.settings, "smtp_host", "localhost")
    monkeypatch.setattr(
        app.state.settings,
        "smtp_from_email",
        "restling@example.com",
    )

    sent_messages: list[tuple[str, str]] = []

    def capture_email_delivery(
        settings: object,
        *,
        recipient: str,
        activation_url: str,
    ) -> None:
        sent_messages.append((recipient, activation_url))

    monkeypatch.setattr(
        invitations,
        "send_invitation_email",
        capture_email_delivery,
    )

    response = api_client.post(
        f"/api/v1/users/{user_id}/invitations",
        headers=auth(administrator_token),
        json={"invitation_delivery": "email"},
    )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"

    invitation = response.json()["invitation"]

    assert invitation["delivery"] == "email"
    assert invitation["activation_url"] is None
    assert invitation["expires_at"]

    assert len(sent_messages) == 1

    recipient, activation_url = sent_messages[0]
    second_token = parse_qs(urlsplit(activation_url).query)["token"][0]

    assert second_token != first_token
    assert second_token not in response.text
    assert activation_url not in response.text

    with Session(test_engine) as session:
        target = session.get(User, user_id)

        assert target is not None
        assert recipient == target.email
        assert target.status == "pending"
        assert target.password_hash is None

        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "account_activation",
            )
        ).all()

        assert len(tokens) == 2

        previous = next(
            token for token in tokens if token.token_hash == hash_token(first_token)
        )
        replacement = next(
            token for token in tokens if token.token_hash == hash_token(second_token)
        )

        assert previous.revoked_at is not None
        assert replacement.revoked_at is None
        assert replacement.consumed_at is None


def test_smtp_failure_preserves_pending_account(
    api_client: TestClient,
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    accounts: dict[str, str],
) -> None:
    """SMTP failure returns 503 without altering the account."""
    administrator_token = accounts["administrator"]

    user_id, _ = create_pending_user(
        api_client,
        administrator_token,
    )

    monkeypatch.setattr(app.state.settings, "smtp_host", "localhost")
    monkeypatch.setattr(
        app.state.settings,
        "smtp_from_email",
        "restling@example.com",
    )

    def fail_email_delivery(
        settings: object,
        *,
        recipient: str,
        activation_url: str,
    ) -> None:
        raise InvitationDeliveryError("Simulated SMTP failure.")

    monkeypatch.setattr(
        invitations,
        "send_invitation_email",
        fail_email_delivery,
    )

    response = api_client.post(
        f"/api/v1/users/{user_id}/invitations",
        headers=auth(administrator_token),
        json={"invitation_delivery": "email"},
    )

    assert response.status_code == 503
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["error"]["code"] == "INVITATION_DELIVERY_FAILED"

    with Session(test_engine) as session:
        target = session.get(User, user_id)

        assert target is not None
        assert target.status == "pending"
        assert target.password_hash is None
        assert target.activated_at is None

        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "account_activation",
            )
        ).all()

        # Token replacement commits before SMTP communication.
        assert len(tokens) == 2
        assert sum(token.revoked_at is None for token in tokens) == 1


def test_email_reissue_without_smtp_preserves_existing_token(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
) -> None:
    """Missing SMTP configuration must not revoke the current token."""
    administrator_token = accounts["administrator"]

    user_id, first_token = create_pending_user(
        api_client,
        administrator_token,
    )

    response = api_client.post(
        f"/api/v1/users/{user_id}/invitations",
        headers=auth(administrator_token),
        json={"invitation_delivery": "email"},
    )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "INVITATION_UNAVAILABLE"

    with Session(test_engine) as session:
        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "account_activation",
            )
        ).all()

        assert len(tokens) == 1
        assert tokens[0].token_hash == hash_token(first_token)
        assert tokens[0].revoked_at is None
        assert tokens[0].consumed_at is None


def test_missing_public_url_preserves_existing_token(
    api_client: TestClient,
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    accounts: dict[str, str],
) -> None:
    """Missing public URL must not invalidate an existing invitation."""
    administrator_token = accounts["administrator"]

    user_id, first_token = create_pending_user(
        api_client,
        administrator_token,
    )

    monkeypatch.setattr(app.state.settings, "public_url", None)

    response = api_client.post(
        f"/api/v1/users/{user_id}/invitations",
        headers=auth(administrator_token),
        json={"invitation_delivery": "manual"},
    )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "INVITATION_UNAVAILABLE"

    with Session(test_engine) as session:
        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "account_activation",
            )
        ).all()

        assert len(tokens) == 1
        assert tokens[0].token_hash == hash_token(first_token)
        assert tokens[0].revoked_at is None
        assert tokens[0].consumed_at is None


@pytest.mark.parametrize(
    "invalid_delivery",
    ["unknown", "", "smtp", "automatic", 123],
)
def test_reissue_rejects_invalid_delivery(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
    invalid_delivery: str | int,
) -> None:
    """Unsupported delivery choices must be rejected without token changes."""
    administrator_token = accounts["administrator"]

    user_id, first_token = create_pending_user(
        api_client,
        administrator_token,
    )

    response = api_client.post(
        f"/api/v1/users/{user_id}/invitations",
        headers=auth(administrator_token),
        json={"invitation_delivery": invalid_delivery},
    )

    assert response.status_code == 422

    with Session(test_engine) as session:
        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "account_activation",
            )
        ).all()

        assert len(tokens) == 1
        assert tokens[0].token_hash == hash_token(first_token)
        assert tokens[0].revoked_at is None


@pytest.mark.parametrize(
    "account_changes",
    [
        {"status": "suspended"},
        {"password_reset_required": True},
    ],
)
def test_ineligible_administrator_cannot_reissue_invitation(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
    account_changes: dict[str, str | bool],
) -> None:
    """An ineligible administrator's access token is rejected."""
    administrator_token = accounts["administrator"]

    user_id, first_token = create_pending_user(
        api_client,
        administrator_token,
    )

    profile_response = api_client.get(
        "/api/v1/users/me",
        headers=auth(administrator_token),
    )

    assert profile_response.status_code == 200
    administrator_id = UUID(profile_response.json()["data"]["id"])

    with Session(test_engine) as session:
        with session.begin():
            administrator = session.get(User, administrator_id)
            assert administrator is not None

            for attribute, value in account_changes.items():
                setattr(administrator, attribute, value)

    response = api_client.post(
        f"/api/v1/users/{user_id}/invitations",
        headers=auth(administrator_token),
        json={"invitation_delivery": "manual"},
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"

    with Session(test_engine) as session:
        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "account_activation",
            )
        ).all()

        assert len(tokens) == 1
        assert tokens[0].token_hash == hash_token(first_token)
        assert tokens[0].revoked_at is None
