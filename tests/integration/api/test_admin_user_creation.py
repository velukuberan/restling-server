"""HTTP integration tests for administrator account creation."""

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
    """Create authenticated administrator and ordinary user accounts."""
    key = uuid7().hex
    password = "A secure creation test passphrase #8472"

    admin_email = f"create-admin-{key}@example.com"
    user_email = f"create-user-{key}@example.com"

    with Session(test_engine) as session:
        session.add_all(
            [
                User(
                    email=admin_email,
                    normalized_email=admin_email,
                    display_name="Creation Administrator",
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

    # Use manual invitation delivery without contacting SMTP.
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
    """Build an access-token authorization header."""
    return {"Authorization": f"Bearer {token}"}


def payload() -> dict[str, str]:
    """Generate a unique user-creation request."""
    return {
        "email": f"new-{uuid7().hex}@example.com",
        "display_name": "New Backend Engineer",
        "job_title": "Backend Engineer",
    }


def test_administrator_creates_pending_user(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
) -> None:
    """Creation persists a pending account and hashed activation token."""
    request_data = payload()

    response = api_client.post(
        "/api/v1/users",
        headers=auth(accounts["administrator"]),
        json=request_data,
    )

    assert response.status_code == 201
    assert response.headers["cache-control"] == "no-store"

    result = response.json()
    user = result["data"]
    invitation = result["invitation"]

    assert user["email"] == request_data["email"]
    assert user["display_name"] == request_data["display_name"]
    assert user["job_title"] == request_data["job_title"]
    assert user["status"] == "pending"
    assert user["system_role"] == "user"
    assert user["activated_at"] is None
    assert user["password_reset_required"] is False

    assert invitation["delivery"] == "manual"
    assert invitation["expires_at"]

    activation_url = invitation["activation_url"]

    assert isinstance(activation_url, str)

    parsed_url = urlsplit(activation_url)

    assert parsed_url.path == "/activate"
    raw_token = parse_qs(parsed_url.query)["token"][0]

    for secret in ("password_hash", "normalized_email", "access_token"):
        assert secret not in user

    with Session(test_engine) as session:
        stored_user = session.get(User, UUID(user["id"]))

        assert stored_user is not None
        assert stored_user.status == "pending"
        assert stored_user.password_hash is None

        stored_token = session.scalar(
            select(OneTimeToken).where(
                OneTimeToken.user_id == stored_user.id,
            )
        )

        assert stored_token is not None
        assert stored_token.purpose == "account_activation"
        assert stored_token.token_hash == hash_token(raw_token)
        assert stored_token.token_hash != raw_token


def test_duplicate_email_returns_conflict(
    api_client: TestClient,
    accounts: dict[str, str],
) -> None:
    """Duplicate creation is rejected by the service/database."""
    request_data = payload()
    headers = auth(accounts["administrator"])

    first = api_client.post(
        "/api/v1/users",
        headers=headers,
        json=request_data,
    )
    assert first.status_code == 201

    second = api_client.post(
        "/api/v1/users",
        headers=headers,
        json=request_data,
    )

    assert second.status_code == 409
    assert second.json()["error"]["code"] == "EMAIL_ALREADY_EXISTS"


def test_regular_user_cannot_create_accounts(
    api_client: TestClient,
    accounts: dict[str, str],
) -> None:
    """An ordinary account cannot use the administrator endpoint."""
    response = api_client.post(
        "/api/v1/users",
        headers=auth(accounts["user"]),
        json=payload(),
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


def test_creation_requires_authentication(
    api_client: TestClient,
) -> None:
    """Missing or invalid access tokens receive 401."""
    for headers in ({}, auth("invalid-token")):
        response = api_client.post(
            "/api/v1/users",
            headers=headers,
            json=payload(),
        )

        assert response.status_code == 401
        assert response.json()["error"]["code"] == "UNAUTHORIZED"


@pytest.mark.parametrize(
    "changes",
    [
        {"email": "invalid-email"},
        {"display_name": "   "},
        {"display_name": "A" * 151},
        {"job_title": "A" * 101},
        {"status": "active"},
        {"system_role": "administrator"},
        {"password": "some-password"},
        {"invitation_delivery": "unknown"},
        {"invitation_delivery": ""},
    ],
)
def test_creation_rejects_invalid_or_forbidden_fields(
    api_client: TestClient,
    accounts: dict[str, str],
    changes: dict[str, str],
) -> None:
    """Invalid data and unauthorized account fields are rejected."""
    request_data = payload()
    request_data.update(changes)

    response = api_client.post(
        "/api/v1/users",
        headers=auth(accounts["administrator"]),
        json=request_data,
    )

    assert response.status_code == 422


def test_missing_public_url_does_not_create_user(
    api_client: TestClient,
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    accounts: dict[str, str],
) -> None:
    """Missing invitation configuration blocks account creation."""
    monkeypatch.setattr(app.state.settings, "public_url", None)

    request_data = payload()

    response = api_client.post(
        "/api/v1/users",
        headers=auth(accounts["administrator"]),
        json=request_data,
    )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "INVITATION_UNAVAILABLE"

    with Session(test_engine) as session:
        stored_user = session.scalar(
            select(User).where(
                User.normalized_email == request_data["email"],
            )
        )

        assert stored_user is None


def test_authorization_precedes_invitation_configuration(
    api_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    accounts: dict[str, str],
) -> None:
    """Ordinary users receive 403 even when invitations are unavailable."""
    monkeypatch.setattr(app.state.settings, "public_url", None)

    response = api_client.post(
        "/api/v1/users",
        headers=auth(accounts["user"]),
        json=payload(),
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


def test_smtp_failure_preserves_pending_user(
    api_client: TestClient,
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    accounts: dict[str, str],
) -> None:
    """Failed SMTP delivery leaves a pending account for re-invitation."""
    monkeypatch.setattr(
        app.state.settings,
        "smtp_host",
        "localhost",
    )
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

    request_data = payload()

    response = api_client.post(
        "/api/v1/users",
        headers=auth(accounts["administrator"]),
        json=request_data,
    )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "INVITATION_DELIVERY_FAILED"
    assert response.headers["cache-control"] == "no-store"

    with Session(test_engine) as session:
        user = session.scalar(
            select(User).where(
                User.normalized_email == request_data["email"],
            )
        )

        assert user is not None
        assert user.status == "pending"
        assert user.password_hash is None
        assert user.activated_at is None

        activation_tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user.id,
                OneTimeToken.purpose == "account_activation",
            )
        ).all()

        assert len(activation_tokens) == 1
        assert activation_tokens[0].consumed_at is None


def test_smtp_success_creates_pending_user(
    api_client: TestClient,
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    accounts: dict[str, str],
) -> None:
    """Successful SMTP submission never exposes activation credentials."""
    monkeypatch.setattr(
        app.state.settings,
        "smtp_host",
        "localhost",
    )
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

    request_data = payload()

    response = api_client.post(
        "/api/v1/users",
        headers=auth(accounts["administrator"]),
        json=request_data,
    )

    assert response.status_code == 201
    assert response.headers["cache-control"] == "no-store"

    result = response.json()

    assert result["data"]["email"] == request_data["email"]
    assert result["data"]["status"] == "pending"
    assert result["data"]["system_role"] == "user"

    assert result["invitation"]["delivery"] == "email"
    assert result["invitation"]["activation_url"] is None
    assert result["invitation"]["expires_at"]

    assert len(sent_messages) == 1

    recipient, activation_url = sent_messages[0]

    assert recipient == request_data["email"]

    parsed_url = urlsplit(activation_url)
    assert parsed_url.path == "/activate"

    raw_token = parse_qs(parsed_url.query)["token"][0]

    # The activation credential must not appear in the API response.
    assert raw_token not in response.text
    assert activation_url not in response.text

    with Session(test_engine) as session:
        user = session.get(
            User,
            UUID(result["data"]["id"]),
        )

        assert user is not None
        assert user.status == "pending"
        assert user.password_hash is None

        stored_token = session.scalar(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user.id,
                OneTimeToken.purpose == "account_activation",
            )
        )

        assert stored_token is not None
        assert stored_token.token_hash == hash_token(raw_token)
        assert stored_token.token_hash != raw_token
        assert stored_token.consumed_at is None


def test_explicit_manual_delivery_with_smtp_enabled(
    api_client: TestClient,
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    accounts: dict[str, str],
) -> None:
    """Manual delivery works even when SMTP is configured."""
    monkeypatch.setattr(app.state.settings, "smtp_host", "localhost")
    monkeypatch.setattr(
        app.state.settings,
        "smtp_from_email",
        "restling@example.com",
    )

    def reject_smtp_call(
        settings: object,
        *,
        recipient: str,
        activation_url: str,
    ) -> None:
        pytest.fail("SMTP must not be used for manual invitations.")

    monkeypatch.setattr(
        invitations,
        "send_invitation_email",
        reject_smtp_call,
    )

    request_data = payload()
    request_data["invitation_delivery"] = "manual"

    response = api_client.post(
        "/api/v1/users",
        headers=auth(accounts["administrator"]),
        json=request_data,
    )

    assert response.status_code == 201
    assert response.headers["cache-control"] == "no-store"

    result = response.json()

    assert result["data"]["status"] == "pending"
    assert result["invitation"]["delivery"] == "manual"

    activation_url = result["invitation"]["activation_url"]
    assert isinstance(activation_url, str)

    raw_token = parse_qs(urlsplit(activation_url).query)["token"][0]

    with Session(test_engine) as session:
        stored_token = session.scalar(
            select(OneTimeToken).where(
                OneTimeToken.user_id == UUID(result["data"]["id"]),
                OneTimeToken.purpose == "account_activation",
            )
        )

        assert stored_token is not None
        assert stored_token.token_hash == hash_token(raw_token)


def test_explicit_email_delivery_without_smtp(
    api_client: TestClient,
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    accounts: dict[str, str],
) -> None:
    """Explicit SMTP selection fails before creating an account."""
    monkeypatch.setattr(app.state.settings, "smtp_host", None)
    monkeypatch.setattr(app.state.settings, "smtp_from_email", None)

    request_data = payload()
    request_data["invitation_delivery"] = "email"

    response = api_client.post(
        "/api/v1/users",
        headers=auth(accounts["administrator"]),
        json=request_data,
    )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "INVITATION_UNAVAILABLE"

    with Session(test_engine) as session:
        user = session.scalar(
            select(User).where(
                User.normalized_email == request_data["email"],
            )
        )

        assert user is None
