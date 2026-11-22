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
from restling_server.users.models import (
    AccessToken,
    LoginSession,
    OneTimeToken,
    User,
)
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


def test_administrator_corrects_pending_account_email(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
) -> None:
    """Correcting a pending email replaces its activation invitation."""
    administrator_token = accounts["administrator"]

    user_id, first_token = create_pending_user(
        api_client,
        administrator_token,
    )

    corrected_email = f"corrected-{uuid7().hex}@example.com"

    response = api_client.post(
        f"/api/v1/users/{user_id}/invitations/correct-email",
        headers=auth(administrator_token),
        json={
            "email": corrected_email,
            "invitation_delivery": "manual",
        },
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
        user = session.get(User, user_id)

        assert user is not None
        assert user.email == corrected_email
        assert user.normalized_email == corrected_email
        assert user.status == "pending"
        assert user.password_hash is None

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


def test_regular_user_cannot_correct_pending_account_email(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
) -> None:
    """An ordinary user cannot change a pending account's email."""
    user_id, first_token = create_pending_user(
        api_client,
        accounts["administrator"],
    )

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None

        original_email = user.email
        original_normalized_email = user.normalized_email

    corrected_email = f"corrected-{uuid7().hex}@example.com"

    response = api_client.post(
        f"/api/v1/users/{user_id}/invitations/correct-email",
        headers=auth(accounts["user"]),
        json={
            "email": corrected_email,
            "invitation_delivery": "manual",
        },
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"
    assert response.headers["cache-control"] == "no-store"

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.email == original_email
        assert user.normalized_email == original_normalized_email
        assert user.status == "pending"
        assert user.password_hash is None

        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "account_activation",
            )
        ).all()

        assert len(tokens) == 1

        original_token = tokens[0]

        assert original_token.token_hash == hash_token(first_token)
        assert original_token.revoked_at is None
        assert original_token.consumed_at is None


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer invalid-token"},
    ],
)
def test_pending_email_correction_requires_authentication(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
    headers: dict[str, str],
) -> None:
    """Unauthenticated requests cannot modify pending accounts."""
    user_id, first_token = create_pending_user(
        api_client,
        accounts["administrator"],
    )

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None

        original_email = user.email
        original_normalized_email = user.normalized_email

    corrected_email = f"corrected-{uuid7().hex}@example.com"

    response = api_client.post(
        f"/api/v1/users/{user_id}/invitations/correct-email",
        headers=headers,
        json={
            "email": corrected_email,
            "invitation_delivery": "manual",
        },
    )

    assert response.status_code == 401
    assert response.headers["cache-control"] == "no-store"

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.email == original_email
        assert user.normalized_email == original_normalized_email
        assert user.status == "pending"
        assert user.password_hash is None

        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "account_activation",
            )
        ).all()

        assert len(tokens) == 1

        original_token = tokens[0]

        assert original_token.token_hash == hash_token(first_token)
        assert original_token.revoked_at is None
        assert original_token.consumed_at is None


def test_pending_email_correction_authorization_precedes_configuration(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unauthorized users cannot discover invitation configuration."""
    user_id, first_token = create_pending_user(
        api_client,
        accounts["administrator"],
    )

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None

        original_email = user.email
        original_normalized_email = user.normalized_email

    # Disable the trusted application URL after creating the account.
    monkeypatch.setattr(
        app.state.settings,
        "public_url",
        None,
    )

    corrected_email = f"corrected-{uuid7().hex}@example.com"

    response = api_client.post(
        f"/api/v1/users/{user_id}/invitations/correct-email",
        headers=auth(accounts["user"]),
        json={
            "email": corrected_email,
            "invitation_delivery": "manual",
        },
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"
    assert response.headers["cache-control"] == "no-store"

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.email == original_email
        assert user.normalized_email == original_normalized_email
        assert user.status == "pending"

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
    "account_changes",
    [
        {"status": "suspended"},
        {"password_reset_required": True},
    ],
)
def test_ineligible_administrator_cannot_correct_pending_email(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
    account_changes: dict[str, object],
) -> None:
    """An ineligible administrator cannot correct a pending email."""
    administrator_token = accounts["administrator"]

    user_id, first_token = create_pending_user(
        api_client,
        administrator_token,
    )

    with Session(test_engine) as session:
        with session.begin():
            user = session.get(User, user_id)

            assert user is not None

            original_email = user.email
            original_normalized_email = user.normalized_email

            administrator = session.scalar(
                select(User)
                .join(LoginSession, LoginSession.user_id == User.id)
                .join(
                    AccessToken,
                    AccessToken.session_id == LoginSession.id,
                )
                .where(AccessToken.token_hash == hash_token(administrator_token))
            )

            assert administrator is not None

            for field, value in account_changes.items():
                setattr(administrator, field, value)

    corrected_email = f"corrected-{uuid7().hex}@example.com"

    response = api_client.post(
        f"/api/v1/users/{user_id}/invitations/correct-email",
        headers=auth(administrator_token),
        json={
            "email": corrected_email,
            "invitation_delivery": "manual",
        },
    )

    assert response.status_code == 401
    assert response.headers["cache-control"] == "no-store"

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.email == original_email
        assert user.normalized_email == original_normalized_email
        assert user.status == "pending"
        assert user.password_hash is None

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


def test_pending_email_correction_rejects_unknown_user(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
) -> None:
    """Email correction requires an existing pending account."""
    unknown_user_id = uuid7()
    corrected_email = f"corrected-{uuid7().hex}@example.com"

    response = api_client.post(
        f"/api/v1/users/{unknown_user_id}/invitations/correct-email",
        headers=auth(accounts["administrator"]),
        json={
            "email": corrected_email,
            "invitation_delivery": "manual",
        },
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "USER_NOT_FOUND"
    assert response.headers["cache-control"] == "no-store"

    with Session(test_engine) as session:
        assert session.get(User, unknown_user_id) is None

        user = session.scalar(
            select(User).where(
                User.normalized_email == corrected_email,
            )
        )

        assert user is None

        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == unknown_user_id,
            )
        ).all()

        assert not tokens


@pytest.mark.parametrize("account_status", ["active", "suspended"])
def test_pending_email_correction_rejects_non_pending_accounts(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
    account_status: str,
) -> None:
    """Email correction is restricted to pending accounts."""
    original_email = f"existing-{uuid7().hex}@example.com"
    corrected_email = f"corrected-{uuid7().hex}@example.com"

    with Session(test_engine) as session:
        with session.begin():
            user = User(
                email=original_email,
                normalized_email=original_email,
                display_name="Existing Account",
                status=account_status,
                system_role="user",
                password_hash=hash_password("A secure account test passphrase #8472"),
            )

            session.add(user)
            session.flush()

            user_id = user.id
            original_password_hash = user.password_hash

    response = api_client.post(
        f"/api/v1/users/{user_id}/invitations/correct-email",
        headers=auth(accounts["administrator"]),
        json={
            "email": corrected_email,
            "invitation_delivery": "manual",
        },
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "INVITATION_NOT_ALLOWED"
    assert response.headers["cache-control"] == "no-store"

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.email == original_email
        assert user.normalized_email == original_email
        assert user.status == account_status
        assert user.password_hash == original_password_hash

        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "account_activation",
            )
        ).all()

        assert not tokens


@pytest.mark.parametrize(
    "account_status",
    ["pending", "active", "suspended"],
)
def test_pending_email_correction_rejects_duplicate_email(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
    account_status: str,
) -> None:
    """Email correction cannot claim another account's email."""
    administrator_token = accounts["administrator"]

    user_id, first_token = create_pending_user(
        api_client,
        administrator_token,
    )

    existing_email = f"existing-{uuid7().hex}@example.com"

    with Session(test_engine) as session:
        with session.begin():
            user = session.get(User, user_id)

            assert user is not None

            original_email = user.email
            original_normalized_email = user.normalized_email

            existing_user = User(
                email=existing_email,
                normalized_email=existing_email,
                display_name="Existing Email Owner",
                status=account_status,
                system_role="user",
                password_hash=(
                    None
                    if account_status == "pending"
                    else hash_password("A secure account test passphrase #8472")
                ),
            )

            session.add(existing_user)
            session.flush()

            existing_user_id = existing_user.id

    response = api_client.post(
        f"/api/v1/users/{user_id}/invitations/correct-email",
        headers=auth(administrator_token),
        json={
            "email": existing_email,
            "invitation_delivery": "manual",
        },
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "EMAIL_ALREADY_EXISTS"
    assert response.headers["cache-control"] == "no-store"

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.email == original_email
        assert user.normalized_email == original_normalized_email
        assert user.status == "pending"
        assert user.password_hash is None

        existing_user = session.get(User, existing_user_id)

        assert existing_user is not None
        assert existing_user.email == existing_email
        assert existing_user.normalized_email == existing_email
        assert existing_user.status == account_status

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
    "invalid_email",
    [
        "not-an-email",
        "user@",
        "@example.com",
        "   ",
    ],
)
def test_pending_email_correction_rejects_invalid_email(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
    invalid_email: str,
) -> None:
    """Invalid email corrections preserve the account and invitation."""
    administrator_token = accounts["administrator"]

    user_id, first_token = create_pending_user(
        api_client,
        administrator_token,
    )

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None

        original_email = user.email
        original_normalized_email = user.normalized_email

    response = api_client.post(
        f"/api/v1/users/{user_id}/invitations/correct-email",
        headers=auth(administrator_token),
        json={
            "email": invalid_email,
            "invitation_delivery": "manual",
        },
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_EMAIL"
    assert response.headers["cache-control"] == "no-store"

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.email == original_email
        assert user.normalized_email == original_normalized_email
        assert user.status == "pending"
        assert user.password_hash is None

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
    "email_format",
    [
        "{local}@EXAMPLE.COM",
        "{upper_local}@example.com",
        "  {local}@example.com  ",
    ],
)
def test_pending_email_correction_enforces_normalized_uniqueness(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
    email_format: str,
) -> None:
    """Email formatting cannot bypass account uniqueness."""
    administrator_token = accounts["administrator"]

    user_id, first_token = create_pending_user(
        api_client,
        administrator_token,
    )

    existing_user_id, existing_token = create_pending_user(
        api_client,
        administrator_token,
    )

    with Session(test_engine) as session:
        user = session.get(User, user_id)
        existing_user = session.get(User, existing_user_id)

        assert user is not None
        assert existing_user is not None

        original_email = user.email
        original_normalized_email = user.normalized_email
        existing_email = existing_user.email

    local = existing_email.split("@", 1)[0]

    corrected_email = email_format.format(
        local=local,
        upper_local=local.upper(),
    )

    response = api_client.post(
        f"/api/v1/users/{user_id}/invitations/correct-email",
        headers=auth(administrator_token),
        json={
            "email": corrected_email,
            "invitation_delivery": "manual",
        },
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "EMAIL_ALREADY_EXISTS"
    assert response.headers["cache-control"] == "no-store"

    with Session(test_engine) as session:
        user = session.get(User, user_id)
        existing_user = session.get(User, existing_user_id)

        assert user is not None
        assert existing_user is not None

        assert user.email == original_email
        assert user.normalized_email == original_normalized_email
        assert user.status == "pending"

        assert existing_user.email == existing_email
        assert existing_user.status == "pending"

        for account_id, raw_token in (
            (user_id, first_token),
            (existing_user_id, existing_token),
        ):
            tokens = session.scalars(
                select(OneTimeToken).where(
                    OneTimeToken.user_id == account_id,
                    OneTimeToken.purpose == "account_activation",
                )
            ).all()

            assert len(tokens) == 1
            assert tokens[0].token_hash == hash_token(raw_token)
            assert tokens[0].revoked_at is None
            assert tokens[0].consumed_at is None


@pytest.mark.parametrize(
    "email_format",
    [
        "{local}@example.com",
        "{upper_local}@example.com",
        "{local}@EXAMPLE.COM",
        "  {local}@example.com  ",
    ],
)
def test_pending_email_correction_rejects_unchanged_email(
    api_client: TestClient,
    test_engine: Engine,
    accounts: dict[str, str],
    email_format: str,
) -> None:
    """An unchanged email must not replace the existing invitation."""
    administrator_token = accounts["administrator"]

    user_id, first_token = create_pending_user(
        api_client,
        administrator_token,
    )

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None

        original_email = user.email
        original_normalized_email = user.normalized_email

    local = original_email.split("@", 1)[0]

    corrected_email = email_format.format(
        local=local,
        upper_local=local.upper(),
    )

    response = api_client.post(
        f"/api/v1/users/{user_id}/invitations/correct-email",
        headers=auth(administrator_token),
        json={
            "email": corrected_email,
            "invitation_delivery": "manual",
        },
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "EMAIL_UNCHANGED"
    assert response.headers["cache-control"] == "no-store"

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.email == original_email
        assert user.normalized_email == original_normalized_email
        assert user.status == "pending"
        assert user.password_hash is None

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


def test_administrator_corrects_pending_email_through_smtp(
    api_client: TestClient,
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    accounts: dict[str, str],
) -> None:
    """SMTP correction delivers a replacement invitation to the new email."""
    administrator_token = accounts["administrator"]

    user_id, first_token = create_pending_user(
        api_client,
        administrator_token,
    )

    corrected_email = f"corrected-{uuid7().hex}@example.com"

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

    response = api_client.post(
        f"/api/v1/users/{user_id}/invitations/correct-email",
        headers=auth(administrator_token),
        json={
            "email": corrected_email,
            "invitation_delivery": "email",
        },
    )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"

    invitation = response.json()["invitation"]

    assert invitation["delivery"] == "email"
    assert invitation["activation_url"] is None
    assert invitation["expires_at"]

    assert len(sent_messages) == 1

    recipient, activation_url = sent_messages[0]

    assert recipient == corrected_email

    second_token = parse_qs(urlsplit(activation_url).query)["token"][0]

    assert second_token != first_token
    assert second_token not in response.text
    assert activation_url not in response.text

    with Session(test_engine) as session:
        target = session.get(User, user_id)

        assert target is not None
        assert target.email == corrected_email
        assert target.normalized_email == corrected_email
        assert target.status == "pending"
        assert target.password_hash is None
        assert target.activated_at is None

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


def test_pending_email_correction_smtp_failure_preserves_state(
    api_client: TestClient,
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    accounts: dict[str, str],
) -> None:
    """Failed SMTP correction preserves the original email and invitation."""
    administrator_token = accounts["administrator"]

    user_id, first_token = create_pending_user(
        api_client,
        administrator_token,
    )

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None

        original_email = user.email
        original_normalized_email = user.normalized_email

    corrected_email = f"corrected-{uuid7().hex}@example.com"

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

    attempted_deliveries: list[tuple[str, str]] = []

    def fail_email_delivery(
        settings: object,
        *,
        recipient: str,
        activation_url: str,
    ) -> None:
        attempted_deliveries.append((recipient, activation_url))

        raise InvitationDeliveryError("Simulated SMTP failure.")

    monkeypatch.setattr(
        invitations,
        "send_invitation_email",
        fail_email_delivery,
    )

    response = api_client.post(
        f"/api/v1/users/{user_id}/invitations/correct-email",
        headers=auth(administrator_token),
        json={
            "email": corrected_email,
            "invitation_delivery": "email",
        },
    )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == ("INVITATION_DELIVERY_FAILED")
    assert response.headers["cache-control"] == "no-store"

    assert len(attempted_deliveries) == 1

    recipient, activation_url = attempted_deliveries[0]

    assert recipient == corrected_email

    replacement_token = parse_qs(urlsplit(activation_url).query)["token"][0]

    assert replacement_token != first_token
    assert replacement_token not in response.text
    assert activation_url not in response.text

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.email == original_email
        assert user.normalized_email == original_normalized_email
        assert user.status == "pending"
        assert user.password_hash is None
        assert user.activated_at is None

        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "account_activation",
            )
        ).all()

        assert len(tokens) == 1

        original_token = tokens[0]

        assert original_token.token_hash == hash_token(first_token)
        assert original_token.revoked_at is None
        assert original_token.consumed_at is None

        replacement = session.scalar(
            select(OneTimeToken).where(
                OneTimeToken.token_hash == hash_token(replacement_token)
            )
        )

        assert replacement is None


def test_pending_email_correction_rejects_concurrent_reissue(
    api_client: TestClient,
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    accounts: dict[str, str],
) -> None:
    """SMTP correction must not overwrite a concurrent invitation reissue."""
    administrator_token = accounts["administrator"]

    user_id, first_token = create_pending_user(
        api_client,
        administrator_token,
    )

    with Session(test_engine) as session:
        user = session.get(User, user_id)
        assert user is not None
        original_email = user.email

    corrected_email = f"corrected-{uuid7().hex}@example.com"

    monkeypatch.setattr(app.state.settings, "smtp_host", "localhost")
    monkeypatch.setattr(
        app.state.settings,
        "smtp_from_email",
        "restling@example.com",
    )

    reissued_tokens: list[str] = []
    delivered_tokens: list[str] = []

    def capture_email_delivery(
        settings: object,
        *,
        recipient: str,
        activation_url: str,
    ) -> None:
        assert recipient == corrected_email

        delivered_token = parse_qs(urlsplit(activation_url).query)["token"][0]
        delivered_tokens.append(delivered_token)

        # Simulate another administrator reissuing the invitation
        # while the original SMTP operation is in progress.
        reissue_response = api_client.post(
            f"/api/v1/users/{user_id}/invitations",
            headers=auth(administrator_token),
            json={"invitation_delivery": "manual"},
        )

        assert reissue_response.status_code == 200

        reissued_url = reissue_response.json()["invitation"]["activation_url"]
        assert isinstance(reissued_url, str)

        reissued_token = parse_qs(urlsplit(reissued_url).query)["token"][0]

        reissued_tokens.append(reissued_token)

    monkeypatch.setattr(
        invitations,
        "send_invitation_email",
        capture_email_delivery,
    )

    response = api_client.post(
        f"/api/v1/users/{user_id}/invitations/correct-email",
        headers=auth(administrator_token),
        json={
            "email": corrected_email,
            "invitation_delivery": "email",
        },
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == ("INVITATION_NOT_ALLOWED")
    assert response.headers["cache-control"] == "no-store"

    assert len(reissued_tokens) == 1
    assert len(delivered_tokens) == 1

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.email == original_email
        assert user.normalized_email == original_email
        assert user.status == "pending"

        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "account_activation",
            )
        ).all()

        assert len(tokens) == 2

        original = next(
            token for token in tokens if token.token_hash == hash_token(first_token)
        )

        reissued = next(
            token
            for token in tokens
            if token.token_hash == hash_token(reissued_tokens[0])
        )

        assert original.revoked_at is not None
        assert reissued.revoked_at is None
        assert reissued.consumed_at is None

        assert all(
            token.token_hash != hash_token(delivered_tokens[0]) for token in tokens
        )


def test_pending_email_correction_rejects_concurrent_activation(
    api_client: TestClient,
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    accounts: dict[str, str],
) -> None:
    """SMTP correction must not overwrite an activated account."""
    administrator_token = accounts["administrator"]

    user_id, first_token = create_pending_user(
        api_client,
        administrator_token,
    )

    with Session(test_engine) as session:
        user = session.get(User, user_id)
        assert user is not None
        original_email = user.email

    corrected_email = f"corrected-{uuid7().hex}@example.com"
    activation_password = "A secure activation test passphrase #8472"

    monkeypatch.setattr(app.state.settings, "smtp_host", "localhost")
    monkeypatch.setattr(
        app.state.settings,
        "smtp_from_email",
        "restling@example.com",
    )

    delivered_tokens: list[str] = []
    activation_responses: list[int] = []

    def capture_email_delivery(
        settings: object,
        *,
        recipient: str,
        activation_url: str,
    ) -> None:
        assert recipient == corrected_email

        delivered_token = parse_qs(urlsplit(activation_url).query)["token"][0]

        delivered_tokens.append(delivered_token)

        # The user activates their account while the corrected
        # invitation is being delivered.
        activation_response = api_client.post(
            "/api/v1/auth/activate",
            json={
                "token": first_token,
                "password": activation_password,
            },
        )

        activation_responses.append(activation_response.status_code)

        assert activation_response.status_code == 200

    monkeypatch.setattr(
        invitations,
        "send_invitation_email",
        capture_email_delivery,
    )

    response = api_client.post(
        f"/api/v1/users/{user_id}/invitations/correct-email",
        headers=auth(administrator_token),
        json={
            "email": corrected_email,
            "invitation_delivery": "email",
        },
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == ("INVITATION_NOT_ALLOWED")
    assert response.headers["cache-control"] == "no-store"

    assert activation_responses == [200]
    assert len(delivered_tokens) == 1

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.email == original_email
        assert user.normalized_email == original_email
        assert user.status == "active"
        assert user.password_hash is not None
        assert user.activated_at is not None

        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "account_activation",
            )
        ).all()

        assert len(tokens) == 1

        original_token = tokens[0]

        assert original_token.token_hash == hash_token(first_token)
        assert original_token.consumed_at is not None

        # The correction's replacement credential was delivered,
        # but must never become valid after account activation.
        assert all(
            token.token_hash != hash_token(delivered_tokens[0]) for token in tokens
        )


def test_pending_email_correction_rejects_concurrent_correction(
    api_client: TestClient,
    test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    accounts: dict[str, str],
) -> None:
    """An in-flight SMTP correction must not overwrite a newer correction."""
    administrator_token = accounts["administrator"]

    user_id, first_token = create_pending_user(
        api_client,
        administrator_token,
    )

    first_email = f"first-{uuid7().hex}@example.com"
    second_email = f"second-{uuid7().hex}@example.com"

    monkeypatch.setattr(app.state.settings, "smtp_host", "localhost")
    monkeypatch.setattr(
        app.state.settings,
        "smtp_from_email",
        "restling@example.com",
    )

    delivered_tokens: list[str] = []
    second_tokens: list[str] = []

    def capture_email_delivery(
        settings: object,
        *,
        recipient: str,
        activation_url: str,
    ) -> None:
        assert recipient == first_email

        delivered_tokens.append(parse_qs(urlsplit(activation_url).query)["token"][0])

        # A second correction commits while the first SMTP
        # delivery is underway.
        second_response = api_client.post(
            f"/api/v1/users/{user_id}/invitations/correct-email",
            headers=auth(administrator_token),
            json={
                "email": second_email,
                "invitation_delivery": "manual",
            },
        )

        assert second_response.status_code == 200

        second_url = second_response.json()["invitation"]["activation_url"]
        assert isinstance(second_url, str)

        second_tokens.append(parse_qs(urlsplit(second_url).query)["token"][0])

    monkeypatch.setattr(
        invitations,
        "send_invitation_email",
        capture_email_delivery,
    )

    response = api_client.post(
        f"/api/v1/users/{user_id}/invitations/correct-email",
        headers=auth(administrator_token),
        json={
            "email": first_email,
            "invitation_delivery": "email",
        },
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "INVITATION_NOT_ALLOWED"
    assert response.headers["cache-control"] == "no-store"

    assert len(delivered_tokens) == 1
    assert len(second_tokens) == 1

    with Session(test_engine) as session:
        user = session.get(User, user_id)

        assert user is not None
        assert user.email == second_email
        assert user.normalized_email == second_email
        assert user.status == "pending"
        assert user.password_hash is None

        tokens = session.scalars(
            select(OneTimeToken).where(
                OneTimeToken.user_id == user_id,
                OneTimeToken.purpose == "account_activation",
            )
        ).all()

        assert len(tokens) == 2

        original = next(
            token for token in tokens if token.token_hash == hash_token(first_token)
        )

        replacement = next(
            token
            for token in tokens
            if token.token_hash == hash_token(second_tokens[0])
        )

        assert original.revoked_at is not None
        assert replacement.revoked_at is None
        assert replacement.consumed_at is None

        assert all(
            token.token_hash != hash_token(delivered_tokens[0]) for token in tokens
        )

